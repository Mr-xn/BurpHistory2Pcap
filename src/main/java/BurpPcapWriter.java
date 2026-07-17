import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 纯 Java 实现的 PCAP 写出器。
 *
 * 原实现依赖 pcap4j + JNA (调用系统 libpcap)。但 Burp 2026.6 自带 JNA 7.0.2
 * 并在扩展类加载器可见范围之外先加载了 jnidispatch 原生库；本扩展自带 JNA
 * 期望的 native 版本为 6.1.6，两者在同一 JVM 进程内无法共存，导出时抛
 * java.lang.Error: incompatible JNA native library。
 *
 * 本类只用到 pcap4j 的 openDead + dumpOpen + dump 三个能力，PCAP 文件格式
 * (RFC 区段 + per-packet record) 以及 Ethernet/IPv4/IPv6/TCP 报文头构造完全
 * 可以纯 Java 完成，从而彻底摆脱 pcap4j/JNA/libpcap 依赖。
 */
public class BurpPcapWriter implements AutoCloseable {

    private static final int MSS = 65495;
    private static final byte[] CLIENT_MAC_ADDRESS = mac("00:62:75:72:70:31");
    private static final byte[] SERVER_MAC_ADDRESS = mac("00:62:75:72:70:32");
    private static final String CLIENT_IP4_ADDRESS = "127.0.0.1";
    private static final String SERVER_IP4_ADDRESS = "127.0.0.2";
    private static final String CLIENT_IP6_ADDRESS = "::1";
    private static final String UNKNOWN_IP4_ADDRESS = "192.0.2.123";
    private static final java.util.concurrent.ThreadLocalRandom random = java.util.concurrent.ThreadLocalRandom.current();

    // libpcap DataLinkType.EN10MB = 1 (Ethernet)
    private static final int DLT_EN10MB = 1;
    // PCAP magic + version 2.4 + snaplen 65535 + linktype EN10MB
    private static final int SNAPLEN = 65535;

    private final DataOutputStream out;
    private final boolean forcePort80;
    private final boolean useRealIPs;
    private final AtomicInteger pktCounter;
    private int totalPackets;

    public BurpPcapWriter(String filename, boolean usePort80, boolean useRealIPs) throws IOException {
        this.out = new DataOutputStream(new FileOutputStream(filename));
        writeGlobalHeader();
        this.forcePort80 = usePort80;
        this.useRealIPs = useRealIPs;
        this.pktCounter = new AtomicInteger(0);
        this.totalPackets = 0;
    }

    /**
     * 返回本次 writer 实例已写入的累计数据包数量 (跨所有 entry)。
     */
    public int totalPacketsWritten() {
        return totalPackets;
    }

    public void writeEntries(List<HttpRequestResponse> entries) throws Exception {
        for (int entryIdx = 0; entryIdx < entries.size(); entryIdx++) {
            HttpRequestResponse entry = entries.get(entryIdx);
            pktCounter.set(0);

            // Get entry data
            BurpEntryData entryData = determineEntryData(entryIdx, entry);
            Endpoint client = entryData.client();
            Endpoint server = entryData.server();
            Instant ts = entryData.ts();

            // TCP handshake
            writeHandshake(client, server, ts);

            // HTTP Request
            byte[] httpRequest = entry.request().toByteArray().getBytes();
            int clientSeq = writePacketsChunked(client, server, httpRequest, client.isn() + 1, server.isn() + 1, ts);

            // HTTP response
            byte[] httpResponse = (entry.response() != null) ? entry.response().toByteArray().getBytes() : null;
            int serverSeq = writePacketsChunked(server, client, httpResponse, server.isn() + 1, clientSeq, ts);

            // TCP teardown
            writeTeardown(client, server, serverSeq, clientSeq, ts);
        }
    }

    private int writePacketsChunked(Endpoint src, Endpoint dst, byte[] data, int srcSeq, int dstSeq, Instant ts) throws Exception {
        if (data != null && data.length > 0) {
            int offset = 0;
            // Source sends chunked data
            while (offset < data.length) {
                int len = Math.min(MSS, data.length - offset);
                byte[] payload = Arrays.copyOfRange(data, offset, offset + len);
                write(packet(TcpFlag.PSH_ACK, src, dst, srcSeq, dstSeq, payload), ts);
                srcSeq += len;
                offset += len;
            }
            // Destination acknowledges all received data
            write(packet(TcpFlag.ACK, dst, src, dstSeq, srcSeq, null), ts);
        }
        return srcSeq;
    }

    private void writeHandshake(Endpoint client, Endpoint server, Instant ts) throws Exception {
        write(packet(TcpFlag.SYN, client, server, client.isn(), 0, null), ts);
        write(packet(TcpFlag.SYN_ACK, server, client, server.isn(), client.isn() + 1, null), ts);
        write(packet(TcpFlag.ACK, client, server, client.isn() + 1, server.isn() + 1, null), ts);
    }

    private void writeTeardown(Endpoint client, Endpoint server, int serverSeq, int clientSeq, Instant ts) throws Exception {
        write(packet(TcpFlag.FIN_ACK, server, client, serverSeq, clientSeq, null), ts);
        write(packet(TcpFlag.FIN_ACK, client, server, clientSeq, serverSeq, null), ts);
        write(packet(TcpFlag.ACK, server, client, serverSeq + 1, clientSeq + 1, null), ts);
    }

    private void write(byte[] packetBytes, Instant ts) throws IOException {
        long epochMicros = ts.plusMillis(pktCounter.getAndIncrement()).toEpochMilli() * 1000L;
        int capturedLen = packetBytes.length;
        // per-packet record header: ts_sec, ts_usec, incl_len, orig_len
        out.writeInt((int) (epochMicros / 1_000_000L));
        out.writeInt((int) (epochMicros % 1_000_000L));
        out.writeInt(capturedLen);
        out.writeInt(capturedLen);
        out.write(packetBytes);
        totalPackets++;
    }

    private byte[] packet(TcpFlag flag, Endpoint src, Endpoint dst, int seq, int ack, byte[] payload) throws UnknownHostException {
        InetAddress srcAddress = src.inetSocketAddress().getAddress();
        InetAddress dstAddress = dst.inetSocketAddress().getAddress();

        byte[] tcp = buildTcp(flag, srcAddress, dstAddress,
                src.inetSocketAddress().getPort(), dst.inetSocketAddress().getPort(),
                seq, ack, payload);

        if (srcAddress instanceof Inet6Address && dstAddress instanceof Inet6Address) {
            byte[] ipv6 = buildIpv6((Inet6Address) srcAddress, (Inet6Address) dstAddress, tcp);
            return buildEthernet(src.macAddress(), dst.macAddress(), (short) 0x86DD, ipv6);
        } else {
            Inet4Address src4 = toInet4(srcAddress);
            Inet4Address dst4 = toInet4(dstAddress);
            byte[] ipv4 = buildIpv4(src4, dst4, tcp);
            return buildEthernet(src.macAddress(), dst.macAddress(), (short) 0x0800, ipv4);
        }
    }

    private Inet4Address toInet4(InetAddress address) {
        if (address instanceof Inet4Address) {
            return (Inet4Address) address;
        }
        try {
            return (Inet4Address) InetAddress.getByName(UNKNOWN_IP4_ADDRESS);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] buildTcp(TcpFlag flag, InetAddress src, InetAddress dst, int srcPort, int dstPort,
                            int seq, int ack, byte[] payload) {
        int payloadLen = payload == null ? 0 : payload.length;
        boolean syn = flag == TcpFlag.SYN || flag == TcpFlag.SYN_ACK;
        boolean ackFlag = flag != TcpFlag.SYN;
        boolean psh = flag == TcpFlag.PSH_ACK;
        boolean fin = flag == TcpFlag.FIN_ACK || flag == TcpFlag.FIN;

        // TCP options: 仅 SYN / SYN_ACK 携带 MSS 选项 (kind=2, length=4, value=MSS)
        byte[] options = syn ? new byte[] {
                0x02, 0x04, (byte) ((MSS >> 8) & 0xFF), (byte) (MSS & 0xFF)
        } : new byte[0];

        int dataOffset = (20 + options.length) / 4; // header length in 32-bit words
        ByteBuffer buf = ByteBuffer.allocate(20 + options.length + payloadLen);
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putInt(seq);
        buf.putInt(ack);
        // data offset (4 bits) + reserved (3 bits) + NS (1 bit) | flags (8 bits)
        buf.put((byte) (dataOffset << 4));
        int flags = 0;
        if (fin) flags |= 0x01;
        if (syn) flags |= 0x02;
        if (psh) flags |= 0x08;
        if (ackFlag) flags |= 0x10;
        buf.put((byte) flags);
        buf.putShort((short) 65535); // window
        buf.putShort((short) 0);     // checksum placeholder
        buf.putShort((short) 0);     // urgent pointer
        if (options.length > 0) buf.put(options);
        if (payloadLen > 0) buf.put(payload);

        byte[] segment = buf.array();
        // TCP checksum over pseudo header + segment
        int checksum = tcpChecksum(src, dst, segment);
        segment[16] = (byte) ((checksum >> 8) & 0xFF);
        segment[17] = (byte) (checksum & 0xFF);
        return segment;
    }

    private int tcpChecksum(InetAddress src, InetAddress dst, byte[] segment) {
        long sum = 0;
        byte[] srcBytes = src.getAddress();
        byte[] dstBytes = dst.getAddress();
        // pseudo header
        sum += word(srcBytes, 0);
        sum += word(srcBytes, 2);
        sum += word(dstBytes, 0);
        sum += word(dstBytes, 2);
        sum += 6; // protocol TCP
        sum += segment.length;
        // segment
        int i = 0;
        while (i + 1 < segment.length) {
            sum += word(segment, i);
            i += 2;
        }
        if (i < segment.length) {
            sum += ((segment[i] & 0xFF) << 8);
        }
        return (int) ~fold(sum);
    }

    private byte[] buildIpv4(Inet4Address src, Inet4Address dst, byte[] payload) {
        int totalLen = 20 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen);
        buf.put((byte) 0x45);              // version 4 + IHL 5
        buf.put((byte) 0x00);              // TOS / DSCP
        buf.putShort((short) totalLen);    // total length
        buf.putShort((short) 0x0000);      // identification
        buf.putShort((short) 0x4000);      // flags (DF) + fragment offset
        buf.put((byte) 64);                // TTL
        buf.put((byte) 6);                 // protocol TCP
        buf.putShort((short) 0);           // header checksum placeholder
        buf.put(src.getAddress());
        buf.put(dst.getAddress());
        buf.put(payload);                  // TCP segment

        byte[] packet = buf.array();
        int checksum = headerChecksum(packet, 0, 20);
        packet[10] = (byte) ((checksum >> 8) & 0xFF);
        packet[11] = (byte) (checksum & 0xFF);
        return packet;
    }

    private byte[] buildIpv6(Inet6Address src, Inet6Address dst, byte[] payload) {
        int payloadLen = payload.length;
        ByteBuffer buf = ByteBuffer.allocate(40 + payloadLen);
        buf.put((byte) 0x60);              // version 6
        buf.put((byte) 0x00);              // traffic class high
        buf.put((byte) 0x00);              // traffic class low + flow label
        buf.put((byte) 0x00);              // flow label
        buf.putShort((short) payloadLen);  // payload length
        buf.put((byte) 6);                 // next header TCP
        buf.put((byte) 64);                // hop limit
        buf.put(src.getAddress());
        buf.put(dst.getAddress());
        buf.put(payload);
        return buf.array();
    }

    private byte[] buildEthernet(byte[] srcMac, byte[] dstMac, short etherType, byte[] payload) {
        ByteBuffer buf = ByteBuffer.allocate(14 + payload.length);
        buf.put(dstMac);
        buf.put(srcMac);
        buf.putShort(etherType);
        buf.put(payload);
        return buf.array();
    }

    private void writeGlobalHeader() throws IOException {
        out.writeInt(0xa1b2c3d4);          // magic number
        out.writeShort(2);                 // version major
        out.writeShort(4);                 // version minor
        out.writeInt(0);                   // thiszone
        out.writeInt(0);                   // sigfigs
        out.writeInt(SNAPLEN);             // snaplen
        out.writeInt(DLT_EN10MB);          // network (Ethernet)
    }

    private static int headerChecksum(byte[] data, int offset, int length) {
        long sum = 0;
        int i = offset;
        int end = offset + length;
        while (i + 1 < end) {
            sum += word(data, i);
            i += 2;
        }
        if (i < end) {
            sum += ((data[i] & 0xFF) << 8);
        }
        return (int) ~fold(sum);
    }

    private static long fold(long sum) {
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return sum & 0xFFFF;
    }

    private static int word(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static byte[] mac(String colonHex) {
        String[] parts = colonHex.split(":");
        byte[] result = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            result[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return result;
    }

    private BurpEntryData determineEntryData(int entryIdx, HttpRequestResponse entry) {
        HttpService svc = entry.request().httpService();
        String clientIp;
        InetAddress serverInetAddress;

        if (useRealIPs) {
            // 解析真实服务端 IP。
            // Burp 2026.6 里 HttpService.ipAddress() 经常返回空串 (Proxy history 不再填充),
            // 因此优先用它, 失败时从 host() 字段解析 (host 可能是 IP 字面量, 也可能是域名)。
            // 注意: InetAddress.getByName("") 会返回 localhost, 必须显式判空。
            serverInetAddress = resolveServerAddress(svc);
        } else {
            serverInetAddress = parseIpLiteral(SERVER_IP4_ADDRESS);
        }
        boolean isIpv6 = serverInetAddress instanceof Inet6Address;
        clientIp = isIpv6 ? CLIENT_IP6_ADDRESS : CLIENT_IP4_ADDRESS;
        String serverIp = serverInetAddress.getHostAddress();

        InetSocketAddress serverAddress = new InetSocketAddress(serverInetAddress, forcePort80 ? 80 : svc.port());
        InetSocketAddress clientAddress = new InetSocketAddress(parseIpLiteral(clientIp), 10000 + entryIdx);
        Endpoint server = new Endpoint(SERVER_MAC_ADDRESS, serverAddress, 50000 + entryIdx * 10);
        Endpoint client = new Endpoint(CLIENT_MAC_ADDRESS, clientAddress, 10000 + entryIdx * 10);

        Instant ts;
        Optional<TimingData> optional = entry.timingData();
        if (optional.isPresent()) {
            ts = optional.get().timeRequestSent().toInstant();
        } else {
            ts = Instant.ofEpochMilli(System.currentTimeMillis() + entryIdx * 1000L);
        }

        return new BurpEntryData(client, server, ts);
    }

    /**
     * 解析服务端真实地址。
     * 仅接受 IP 字面量, 绝不做 DNS 解析 (避免导出时产生额外的网络请求)。
     * 优先用 HttpService.ipAddress(); 若为空或非法, 再看 HttpService.host() 是否本身是 IP 字面量;
     * 都拿不到时用随机占位 IP (192.0.2.0/24 文档保留段, 不与真实流量混淆)。
     *
     * 注意: 早期版本曾尝试对 host() 做 DNS 解析, 但那会在离线导出 pcap 时触发真实网络请求,
     * 不是预期行为。Burp 2026.6 的 Proxy history 不再填充 ipAddress(), 因此多数情况会落到随机 IP。
     */
    private InetAddress resolveServerAddress(HttpService svc) {
        InetAddress parsed = parseIpLiteral(svc.ipAddress());
        if (parsed != null) return parsed;
        // host() 偶尔本身就是 IP 字面量 (例如直连 IP), 这种情况可直接用, 不触发 DNS
        parsed = parseIpLiteral(svc.host());
        if (parsed != null) return parsed;
        return randomServerIp();
    }

    /**
     * 仅当字符串是严格的 IPv4 / IPv6 字面量时, 返回对应 InetAddress; 否则返回 null。
     * 严格做格式校验 + 用 InetAddress.getByAddress(byte[]) 构造, 绝不触发 DNS。
     * (InetAddress.getByName 会解析域名, 不能用它判断"是不是 IP 字面量"。)
     */
    private static InetAddress parseIpLiteral(String s) {
        if (s == null || s.isEmpty()) return null;
        // IPv4: 点分四段, 每段 0-255 纯数字
        if (s.indexOf('.') >= 0 && s.indexOf(':') < 0) {
            String[] octets = s.split("\\.", -1);
            if (octets.length == 4) {
                byte[] addr = new byte[4];
                for (int i = 0; i < 4; i++) {
                    String o = octets[i];
                    if (o.isEmpty()) return null;
                    try {
                        int v = Integer.parseInt(o);
                        if (v < 0 || v > 255) return null;
                        addr[i] = (byte) v;
                    } catch (NumberFormatException e) {
                        return null;
                    }
                }
                try {
                    return InetAddress.getByAddress(addr);
                } catch (Exception ignored) {
                    return null;
                }
            }
            return null;
        }
        // IPv6: 含冒号, 用字面量解析。Inet6Address.getByAddress 本身不触发 DNS,
        // 但需要 16 字节; 这里用包装方法严格校验。
        if (s.indexOf(':') >= 0) {
            try {
                byte[] addr = textToIPv6Bytes(s);
                if (addr != null) {
                    return InetAddress.getByAddress(addr);
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    /**
     * 把 IPv6 字面量转成 16 字节, 非法格式返回 null。不触发 DNS。
     */
    private static byte[] textToIPv6Bytes(String src) {
        // 处理 "::" 缩写
        int doubleColon = src.indexOf("::");
        String[] head;
        String[] tail;
        if (doubleColon >= 0) {
            // 只允许一个 "::"
            if (src.indexOf("::", doubleColon + 1) >= 0) return null;
            String h = src.substring(0, doubleColon);
            String t = src.substring(doubleColon + 2);
            head = h.isEmpty() ? new String[0] : h.split(":", -1);
            tail = t.isEmpty() ? new String[0] : t.split(":", -1);
        } else {
            head = src.split(":", -1);
            tail = new String[0];
        }
        int total = head.length + tail.length;
        if (total > 8) return null;
        byte[] result = new byte[16];
        int pos = 0;
        for (String g : head) {
            byte[] b = hexGroup(g);
            if (b == null) return null;
            result[pos++] = b[0];
            result[pos++] = b[1];
        }
        // "::" 缩写的零填充
        int zeroGroups = 8 - total;
        pos += zeroGroups * 2;
        for (String g : tail) {
            byte[] b = hexGroup(g);
            if (b == null) return null;
            result[pos++] = b[0];
            result[pos++] = b[1];
        }
        return result;
    }

    private static byte[] hexGroup(String g) {
        if (g.isEmpty() || g.length() > 4) return null;
        try {
            int v = Integer.parseInt(g, 16);
            if (v < 0 || v > 0xFFFF) return null;
            return new byte[] { (byte) ((v >> 8) & 0xFF), (byte) (v & 0xFF) };
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * 生成随机服务端占位 IPv4 (192.0.2.0/24, RFC 5737 文档保留段)。
     */
    private static InetAddress randomServerIp() {
        try {
            byte[] addr = new byte[] {
                    (byte) 192, (byte) 0, (byte) 2,
                    (byte) random.nextInt(1, 254)
            };
            return InetAddress.getByAddress(addr);
        } catch (Exception e) {
            return parseIpLiteral(SERVER_IP4_ADDRESS);
        }
    }

    /**
     * 判断字符串是否是 IP 字面量 (供外部/调试参考, 当前实现由 parseIpLiteral 统一处理)。
     */


    @Override
    public void close() throws IOException {
        out.flush();
        out.close();
    }

    enum TcpFlag {
        SYN, SYN_ACK, ACK, PSH_ACK, FIN_ACK, FIN
    }

    record BurpEntryData(Endpoint client, Endpoint server, Instant ts) {}

    record Endpoint(byte[] macAddress, InetSocketAddress inetSocketAddress, int isn) {}
}
