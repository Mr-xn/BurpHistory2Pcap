# BurpHistory2Pcap（中文文档）

> English documentation: [README.md](README.md)

[burp2pcap](https://github.com/turekt/burp2pcap) 的 Burp 扩展实现。
BurpHistory2Pcap 可以把 Burp Proxy HTTP History 里选中的流量直接导出为 PCAP 文件。

---

## 本仓库的改动说明

本仓库 fork 自 [turekt/burp2pcap](https://github.com/turekt/burp2pcap) 的 BApp Store 版本
（`HTTP History to PCAP`，UUID `1de644f1b90e4f54bc385bd1ffc1b147`，v1.0.0），
针对 **Burp Suite 2026.6** 的兼容性问题做了重写。改动集中在 PCAP 写出层
（`src/main/java/BurpPcapWriter.java`）和构建依赖（`pom.xml` / `build.gradle`），
对外功能与右键菜单交互保持不变。

### 为什么改

原版本依赖 **pcap4j + JNA + 系统 libpcap** 来写 PCAP。在 **Burp 2026.4.x → 2026.6** 升级之间，
Burp 把自带的 JNA 从旧版升到了 **7.0.2**，并在启动时先加载了 7.0.2 的 `jnidispatch` 原生库。
而本扩展自带的 JNA 是 5.13.0（期望原生库 6.1.6），两者在**同一个 JVM 进程内无法共存**——
导出时 `com.sun.jna.Native` 初始化会检测到已加载的 7.0.2 与期望的 6.1.6 不匹配，抛出
`java.lang.Error: incompatible JNA native library`。

更隐蔽的是：原代码用 `catch (UnsatisfiedLinkError | Exception)` 捕获异常，而这个 `Error`
不属于其中任何一类，且导出跑在一个没有 `UncaughtExceptionHandler` 的裸 `Thread` 里，
导致**线程静默死亡**——表现就是「点 OK 没有任何反应」，连错误对话框都不弹，
Burp 的 Extensions / Errors 面板也是空的。

我曾尝试过几种"让插件自带 JNA"的修复（升级 JNA、设 `jna.nosys=true`、复用 Burp 的 JNA），
均被最小复现实验一一证伪：要么拿不到 JNA 7.0.2（PortSwigger 内部 fork，未发布到 Maven），
要么因扩展类加载器隔离而 `NoClassDefFoundError`，要么同一个 JVM 进程内原生符号已被
7.0.2 占用导致 `jna.nosys` 也无济于事。因此唯一干净的解法是**彻底去掉原生依赖**。

### 改了什么

- **`BurpPcapWriter.java` 完全重写为纯 Java**：自己写 PCAP 全局头 / per-packet 记录头，
  自己构造 Ethernet / IPv4 / IPv6 / TCP 报文（含正确的校验和计算），不再调用 pcap4j / JNA / libpcap。
- **`BurpHistory2Pcap.java` 加入了完整的日志体系**：通过 Montoya 的 `Logging` API，
  把加载信息和每次导出的进度写入 Burp 的 **Extensions → Output** 面板，把任何失败（含完整堆栈）
  写入 **Extensions → Errors** 面板。导出的异常处理从 `catch (UnsatisfiedLinkError | Exception)`
  放宽为 `catch (Throwable)`，并给导出线程安装了 `UncaughtExceptionHandler` 作为最后防线——
  这样「线程静默死亡」（最初的故障现象）再也不会发生。
- **`pom.xml` / `build.gradle`** 去掉 `pcap4j-core`、`jna`、`jna-platform`、`slf4j-api`、
  `slf4j-simple` 依赖，只保留 `montoya-api`。
- **目的 IP 解析逻辑**：只接受 IP 字面量（IPv4 / IPv6 自动判别），**导出时绝不发起 DNS 查询**；
  当 Burp 没有记录有效 IP（例如只记录了域名，这在 2026.6 的 Proxy history 里很常见，
  `HttpService.ipAddress()` 返回空）时，使用随机占位 IP（`192.0.2.0/24`，RFC 5737 文档保留段）。

### 这些变化带来的好处

- ✅ **兼容 Burp 2026.6 及以后**：不再与 Burp 自带的 JNA 版本冲突，根本上解决「点 OK 无反应」的问题。
- ✅ **零原生依赖**：不再需要系统安装 libpcap，也不再依赖 JNA 原生库，Windows / macOS / Linux
  开箱即用，也不再受 `--enable-native-access` 等运行时限制影响。
- ✅ **体积大幅缩小**：打包后的 jar 从 ~4.7 MB（含 JNA / pcap4j / slf4j）降到 ~180 KB。
- ✅ **导出更纯净**：不再为了填 IP 而对域名做 DNS 查询，避免在离线导出时产生意外的网络请求。
- ✅ **生成文件已验证**：导出的 PCAP 可被 tcpdump / Wireshark 正确解析，TCP 校验和正确，
  完整保留 TCP 握手、HTTP 请求 / 响应、拆链过程。
- ✅ **天生可观测**：每次导出都会记录（host、状态码、包数）到 Extensions / Output 面板，
  每次失败都会带完整堆栈记录到 Extensions / Errors 面板。不会再有静默失败——
  最初那个「点 OK 无反应」的 bug，如果有这套日志，堆栈会立刻显示出来。

> 注：随机占位 IP 意味着 Wireshark 里看到的源/目的 IP 不是真实服务器地址。
> 这只影响"按 IP 过滤"，不影响 HTTP 对话内容的查看与协议解析（这也是 pcap 导出的主要价值）。
> 如果 Burp 记录了真实 IP（`HttpService.ipAddress()` 返回有效字面量），勾选
> "Use real server IPs" 时仍然会使用真实 IP。

---

## 运行要求

本扩展用纯 Java 生成 PCAP，**无需任何原生库（libpcap / JNA）**，任意系统开箱即用。

## 构建

构建环境要求：
- JDK 21+
- Gradle 或 Maven

### 用 Gradle 构建

```
gradle jar
```
把 `build/libs` 目录下的 `burphistory2pcap.jar` 导入 Burp Suite。

### 用 Maven 构建

```
mvn package
```
把 `target` 目录下的 `burphistory2pcap-1.0.0.jar` 导入 Burp Suite。

### 使用 GitHub Actions 手动触发打包并发布 Release

仓库已内置 `.github/workflows/release.yml`，可手动触发发布。

1. 打开 **GitHub → Actions → Manual Release → Run workflow**
2. 填写参数：
   - `tag`（必填，例如 `v1.0.1`）
   - `release_name`（可选）
   - `prerelease`（可选）
   - `generate_release_notes`（可选）
3. 点击运行

该工作流会构建 `build/libs/burphistory2pcap.jar` 并上传到 GitHub Release。

## 使用方法

在 Proxy 下的 HTTP History 标签页选中要导出的记录（Ctrl + A 全选），右键打开上下文菜单，选择：
```
Extensions -> BurpHistory2Pcap -> Export selected HTTP message(s) to PCAP
```

导出选项说明：
- **Filepath**
  - PCAP 文件的本地保存路径
- **Use port 80**
  - 勾选后把 PCAP 里服务端端口统一改为 HTTP 80，可显著改善 Wireshark 的 HTTP 解析效果
  - 不勾选则保留实际端口
- **Use real server IPs**
  - 勾选后，当 Burp 记录了真实服务端 IP 时使用真实 IP；当拿不到有效 IP
    （例如只记录了域名）时使用随机占位 IP（`192.0.2.0/24`）——**导出过程不会发起 DNS 查询**
  - 不勾选则使用预定义的本地占位 IP

扩展会按上述设置，把选中的 HTTP 消息生成 PCAP 文件，保存到指定路径。

## 日志

本扩展通过 Montoya 的 `Logging` API 把日志写入 Burp 自带的扩展控制台。在
**Extensions → Installed → BurpHistory2Pcap** 里可以看到两个面板：

- **Output 面板**：扩展加载信息（Java / OS 版本、写出器类型）；每次导出时记录目标路径、
  选中消息数、每条记录的 host 与状态码、最终写入的包数。
- **Errors 面板**：任何导出失败都会带完整堆栈记录（`logToError(msg, throwable)`）。
  导出线程还安装了 `UncaughtExceptionHandler`，所以即便有未捕获的 `Error`
  （最初的静默失败模式）也会被记录到这里，而不会让线程无声无息地死掉。

成功导出的日志示例：
```
BurpHistory2Pcap loaded.
  java.version   = 26.0.1
  ...
Export started: 1 message(s) -> /Users/me/out.pcap (forcePort80=true, useRealIPs=true)
  [1/1] host=cip.cc status=200
Export complete: 10 packet(s) written to /Users/me/out.pcap
```
