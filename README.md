# BurpHistory2Pcap

A [burp2pcap](https://github.com/turekt/burp2pcap) script implemented as a Burp extension.
BurpHistory2Pcap exports selected traffic directly from Burp HTTP History tab into a PCAP file.

> **中文文档**: [README_zh.md](README_zh.md)

---

## About this fork

This repo is a fork of [turekt/burp2pcap](https://github.com/turekt/burp2pcap) (the BApp Store
build *"HTTP History to PCAP"*, UUID `1de644f1b90e4f54bc385bd1ffc1b147`, v1.0.0). It is rewritten
for **Burp Suite 2026.6** compatibility. The changes are isolated to the PCAP writer
(`src/main/java/BurpPcapWriter.java`) and build dependencies (`pom.xml` / `build.gradle`);
the user-facing feature set and right-click menu behaviour are unchanged.

### Why it was changed

The original version relied on **pcap4j + JNA + the system libpcap** to write PCAP files.
Between **Burp 2026.4.x and 2026.6**, Burp upgraded its bundled JNA to **7.0.2** and loads the
7.0.2 `jnidispatch` native library at startup. The extension shipped JNA 5.13.0 (expecting native
`6.1.6`), and **two JNA native versions cannot coexist in a single JVM process** — so on export,
`com.sun.jna.Native` detects the already-loaded 7.0.2 vs the expected 6.1.6 and throws
`java.lang.Error: incompatible JNA native library`.

Worse, the original `catch (UnsatisfiedLinkError | Exception)` does not cover that `Error`, and
the export runs on a bare `Thread` without an `UncaughtExceptionHandler`, so the thread dies
silently — the symptom is exactly *"clicking OK does nothing"*: no success dialog, no error
dialog, and an empty Errors panel.

Several "keep JNA bundled" fixes were attempted and disproved by minimal reproductions (upgrading
JNA, `jna.nosys=true`, reusing Burp's JNA): JNA 7.0.2 is a PortSwigger internal fork not on
Maven; the extension classloader is isolated so removing JNA causes `NoClassDefFoundError`; and
`jna.nosys` cannot help when the native symbol is already taken by 7.0.2. The only clean fix is
to **remove the native dependency entirely**.

### What changed

- **`BurpPcapWriter.java` is rewritten in pure Java**: writes the PCAP global/per-packet headers
  itself and constructs Ethernet / IPv4 / IPv6 / TCP packets (with correct checksums) — no
  pcap4j, no JNA, no libpcap.
- **`BurpHistory2Pcap.java` now has a logging system**: it writes load info and per-export
  progress to Burp's **Extensions → Output** panel, and any failure (with full stack trace) to
  the **Extensions → Errors** panel via the Montoya `Logging` API. The export's exception
  handler was widened from `catch (UnsatisfiedLinkError | Exception)` to `catch (Throwable)`,
  and the export thread now installs an `UncaughtExceptionHandler` as a last line of defence —
  so a silent thread death (the original failure mode) can no longer happen.
- **`pom.xml` / `build.gradle`** drop `pcap4j-core`, `jna`, `jna-platform`, `slf4j-api`,
  `slf4j-simple`; only `montoya-api` remains.
- **Server IP resolution**: only IP literals are accepted (IPv4 / IPv6 auto-detected); **no DNS
  lookups are performed during export**. When Burp has no valid IP on record (e.g. only a
  hostname — common in 2026.6 where `HttpService.ipAddress()` returns empty), a random
  placeholder IP from `192.0.2.0/24` (RFC 5737 documentation range) is used.

### Benefits of these changes

- ✅ **Compatible with Burp 2026.6+** — no more conflict with Burp's bundled JNA; the
  "clicking OK does nothing" failure is fixed at the root.
- ✅ **Zero native dependencies** — no libpcap to install, no JNA native library, works
  out-of-the-box on Windows / macOS / Linux, and is unaffected by `--enable-native-access`.
- ✅ **Much smaller artifact** — the packaged jar drops from ~4.7 MB (with JNA/pcap4j/slf4j)
  to ~180 KB.
- ✅ **Cleaner exports** — no DNS queries are issued to fill in IPs, so offline export never
  makes unexpected network requests.
- ✅ **Verified output** — generated PCAPs parse correctly in tcpdump / Wireshark with correct
  TCP checksums and full TCP handshake / HTTP request-response / teardown.
- ✅ **Observable by design** — every export is logged (host, status, packet count) to the
  Extensions / Output panel, and every failure is logged with a full stack trace to the
  Extensions / Errors panel. No more silent failures; the original "clicking OK does nothing"
  bug would have shown its stack trace immediately.

> Note: the random placeholder IP means the source/destination IPs shown in Wireshark are not
> the real server addresses. This only affects "filter by IP"; it does not affect viewing the
> HTTP conversation or protocol dissection, which is the main value of the export. If Burp did
> record a real IP (`HttpService.ipAddress()` returns a valid literal), it is still used when
> "Use real server IPs" is checked.

---

## Requirements

This extension generates PCAP files in pure Java — no native libraries (libpcap/JNA) are
required, so it works on any system without extra dependencies.

## Build

Requirements to build the extension:
- JDK 21+
- Gradle or Maven

### Build using Gradle

Gradle build command:
```
gradle jar
```
Import `burphistory2pcap.jar` file located in `build/libs` folder to Burp suite.

### Build using Maven

Maven build command:
```
mvn package
```
Import `burphistory2pcap-1.0.0.jar` file located in `target` folder to Burp suite.

## Usage

In HTTP History tab under Proxy, select rows that you want to export (Ctrl + A to select all) and then right click to open context menu. Under context menu choose:
```
Extensions -> BurpHistory2Pcap -> Export selected HTTP message(s) to PCAP
```

Specify write options:
- Filepath
  - local path where the PCAP file will be saved
- Use port 80
  - if checked sets the server port in the PCAP file to HTTP 80 which significantly improves Wireshark packet dissection
  - uncheck if you want to have actual server port in your PCAP file
- Use real server IPs
  - if checked, the PCAP uses the server's real IP when available (as recorded by Burp);
    when the real IP is unavailable (e.g. Burp recorded a hostname and no IP literal),
    a random placeholder IP from `192.0.2.0/24` is used instead — no DNS lookups are
    performed during export
  - if unchecked, server IP will be set to a predefined local IP

The extension will generate a PCAP file containing selected HTTP messages on the specified filepath with set options.

## Logging

The extension logs to Burp's built-in extension console via the Montoya `Logging` API. Open
**Extensions → Installed → BurpHistory2Pcap** to view the panels:

- **Output panel** — extension load info (Java/OS version, writer type) and, on each export, the
  target path, selected message count, per-entry host and status code, and the final packet count.
- **Errors panel** — any export failure with a full stack trace (`logToError(msg, throwable)`).
  The export thread also installs an `UncaughtExceptionHandler`, so even an uncaught `Error`
  (the original silent-failure mode) is captured here rather than killing the thread silently.

Example output (successful export):
```
BurpHistory2Pcap loaded.
  java.version   = 26.0.1
  ...
Export started: 1 message(s) -> /Users/me/out.pcap (forcePort80=true, useRealIPs=true)
  [1/1] host=cip.cc status=200
Export complete: 10 packet(s) written to /Users/me/out.pcap
```

