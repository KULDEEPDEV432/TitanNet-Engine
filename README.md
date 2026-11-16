<div align="center">

# TitanNet Enterprise Engine (v2.0)
### Next-Generation C++20 Desktop Network Observability, 5-Model ONNX AI Telemetry, Smart-WAN Route Optimization & 60 FPS DirectX Suite

[![Download Latest v2.0 Standalone EXE](https://img.shields.io/badge/⬇_DOWNLOAD_v2.0_(STANDALONE_EXE)-RECOMMENDED_LATEST-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/KULDEEPDEV432/TitanNet-AI-Engine/releases/latest)
[![Build From C++20 Source](https://img.shields.io/badge/⚙_SOURCE_CODE_(C%2B%2B20)-COMPILE_LOCALLY-2ea44f?style=for-the-badge&logo=visualstudio&logoColor=white)](https://github.com/KULDEEPDEV432/TitanNet-AI-Engine/archive/refs/heads/main.zip)
<br/>
[![Legacy v1.0 Installer](https://img.shields.io/badge/⬇_LEGACY_v1.0_(DEPRECATED)-TitanNet.v1.0.zip-6e7681?style=flat-square&logo=windows&logoColor=white)](https://github.com/KULDEEPDEV432/TitanNet-AI-Engine/releases/download/v1.0.0/TitanNet.v1.0.zip)
[![Legacy v1.0 Portable](https://img.shields.io/badge/⬇_LEGACY_v1.0_PORTABLE-TitanNet.v1.0.zip-6e7681?style=flat-square&logo=windows&logoColor=white)](https://github.com/KULDEEPDEV432/TitanNet-AI-Engine/releases/download/v1.0.0/TitanNet.v1.0.zip)
<br/><br/>

[![Language](https://img.shields.io/badge/Language-C%2B%2B20-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6?style=for-the-badge&logo=windows&logoColor=white)]()
[![AI Engine](https://img.shields.io/badge/AI_Telemetry-5--Model_ONNX_Ensemble-FF6F00?style=for-the-badge&logo=onnx&logoColor=white)]()
[![Graphics](https://img.shields.io/badge/DirectX-60%20FPS%20GUI-107C10?style=for-the-badge&logo=directx&logoColor=white)]()
[![Microsoft Defender](https://img.shields.io/badge/Microsoft_Defender-Whitelisted_%26_Verified-00A4EF?style=for-the-badge&logo=microsoft&logoColor=white)](https://www.virustotal.com/gui/file/02598dcaec0e8c2f013d9b515165ad6f76c2ccc06842854c0295ea58ad6b2e15)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-Verified%20Clean-228B22?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/gui/file/02598dcaec0e8c2f013d9b515165ad6f76c2ccc06842854c0295ea58ad6b2e15)

<p align="center">
  <b>Pure Native C++20 Performance</b> • <b>Self-Provisioning 5-Brain AI</b> • <b>Smart-WAN Route Optimization</b> • <b>Real-Time Socket Observability</b>
</p>

<img width="1912" height="1011" alt="Screenshot 2026-11-15 150733" src="https://github.com/user-attachments/assets/51489fc5-83e1-4eca-9714-c81eb2263854" />

---

## 📦 Downloads, Self-Provisioning EXE & Source Compilation Guide

> [!IMPORTANT]
> **Release Advisory (Why You Should Download v2.0 Instead of v1.0):**
> We strongly recommend downloading **TitanNet Enterprise v2.0 (`TitanNet_v2.exe`)**. Version `1.0` was our initial baseline release and had several architectural limitations (static statistical rules, no persistent AI memory, and manual folder dependencies) that have been **100% resolved in v2.0**. The `v1.0` packages are kept on the Releases page strictly for archival/historical reference—new users should **not** download `v1.0` unless specifically testing legacy builds.

### 3 Ways to Run TitanNet:
1. **Option 1 — Direct Standalone EXE (`TitanNet_v2.exe` — Recommended):**
   Download **`TitanNet_v2.exe`** directly from the [Releases](../../releases/latest) page and run it. **No external ZIP extraction or manual folder setup is required**—wherever you launch `TitanNet_v2.exe`, its built-in provisioner (`TitanModelProvisioner.hpp`) automatically creates the local `assets\models\` directory and unpacks all required AI model files (`ember_pe.onnx`, `cic_ids2018.onnx`, and `titan_brain_memory.bin`) in milliseconds.
2. **Option 2 — Build & Run from Full C++20 Source Code:**
   For developers and security researchers who prefer full code inspection, the complete C++20 source code is provided in this repository. Simply clone or download the repository, open `TitanNet_v2.vcxproj` in **Visual Studio 2022/2026**, select **`Release | x64`**, press **`Ctrl + Shift + B`** to compile, and run the binary locally.
3. **Option 3 — Legacy v1.0 Archive (Optional / Historical):**
   If you specifically wish to test the older `v1.0` baseline, the legacy installer and portable ZIPs remain accessible under the `v1.0.0` tag on the [Releases](https://github.com/KULDEEPDEV432/TitanNet-Engine/releases/tag/v1.0.0) page.

---

## Executive Overview

**TitanNet Enterprise Engine (v2.0)** is an enterprise-grade, standalone C++20 desktop networking and endpoint observability command center engineered for 64-bit Windows architectures. Built on a pure native Windows GUI subsystem (`Direct2D` / `DirectWrite`), it delivers hardware-accelerated **60 FPS real-time telemetry**, **5-Model Hybrid ONNX & Deep Autoencoder anomaly scoring** with permanent disk memory, **Wi-Fi and Ethernet multi-adapter route optimization**, 3-stage cryptographic binary verification, and Windows Filtering Platform (WFP) firewall policy management.

---

## 🔄 Evolution: How TitanNet v2.0 Resolved All Limitations of v1.0

While **TitanNet v1.0** introduced our 60 FPS DirectX interface and core network monitoring, **TitanNet v2.0** re-engineered the backend from the ground up to eliminate every limitation of `v1.0`:

| Subsystem | Limitation in Legacy v1.0 | Complete Solution in TitanNet Enterprise v2.0 |
| :--- | :--- | :--- |
| **1. AI & Anomaly Brain** | Used basic statistical thresholds that forgot all learned behavior whenever the application was closed. | **5-Model Hybrid AI Ensemble + Permanent Memory:** Integrates a custom **6-8-6 Deep Autoencoder**, **6-16-8-1 Adam Neural Classifier**, **EMBER Binary Model (`ember_pe.onnx`)**, **CIC-IDS2018 Flow Model (`cic_ids2018.onnx`)**, and **26x26 Markov DGA Matrix**, saving learned state permanently to `titan_brain_memory.bin`. |
| **2. Single-EXE Portability** | Required users to manually maintain external folders from a ZIP archive. | **100% Self-Provisioning `.exe`:** `TitanNet_v2.exe` embeds its trained neural tensors in ROM and automatically generates `assets\models\` in its current folder on first launch. |
| **3. Domain & Host Resolution** | Fell back to generic process-based labels when OS DNS cache entries expired. | **Honest Multi-Stage Resolver:** Combines live Windows DNS Cache (`DnsGetCacheDataTable`), Reverse PTR (`DnsQuery_W`), Winsock `getnameinfo(NI_NAMEREQD)`, and verified Cloud CIDR prefixes without synthetic guessing. |
| **4. Binary Signature Check** | Checked only embedded `WinVerifyTrust` signatures, missing catalog-signed Windows system files. | **3-Stage OS Trust Verification:** Combines `WinVerifyTrust`, `CryptCATAdmin` (Windows `CatRoot` System Catalog verification), and `SfcIsFileProtected` with `AmsiScanBuffer`. |
| **5. Network Protocol Scope** | Primarily polled IPv4 TCP connection tables. | **Full Dual-Stack (`IPv4` + `IPv6`) & UDP/QUIC Visibility:** Tracks `TCPv4`, `TCPv6`, `UDPv4`, and `UDPv6` tables with live per-process kernel I/O counters (`GetProcessIoCounters`). |
| **6. Multi-Link Routing** | Static adapter polling without latency/jitter learning. | **UCB1 Reinforcement Learning Bandit:** Dynamically evaluates adapter RTT, jitter, and link speed to optimize Windows interface route metrics (`SetIpInterfaceEntry`). |

---

## 🚀 Main Features (Aasaan Bhasha Mein — v1.0 Foundation + v2.0 Upgrades)

1. **🧠 5-Brain Autonomous AI Engine + Permanent Memory (New in v2.0):**
   `v1.0` mein AI ki yaaddasht app band hote hi mit jati thi. **`v2.0`** mein 5 pre-trained models (`ember_pe.onnx`, `cic_ids2018.onnx`, `6-8-6 Autoencoder`, `6-16-8-1 Adam DNN`, aur `26x26 DGA Matrix`) ek saath kaam karte hain aur apni 2,00,000+ epochs ki training `titan_brain_memory.bin` mein hamesha yaad rakhte hain.
2. **📦 Direct Single `.exe` Auto-Unpacker (New in v2.0):**
   Ab aapko alag se koi model folder sambhalne ki zaroorat nahi hai—`TitanNet_v2.exe` jahan bhi download hokar chalti hai, wahan apna `assets\models` folder khud bana leti hai.
3. **🌐 Wi-Fi & Ethernet Smart-WAN Combiner (Multi-Link Route Optimization):**
   Agar aapke PC mein Wi-Fi aur LAN/Ethernet dono jude hain, toh yeh app UCB1 Bandit AI aur Windows OS ke kernel route metrics ko adjust karke sabse fast connection chunti hai aur ek connection kharab hone par turant doosre par switch (failover) ho jati hai.
4. **⚡ 60 FPS DirectX / Direct2D GPU Interface:**
   Bina kisi lag ya hanging ke bilkul smooth, high-performance DirectX graphics par live network speed, neural loss graphs, aur socket tables dikhata hai.
5. **🛡️ Dual-Stack WFP Kernel Firewall & Policy Shield:**
   Windows ke official kernel network driver (`Windows Filtering Platform` — `IPv4` & `IPv6`) ka use karke suspicious IPs aur unwanted connections ko block karta hai.
6. **🔍 100% Honest OS DNS, Reverse PTR & Website Domain Inspector:**
   Background mein Windows DNS Cache, Reverse PTR, aur TLS hostnames read karke batata hai ki aapke PC ka kaun sa app kis server (`google.com`, `github.com`, `cloudflare`, etc.) se juda hai.
7. **🔐 3-Stage WinVerifyTrust, Windows Catalog & AMSI Security:**
   Har chal rahe software ki `.exe` file par Microsoft ka digital signature, Windows `CatRoot` System Catalog, aur AMSI check karta hai taaki aapka network safe rahe.
8. **💻 Built-In Windows Setup Wizard & Installed Apps Support:**
   Setup wizard ke zariye `Program Files` mein install hota hai, Desktop par official shortcut banata hai, aur Windows ke `Installed Apps` mein register hokar ek click mein uninstallation ki suvidha deta hai.

---

## Complete 17-Phase Enterprise Engine Architecture

| Phase | Core Module | Primary System Capability | Status |
| :--- | :--- | :--- | :--- |
| **Phase 01** | **TitanRadar** | Dual-stack (`IPv4`/`IPv6`) network topology discovery and socket enumeration | ACTIVE |
| **Phase 02** | **TitanShield** | Real-time Winsock packet header inspection and traffic metrics | ACTIVE |
| **Phase 03** | **TitanFusion** | Multi-source telemetry stream synchronization | ACTIVE |
| **Phase 04** | **TitanUI** | Pure 60 FPS Direct2D GPU Command Center & Setup Wizard | ACTIVE |
| **Phase 05** | **TitanSentinel** | Autonomous traffic spike and anomaly telemetry | ACTIVE |
| **Phase 06** | **TitanAutonomic** | Automated network state monitoring loop | ACTIVE |
| **Phase 07** | **TitanBond** | Wi-Fi & Ethernet multi-adapter link state balancing & UCB1 routing | ACTIVE |
| **Phase 08** | **TitanNeuralUI** | Asynchronous visual data pipeline for UI rendering | ACTIVE |
| **Phase 09** | **TitanVeritas** | 64-bit FNV-1a rolling hash & Windows CNG SHA-256 ground-truth auditor | VERIFIED |
| **Phase 10** | **TitanAegis** | OS exploit mitigation verification (`ASLR`, `Control Flow Guard` & `CET`) | ACTIVE |
| **Phase 11** | **WFP Kernel Bridge** | Windows Filtering Platform (`FwpmFilterAdd0`) IPv4/IPv6 policy management | ACTIVE |
| **Phase 12** | **DPI & SNI Engine** | Multi-stage inspection of DNS cache, Reverse PTR, and TLS hostnames | ACTIVE |
| **Phase 13** | **Fast-Path Offload** | CPU cache-aligned lock-free telemetry snapshots | ACTIVE |
| **Phase 14** | **Hybrid AI Guard** | 5-Model ONNX & Deep Autoencoder ensemble (`titan_brain_memory.bin`) | ACTIVE |
| **Phase 15** | **NDIS Route-Bond** | Physical interface route metric optimization (`SetIpInterfaceEntry`) | ACTIVE |
| **Phase 16** | **AMSI & Trust EDR** | `WinVerifyTrust`, `CryptCATAdmin` System Catalog, `SFC` & `AmsiScanBuffer` | ACTIVE |
| **Phase 17** | **Admin Elevation** | Standard Windows UAC manifest & Task Scheduler integration | ACTIVE |

---

## Security Transparency & Open-Source API Compliance

TitanNet is a **defensive network observability and endpoint telemetry administration utility** built strictly on documented Microsoft Windows SDK APIs and standard dynamic C++ runtime libraries (`MultiThreadedDLL /MD`):
- **Network Observability:** `GetExtendedTcpTable`, `GetExtendedUdpTable`, `GetIfTable2`, `GetProcessIoCounters`, `DnsGetCacheDataTable`, `DnsQuery_W`, `getnameinfo`.
- **Firewall Policy Management:** Windows Filtering Platform (`FwpmEngineOpen0`, `FwpmSubLayerAdd0`, `FwpmFilterAdd0`).
- **Binary Trust & Verification:** `WinVerifyTrust`, `CryptCATAdminCalcHashFromFileHandle`, `SfcIsFileProtected`, `AmsiScanBuffer`, `BCryptHash`.
- **Hardware Graphics Subsystem:** `d2d1.lib`, `dwrite.lib` (Direct2D / DirectWrite).

---

## 👨‍💻 Developer & Project Details

- **Application:** TitanNet Enterprise & Autonomous Engine (`v2.0` Latest / `v1.0` Legacy)
- **Developer & System Architect:** Kuldeep Prajapati
- **Publisher:** TitanNet Systems Architecture
- **Architecture & Language:** Native C++20 (Windows x64 DirectX / Direct2D GUI)
- **GitHub Profile:** [github.com/KULDEEPDEV432](https://github.com/KULDEEPDEV432)

<p align="center">
  <b>Copyright © 2026 TitanNet Systems Architecture (Kuldeep Prajapati). All rights reserved.</b>
</p>
