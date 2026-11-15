<div align="center">

# TitanNet Enterprise Engine (v2.0 & v1.0)
### Next-Generation C++20 Desktop Network Observability, Multi-Model ONNX AI Telemetry, Smart-WAN Route Optimization & Direct2D Visualization Suite

[![Download TitanNet v2.0 EXE](https://img.shields.io/badge/⬇_DOWNLOAD_LATEST_(v2.0_EXE)-TitanNet_v2.exe-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/KULDEEPDEV432/TitanNet-AI-Engine/releases/latest)
[![Download Installer ZIP (v1.0)](https://img.shields.io/badge/⬇_DOWNLOAD_INSTALLER_(v1.0_ZIP)-TitanNet.v1.0.zip-2ea44f?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/KULDEEPDEV432/TitanNet-AI-Engine/releases/download/v1.0.0/TitanNet.v1.0.zip)
[![Download Portable ZIP (v1.0)](https://img.shields.io/badge/⬇_PORTABLE_VERSION_(v1.0_ZIP)-TitanNet.v1.0.zip-2ea44f?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/KULDEEPDEV432/TitanNet-AI-Engine/releases/download/v1.0.0/TitanNet.v1.0.zip)
<br/>

[![Language](https://img.shields.io/badge/Language-C%2B%2B20-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6?style=for-the-badge&logo=windows&logoColor=white)]()
[![AI Engine](https://img.shields.io/badge/AI_Telemetry-ONNX_%2B_Autoencoder-FF6F00?style=for-the-badge&logo=onnx&logoColor=white)]()
[![Graphics](https://img.shields.io/badge/DirectX-60%20FPS%20GUI-107C10?style=for-the-badge&logo=directx&logoColor=white)]()
[![Microsoft Defender](https://img.shields.io/badge/Microsoft_Defender-Whitelisted_%26_Verified-00A4EF?style=for-the-badge&logo=microsoft&logoColor=white)](https://www.virustotal.com/gui/file/02598dcaec0e8c2f013d9b515165ad6f76c2ccc06842854c0295ea58ad6b2e15)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-Verified%20Clean-228B22?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/gui/file/02598dcaec0e8c2f013d9b515165ad6f76c2ccc06842854c0295ea58ad6b2e15)

<p align="center">
  <b>Pure Native C++20 Performance</b> • <b>5-Model Hybrid AI Telemetry</b> • <b>Smart-WAN Route Optimization</b> • <b>Real-Time Socket Observability</b>
</p>

<img width="1906" height="996" alt="Screenshot 2026-11-04 133342" src="https://github.com/user-attachments/assets/3f8bf73a-f22b-43dc-9d3c-e0aef8da81fe" />
</div>

---

## Downloads & Build Options

- **TitanNet Enterprise v2.0 (Latest Self-Contained Release):** Available on the [Releases](../../releases) page. The standalone `TitanNet_v2.exe` binary automatically provisions its local `assets/models` AI directory (`ember_pe.onnx`, `cic_ids2018.onnx`, and `titan_brain_memory.bin`) on first launch.
- **TitanNet v1.0 (Baseline Release):** Official v1.0 installer and portable packages remain available on the [Releases](../../releases) page.
- **Build from Source:** All standard C++20 source and header files are included in this repository for transparent local compilation via Visual Studio 2022/2026 (`MultiThreadedDLL /MD`).

---

## What's New in TitanNet Enterprise v2.0 (Evolution from v1.0)

**TitanNet Enterprise v2.0** is a major architectural upgrade built to resolve the technical limitations of `v1.0`. While `v1.0` established the core 60 FPS Direct2D GUI and basic socket monitoring, `v2.0` upgrades every subsystem to genuine OS APIs, persistent multi-model machine learning, and dual-stack networking.

### How v2.0 Solved the Limitations of v1.0

| Subsystem | Limitation in TitanNet v1.0 | Upgraded Solution in TitanNet Enterprise v2.0 |
| :--- | :--- | :--- |
| **1. AI & Anomaly Telemetry** | Relied primarily on static statistical rules and memory-only Z-score thresholds that reset when closing the app. | **5-Model Hybrid AI Ensemble:** Combines a custom **6-8-6 Deep Autoencoder** (with persistent disk memory via `titan_brain_memory.bin`), a **6-16-8-1 Adam Neural Classifier**, **EMBER Structural Binary Telemetry (`ember_pe.onnx`)**, **CIC-IDS2018 Flow Telemetry (`cic_ids2018.onnx`)**, and a **26x26 Markov Bigram Matrix**. |
| **2. Domain & Host Resolution** | Used fallback process-name labels when DNS cache entries expired. | **100% Honest Multi-Stage Resolver:** Combines Windows DNS Cache (`DnsGetCacheDataTable`), live Reverse PTR (`DnsQuery_W`), Winsock `getnameinfo(NI_NAMEREQD)`, and verified Cloud CIDR prefixes without synthetic guessing. |
| **3. Binary Trust Verification** | Checked only basic embedded file signatures (`WinVerifyTrust`), which could misclassify catalog-signed Windows binaries. | **3-Stage OS Verification:** Integrates `WinVerifyTrust`, `CryptCATAdmin` (Windows `CatRoot` System Catalog verification), and `SfcIsFileProtected` alongside Microsoft `AmsiScanBuffer` integration. |
| **4. Network Stack Coverage** | Focused primarily on IPv4 TCP table polling. | **Full Dual-Stack (IPv4 + IPv6) & UDP/QUIC Visibility:** Inspects `TCPv4`, `TCPv6`, `UDPv4`, and `UDPv6` extended tables (`GetExtendedTcpTable` / `GetExtendedUdpTable`) with per-process I/O counters (`GetProcessIoCounters`). |
| **5. Multi-Adapter Management** | Basic adapter polling without latency-aware learning. | **UCB1 Reinforcement Learning Route Optimizer:** Continuously measures adapter RTT latency, jitter, and link speed to compute optimal Windows IP interface route metrics (`SetIpInterfaceEntry`). |
| **6. Deployment Portability** | Required manual extraction of external configuration folders. | **Self-Provisioning Architecture:** Automatically initializes its required `assets/models/` neural weight files in the local directory upon startup. |

---

## 🌟 TitanNet v2.0 Upgrades (Aasaan Bhasha Mein)

1. **🧠 5-Brain Real AI Engine + Permanent Memory (`titan_brain_memory.bin`):**
   `v1.0` mein basic statistical rules the aur app band karne par AI ki learning zero ho jati thi. **`v2.0`** mein 5 pre-trained models (`ember_pe.onnx`, `cic_ids2018.onnx`, `6-8-6 Autoencoder`, `6-16-8-1 Adam DNN`, aur `26x26 DGA Matrix`) ek saath kaam karte hain aur apni 2,00,000+ epochs ki yaaddasht disk par hamesha yaad rakhte hain.
2. **🔍 100% Real Website & Hostname Resolution:**
   Ab koi bhi domain andaze se nahi dikhaya jata—Windows DNS Cache, Reverse PTR, aur Winsock Kernel `getnameinfo` se 100% asli server hostnames aur Cloud providers dikhte hain.
3. **🛡️ 3-Stage Microsoft Signature & System Catalog Check:**
   Ab `WinVerifyTrust` ke saath Windows `CatRoot` System Catalog (`CryptCATAdmin`) aur `SFC` juda hai, jisse asli Windows aur Microsoft processes ki 100% sahi pehchan hoti hai.
4. **📦 Self-Contained Single `.exe` (Auto-Model Unpacker):**
   User ko alag se koi model folder set karne ki zaroorat nahi hai—`TitanNet_v2.exe` jahan bhi run hota hai, wahan apna `assets\models` folder khud bana leta hai.

---

## Executive Overview (Core v1.0 & v2.0 Foundation)

**TitanNet** is an enterprise-grade, standalone C++20 desktop networking and telemetry command center engineered for 64-bit Windows architectures. Designed with a pure Windows GUI subsystem, it delivers hardware-accelerated **60 FPS DirectX/Direct2D telemetry**, real-time network interface monitoring, **Wi-Fi and Ethernet multi-adapter route optimization**, cryptographic state verification, and Windows Filtering Platform (WFP) firewall policy management.

---

## 🚀 Main Features (Aasaan Bhasha Mein — Preserved from v1.0)

1. **🌐 Wi-Fi & Ethernet Speed Combiner (Multi-Link Route Optimization):**
   Agar aapke PC mein Wi-Fi aur LAN/Ethernet dono jude hain, toh yeh app Windows OS ke kernel routes ko adjust karke dono ka internet smart tarike se use karne mein madad karti hai aur ek connection kharab hone par turant doosre par switch (failover) ho jati hai.
2. **⚡ 60 FPS DirectX GPU Interface:**
   Bina kisi lag ya hanging ke bilkul smooth, high-performance DirectX graphics par live network speed aur graphs dikhata hai.
3. **🛡️ WFP Kernel Firewall & Tracker Shield:**
   Windows ke official kernel network driver (`Windows Filtering Platform`) ka use karke unwanted IPs aur suspicious connections ko block karta hai.
4. **🔍 Live OS DNS & Website Domain Inspector:**
   Background mein Windows DNS Cache aur TLS SNI read karke batata hai ki aapke PC ka kaun sa app kis website ya server (`google.com`, `github.com` etc.) se data bhej raha hai.
5. **🔐 WinVerifyTrust, Catalog & AMSI Security:**
   Har chal rahe software ki `.exe` file par Microsoft ka digital signature aur catalog check karta hai taaki aapka network safe rahe.
6. **💻 Official Windows Installer & Installed Apps Support:**
   Setup wizard ke zariye `Program Files` mein install hota hai, Desktop par shortcut banata hai, aur Windows ke `Installed Apps` mein register hokar ek click mein uninstallation ki suvidha deta hai.

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
| **Phase 09** | **TitanVeritas** | 64-bit FNV-1a rolling hash & Windows CNG SHA-256 auditor | VERIFIED |
| **Phase 10** | **TitanAegis** | Compiler mitigation verification (`ASLR`, `Control Flow Guard` & `CET`) | ACTIVE |
| **Phase 11** | **WFP Kernel Bridge** | Windows Filtering Platform (`FwpmFilterAdd0`) IP policy management | ACTIVE |
| **Phase 12** | **DPI & SNI Engine** | Inspection of DNS cache, Reverse PTR, and TLS hostnames | ACTIVE |
| **Phase 13** | **Fast-Path Offload** | CPU cache-aligned lock-free telemetry snapshots | ACTIVE |
| **Phase 14** | **Hybrid AI Guard** | 5-Model ONNX & Deep Autoencoder telemetry (`titan_brain_memory.bin`) | ACTIVE |
| **Phase 15** | **NDIS Route-Bond** | Interface route metric optimization (`SetIpInterfaceEntry`) | ACTIVE |
| **Phase 16** | **AMSI & Trust EDR** | `WinVerifyTrust`, `CryptCATAdmin` Catalog, `SFC`, and `AmsiScanBuffer` | ACTIVE |
| **Phase 17** | **Admin Elevation** | Standard Windows UAC manifest & Task Scheduler integration | ACTIVE |

---

## Security Transparency & Open-Source Compliance

TitanNet is a **defensive network observability and endpoint telemetry administration utility** built strictly on documented Microsoft Windows SDK APIs:
- **Network Telemetry:** `GetExtendedTcpTable`, `GetExtendedUdpTable`, `GetIfTable2`, `GetProcessIoCounters`, `DnsGetCacheDataTable`.
- **Policy Management:** Windows Filtering Platform (`FwpmEngineOpen0`, `FwpmFilterAdd0`).
- **Trust & Verification:** `WinVerifyTrust`, `CryptCATAdminCalcHashFromFileHandle`, `SfcIsFileProtected`, `AmsiScanBuffer`, `BCryptHash`.
- **Graphics Subsystem:** `d2d1.lib`, `dwrite.lib` (Hardware-accelerated Direct2D).

---

## Installation & Deployment Guide

1. **TitanNet v2.0 (Standalone / Auto-Provisioning):** Download **`TitanNet_v2.exe`** (or its release archive) from the [Releases](../../releases) page and launch it as Administrator. On first run, it automatically creates `assets\models\` in its local folder and provisions the pre-trained `.onnx` and `.bin` telemetry models.
2. **TitanNet v1.0 Setup Wizard:** Click the green **DOWNLOAD INSTALLER (v1.0 ZIP)** button at the top, extract **`TitanNet.v1.0.zip`**, and run **`TitanNet v1.0`** to install with Desktop shortcuts and Windows Installed Apps registry integration.
3. **System Requirements:** Windows 10 or Windows 11 (64-bit x64) and a DirectX-compatible GPU for 60 FPS hardware rendering.

---

## 👨‍💻 Developer & Project Details

- **Application:** TitanNet Autonomous & Enterprise Engine (`v1.0` & `v2.0`)
- **Developer & System Architect:** Kuldeep Prajapati
- **Publisher:** TitanNet Systems Architecture
- **Architecture & Language:** Native C++20 (Windows x64 DirectX / Direct2D GUI)
- **GitHub:** [github.com/KULDEEPDEV432](https://github.com/KULDEEPDEV432)

<p align="center">
  <b>Copyright © 2026 TitanNet Systems Architecture (Kuldeep Prajapati). All rights reserved.</b>
</p>
