#include "TitanShield.hpp"
#include "NetworkCore.hpp"

#include <algorithm>
#include <cctype>

namespace TitanNet::Shield {

    TitanShieldEngine::TitanShieldEngine() noexcept {
        // Default Telemetry & Background Tracker Blocklist
        blockedProcesses_ = {
            "PerfWatson2.exe",
            "CompatTelRunner.exe",
            "DiagTrack.exe",
            "WerFault.exe",
            "wermgr.exe"
        };
    }

    TitanShieldEngine::~TitanShieldEngine() noexcept {
        Stop();
    }

    void TitanShieldEngine::Start(std::string_view bindIpv4) noexcept {
        if (snifferThread_.joinable()) {
            return;
        }
        std::string ipCopy(bindIpv4);
        snifferThread_ = std::jthread([this, ip = std::move(ipCopy)](std::stop_token st) {
            SnifferWorker(st, ip);
            });
    }

    void TitanShieldEngine::Stop() noexcept {
        if (snifferThread_.joinable()) {
            snifferThread_.request_stop();
            snifferThread_.join();
        }
    }

    std::string TitanShieldEngine::GetStatusMessage() const noexcept {
        std::scoped_lock lock(eventMutex_);
        return statusMessage_;
    }

    std::vector<ShieldEvent> TitanShieldEngine::GetRecentEvents() const noexcept {
        std::scoped_lock lock(eventMutex_);
        return { recentEvents_.begin(), recentEvents_.end() };
    }

    // ========================================================================
    // MEMORY-SAFE TLS CLIENT-HELLO SNI PARSER (Zero Buffer Over-read)
    // ========================================================================
    std::string TitanShieldEngine::ExtractTlsSniBounded(std::span<const std::uint8_t> tls) noexcept {
        // Minimum TLS Record (5) + Handshake (4) + Version (2) + Random (32) = 43 bytes
        if (tls.size() < 43) return {};

        // ContentType == 0x16 (Handshake), Major Version == 0x03, HandshakeType == 0x01 (ClientHello)
        if (tls[0] != 0x16 || tls[1] != 0x03 || tls[5] != 0x01) {
            return {};
        }

        std::size_t pos = 43;
        if (pos >= tls.size()) return {};

        // 1. Skip Session ID
        const std::size_t sessionIdLen = tls[pos];
        pos += 1 + sessionIdLen;
        if (pos + 2 > tls.size()) return {};

        // 2. Skip Cipher Suites
        const std::size_t cipherSuitesLen = (static_cast<std::size_t>(tls[pos]) << 8) | tls[pos + 1];
        pos += 2 + cipherSuitesLen;
        if (pos + 1 > tls.size()) return {};

        // 3. Skip Compression Methods
        const std::size_t compressionLen = tls[pos];
        pos += 1 + compressionLen;
        if (pos + 2 > tls.size()) return {};

        // 4. Parse TLS Extensions Block
        const std::size_t extensionsLen = (static_cast<std::size_t>(tls[pos]) << 8) | tls[pos + 1];
        pos += 2;

        const std::size_t extEnd = (std::min)(tls.size(), pos + extensionsLen);

        while (pos + 4 <= extEnd) {
            const std::uint16_t extType = static_cast<std::uint16_t>((tls[pos] << 8) | tls[pos + 1]);
            const std::size_t   extLen = (static_cast<std::size_t>(tls[pos + 2]) << 8) | tls[pos + 3];
            pos += 4;

            if (pos + extLen > extEnd) break;

            // Extension Type 0x0000 == Server Name Indication (SNI)
            if (extType == 0x0000 && extLen >= 5) {
                const std::uint8_t nameType = tls[pos + 2];
                const std::size_t  nameLen = (static_cast<std::size_t>(tls[pos + 3]) << 8) | tls[pos + 4];

                if (nameType == 0x00 && nameLen > 0 && nameLen <= 253 && (5 + nameLen <= extLen)) {
                    std::string domain;
                    domain.reserve(nameLen);

                    for (std::size_t i = 0; i < nameLen; ++i) {
                        const char ch = static_cast<char>(tls[pos + 5 + i]);
                        // Security Sanitization: Sirf safe DNS characters allow karo
                        if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '-') {
                            domain.push_back(ch);
                        }
                        else {
                            return {};
                        }
                    }
                    return domain;
                }
            }
            pos += extLen;
        }

        return {};
    }

    // ========================================================================
    // KERNEL RAW SOCKET SNIFFER THREAD (SIO_RCVALL)
    // ========================================================================
    void TitanShieldEngine::SnifferWorker(std::stop_token stopToken, std::string bindIpv4) noexcept {
        if (!wsaSession_.IsValid() || bindIpv4.empty() || bindIpv4 == "0.0.0.0") {
            std::scoped_lock lock(eventMutex_);
            statusMessage_ = "Waiting for valid IPv4 interface...";
            return;
        }

        ScopedSocket rawSock(::socket(AF_INET, SOCK_RAW, IPPROTO_IP));
        if (!rawSock.IsValid()) {
            std::scoped_lock lock(eventMutex_);
            statusMessage_ = "Process Shield Active (Run VS as Admin for Raw Packet SNI Sniffer)";
            return;
        }

        sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_port = 0;
        if (::inet_pton(AF_INET, bindIpv4.c_str(), &bindAddr.sin_addr) != 1) {
            std::scoped_lock lock(eventMutex_);
            statusMessage_ = "Invalid IPv4 bind address for Raw Socket";
            return;
        }

        if (::bind(rawSock.Get(), reinterpret_cast<const sockaddr*>(&bindAddr), sizeof(bindAddr)) == SOCKET_ERROR) {
            std::scoped_lock lock(eventMutex_);
            statusMessage_ = "Process Shield Active (Bind requires Admin privileges)";
            return;
        }

        // Enable Promiscuous IP-Level Packet Capture (SIO_RCVALL)
        DWORD rcvAllMode = RCVALL_IPLEVEL;
        DWORD bytesReturned = 0;
        if (::WSAIoctl(rawSock.Get(), SIO_RCVALL, &rcvAllMode, sizeof(rcvAllMode),
            nullptr, 0, &bytesReturned, nullptr, nullptr) == SOCKET_ERROR) {
            std::scoped_lock lock(eventMutex_);
            statusMessage_ = "Process Shield Active (SIO_RCVALL requires Admin)";
            return;
        }

        // 250ms Receive Timeout taaki stop_token check kabhi hang na ho
        DWORD recvTimeoutMs = 250;
        ::setsockopt(rawSock.Get(), SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&recvTimeoutMs), sizeof(recvTimeoutMs));

        rawSnifferActive_.store(true);
        {
            std::scoped_lock lock(eventMutex_);
            statusMessage_ = "ACTIVE [Kernel Raw Socket + Deep TLS SNI Inspector Online]";
        }

        std::vector<std::uint8_t> packetBuffer(65536);

        while (!stopToken.stop_requested()) {
            const int bytesRead = ::recv(
                rawSock.Get(),
                reinterpret_cast<char*>(packetBuffer.data()),
                static_cast<int>(packetBuffer.size()),
                0
            );

            if (bytesRead <= 0) {
                continue;
            }

            packetsInspected_.fetch_add(1, std::memory_order_relaxed);
            std::span<const std::uint8_t> pkt(packetBuffer.data(), static_cast<std::size_t>(bytesRead));

            // 1. Bounds Check IPv4 Header (minimum 20 bytes)
            if (pkt.size() < 20) continue;
            const std::uint8_t version = (pkt[0] >> 4) & 0x0F;
            const std::size_t  ihlBytes = static_cast<std::size_t>(pkt[0] & 0x0F) * 4;
            if (version != 4 || ihlBytes < 20 || pkt.size() < ihlBytes) continue;

            // Sirf TCP Packets (Protocol == 6) inspect karo
            if (pkt[9] != IPPROTO_TCP) continue;

            std::uint32_t srcIpNet = 0;
            std::uint32_t dstIpNet = 0;
            std::memcpy(&srcIpNet, &pkt[12], sizeof(std::uint32_t));
            std::memcpy(&dstIpNet, &pkt[16], sizeof(std::uint32_t));

            // 2. Bounds Check TCP Header (minimum 20 bytes)
            auto tcp = pkt.subspan(ihlBytes);
            if (tcp.size() < 20) continue;

            const std::uint16_t dstPort = static_cast<std::uint16_t>((tcp[2] << 8) | tcp[3]);
            const std::size_t   tcpHeaderBytes = static_cast<std::size_t>((tcp[12] >> 4) & 0x0F) * 4;
            if (tcpHeaderBytes < 20 || tcp.size() <= tcpHeaderBytes) continue;

            // 3. Inspect Payload for TLS ClientHello SNI
            auto payload = tcp.subspan(tcpHeaderBytes);
            std::string sni = ExtractTlsSniBounded(payload);

            if (!sni.empty()) {
                ShieldEvent ev{};
                ev.sourceIp = Core::NetworkCore::IpToString(srcIpNet);
                ev.destIp = Core::NetworkCore::IpToString(dstIpNet);
                ev.destPort = dstPort;
                ev.sniDomain = std::move(sni);
                ev.wasBlocked = false;

                std::scoped_lock lock(eventMutex_);
                // Duplicate consecutive SNI filter
                if (recentEvents_.empty() || recentEvents_.front().sniDomain != ev.sniDomain) {
                    recentEvents_.push_front(std::move(ev));
                    if (recentEvents_.size() > 6) {
                        recentEvents_.pop_back();
                    }
                }
            }
        }

        rawSnifferActive_.store(false);
    }

    // ========================================================================
    // KERNEL TCP CONNECTION KILLER (SetTcpEntry -> MIB_TCP_STATE_DELETE_TCB)
    // ========================================================================
    bool TitanShieldEngine::TerminateKernelTcpConnection(
        std::string_view localIp, std::uint16_t localPort,
        std::string_view remoteIp, std::uint16_t remotePort) noexcept {

        MIB_TCPROW row{};
        row.dwState = MIB_TCP_STATE_DELETE_TCB;

        std::string locStr(localIp);
        std::string remStr(remoteIp);

        if (::inet_pton(AF_INET, locStr.c_str(), &row.dwLocalAddr) != 1) return false;
        if (::inet_pton(AF_INET, remStr.c_str(), &row.dwRemoteAddr) != 1) return false;

        row.dwLocalPort = ::htons(localPort);
        row.dwRemotePort = ::htons(remotePort);

        return (::SetTcpEntry(&row) == NO_ERROR);
    }

    std::size_t TitanShieldEngine::EnforceTelemetryPolicy(const std::vector<Core::TcpFlowRecord>& activeFlows) noexcept {
        std::size_t newlyBlocked = 0;

        for (const auto& flow : activeFlows) {
            if (blockedProcesses_.contains(flow.processName)) {
                const bool killed = TerminateKernelTcpConnection(
                    flow.localAddress, flow.localPort,
                    flow.remoteAddress, flow.remotePort
                );

                connectionsBlocked_.fetch_add(1, std::memory_order_relaxed);
                ++newlyBlocked;

                ShieldEvent alert{};
                alert.sourceIp = flow.localAddress;
                alert.destIp = flow.remoteAddress;
                alert.destPort = flow.remotePort;
                alert.sniDomain = std::string("[TELEMETRY] ") + flow.processName +
                    (killed ? " (KILLED)" : " (DETECTED)");
                alert.wasBlocked = true;

                std::scoped_lock lock(eventMutex_);
                if (recentEvents_.empty() || recentEvents_.front().sniDomain != alert.sniDomain) {
                    recentEvents_.push_front(std::move(alert));
                    if (recentEvents_.size() > 6) {
                        recentEvents_.pop_back();
                    }
                }
            }
        }

        return newlyBlocked;
    }

} // namespace TitanNet::Shield