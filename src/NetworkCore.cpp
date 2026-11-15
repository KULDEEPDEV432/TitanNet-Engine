#include "TitanSafety.hpp"
#include "NetworkCore.hpp"
#include "TitanDualStack.hpp"
#include <mstcpip.h>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <mutex>
#include <thread>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifndef SIO_RCVALL
#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)
#endif

namespace TitanNet::Core {

    namespace {
        struct RealUdpPeer {
            std::uint32_t remoteIpNetOrder{ 0 };
            std::uint16_t remotePort{ 0 };
            std::chrono::steady_clock::time_point lastPacketTime;
        };

        struct TransientHoldEntry {
            TcpFlowRecord record;
            std::chrono::steady_clock::time_point lastSeen;
        };

        std::mutex g_udpSniffMutex;
        std::unordered_map<std::uint16_t, RealUdpPeer>      g_realUdpPortMap;
        std::unordered_map<std::string, TransientHoldEntry> g_transientFlowCache;
        std::once_flag                                      g_snifferInitFlag;

        bool IsPublicRoutableIpv4(std::uint32_t netIp) noexcept {
            const std::uint32_t h = ::ntohl(netIp);
            if (h == 0 || (h >> 24) == 127 || (h >> 24) == 10 || (h >> 24) >= 224) return false;
            if ((h >> 16) == 0xC0A8 || (h >> 16) == 0xA9FE) return false; // 192.168.x.x or 169.254.x.x
            if ((h >> 20) == 0xAC1) return false;                         // 172.16.0.0/12
            return true;
        }

        // 100% Real Wire-Level UDP / QUIC Packet Sniffer (Zero Guessing / Zero Fake IPs)
        void StartRealKernelUdpSnifferOnce() noexcept {
            std::call_once(g_snifferInitFlag, []() {
                std::thread([]() {
                    // Discover primary outbound local IPv4 address via kernel routing socket
                    SOCKET probe = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    if (probe == INVALID_SOCKET) return;

                    sockaddr_in googleDns{};
                    googleDns.sin_family = AF_INET;
                    googleDns.sin_port = ::htons(53);
                    ::inet_pton(AF_INET, "8.8.8.8", &googleDns.sin_addr);
                    (void)::connect(probe, reinterpret_cast<const sockaddr*>(&googleDns), sizeof(googleDns));

                    sockaddr_in localAddr{};
                    int addrLen = sizeof(localAddr);
                    if (::getsockname(probe, reinterpret_cast<sockaddr*>(&localAddr), &addrLen) != 0) {
                        ::closesocket(probe);
                        return;
                    }
                    ::closesocket(probe);

                    const std::uint32_t myLocalIp = localAddr.sin_addr.S_un.S_addr;
                    if (myLocalIp == 0) return;

                    SOCKET rawSock = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
                    if (rawSock == INVALID_SOCKET) return;

                    sockaddr_in bindAddr{};
                    bindAddr.sin_family = AF_INET;
                    bindAddr.sin_addr.S_un.S_addr = myLocalIp;
                    bindAddr.sin_port = 0;
                    if (::bind(rawSock, reinterpret_cast<const sockaddr*>(&bindAddr), sizeof(bindAddr)) != 0) {
                        ::closesocket(rawSock);
                        return;
                    }

                    DWORD mode = 1; // RCVALL_ON
                    DWORD bytesRet = 0;
                    if (::WSAIoctl(rawSock, SIO_RCVALL, &mode, sizeof(mode), nullptr, 0, &bytesRet, nullptr, nullptr) != 0) {
                        ::closesocket(rawSock);
                        return;
                    }

                    std::vector<std::uint8_t> pkt(65536);
                    while (true) {
                        const int n = ::recv(rawSock, reinterpret_cast<char*>(pkt.data()), static_cast<int>(pkt.size()), 0);
                        if (n < 28) continue;

                        const std::uint8_t ihl = static_cast<std::uint8_t>((pkt[0] & 0x0F) * 4);
                        if (ihl < 20 || n < ihl + 8) continue;

                        const std::uint8_t proto = pkt[9];
                        if (proto != 17) continue; // IPPROTO_UDP = 17

                        std::uint32_t srcIp = 0, dstIp = 0;
                        std::memcpy(&srcIp, &pkt[12], 4);
                        std::memcpy(&dstIp, &pkt[16], 4);

                        const std::uint16_t srcPort = static_cast<std::uint16_t>((pkt[ihl] << 8) | pkt[ihl + 1]);
                        const std::uint16_t dstPort = static_cast<std::uint16_t>((pkt[ihl + 2] << 8) | pkt[ihl + 3]);

                        std::uint16_t localPort = 0;
                        std::uint32_t remoteIp = 0;
                        std::uint16_t remotePort = 0;

                        if (srcIp == myLocalIp && IsPublicRoutableIpv4(dstIp)) {
                            localPort = srcPort;
                            remoteIp = dstIp;
                            remotePort = dstPort;
                        } else if (dstIp == myLocalIp && IsPublicRoutableIpv4(srcIp)) {
                            localPort = dstPort;
                            remoteIp = srcIp;
                            remotePort = srcPort;
                        }

                        if (localPort != 0 && remoteIp != 0) {
                            std::scoped_lock lk(g_udpSniffMutex);
                            if (g_realUdpPortMap.size() > 1024) g_realUdpPortMap.clear();
                            g_realUdpPortMap[localPort] = { remoteIp, remotePort, std::chrono::steady_clock::now() };
                        }
                    }
                }).detach();
            });
        }
    }

    std::string NetworkCore::WideToUtf8(std::wstring_view wideStr) noexcept {
        if (wideStr.empty()) return {};
        const int srcLen = static_cast<int>(wideStr.size());
        const int reqBytes = ::WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), srcLen, nullptr, 0, nullptr, nullptr);
        if (reqBytes <= 0) return {};
        std::string utf8Str(static_cast<std::size_t>(reqBytes), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), srcLen, utf8Str.data(), reqBytes, nullptr, nullptr);
        return utf8Str;
    }

    std::string NetworkCore::IpToString(std::uint32_t netByteOrderIp) noexcept {
        in_addr addr{};
        addr.S_un.S_addr = netByteOrderIp;
        char buffer[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr) return "0.0.0.0";
        return std::string(buffer);
    }

    std::string NetworkCore::ResolveProcessName(std::uint32_t pid) noexcept {
        if (pid == 0) return "[System Idle]";
        if (pid == 4) return "[Windows Kernel]";
        ScopedHandle procHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!procHandle.IsValid()) return "[Protected/Elevated]";
        wchar_t pathBuffer[MAX_PATH]{};
        DWORD bufferLen = MAX_PATH;
        if (!::QueryFullProcessImageNameW(procHandle.Get(), 0, pathBuffer, &bufferLen)) return "[Unknown Process]";
        std::wstring_view fullPath(pathBuffer, bufferLen);
        const std::size_t lastSlash = fullPath.find_last_of(L"\\/");
        std::wstring_view fileName = (lastSlash != std::wstring_view::npos) ? fullPath.substr(lastSlash + 1) : fullPath;
        return WideToUtf8(fileName);
    }

    std::vector<AdapterRecord> NetworkCore::EnumerateActiveAdapters() noexcept {
        std::vector<AdapterRecord> results;
        ULONG bufferSize = 16384;
        std::vector<std::uint8_t> rawBuffer;
        DWORD apiStatus = ERROR_BUFFER_OVERFLOW;

        for (int i = 0; i < 5 && apiStatus == ERROR_BUFFER_OVERFLOW; ++i) {
            rawBuffer.resize(bufferSize);
            auto* pAddr = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(rawBuffer.data());
            ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
            apiStatus = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, pAddr, &bufferSize);
        }
        if (apiStatus != NO_ERROR) return results;

        for (const auto* pCurr = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(rawBuffer.data()); pCurr != nullptr; pCurr = pCurr->Next) {
            if (pCurr->OperStatus != IfOperStatusUp || pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            std::uint64_t rxOctets = 0, txOctets = 0;
            MIB_IF_ROW2 ifRow{};
            ifRow.InterfaceIndex = pCurr->IfIndex;
            if (::GetIfEntry2(&ifRow) == NO_ERROR) {
                rxOctets = ifRow.InOctets;
                txOctets = ifRow.OutOctets;
            }
            std::string v4Addr;
            for (const auto* pUni = pCurr->FirstUnicastAddress; pUni != nullptr; pUni = pUni->Next) {
                if (pUni->Address.lpSockaddr && pUni->Address.lpSockaddr->sa_family == AF_INET && v4Addr.empty()) {
                    const auto* sa4 = reinterpret_cast<const sockaddr_in*>(pUni->Address.lpSockaddr);
                    v4Addr = IpToString(sa4->sin_addr.S_un.S_addr);
                }
            }
            if (!v4Addr.empty()) {
                AdapterRecord rec{};
                rec.interfaceIndex = pCurr->IfIndex;
                rec.friendlyName = WideToUtf8(pCurr->FriendlyName ? pCurr->FriendlyName : L"");
                rec.hardwareDescription = WideToUtf8(pCurr->Description ? pCurr->Description : L"");
                rec.ipv4Address = std::move(v4Addr);
                rec.txLinkSpeedMbps = (pCurr->TransmitLinkSpeed == MAXULONG64) ? 0 : (pCurr->TransmitLinkSpeed / 1'000'000ULL);
                rec.rxLinkSpeedMbps = (pCurr->ReceiveLinkSpeed == MAXULONG64) ? 0 : (pCurr->ReceiveLinkSpeed / 1'000'000ULL);
                rec.rxBytesTotal = rxOctets;
                rec.txBytesTotal = txOctets;
                results.push_back(std::move(rec));
            }
        }
        return results;
    }

    static bool ExtractCleanIPv6(const UCHAR ucAddr[16], std::string& outIp, bool& outIsMappedV4) noexcept {
        outIsMappedV4 = false;
        bool prefixZero = true;
        for (int i = 0; i < 10; ++i) { if (ucAddr[i] != 0) { prefixZero = false; break; } }
        if (prefixZero && ucAddr[10] == 0xFF && ucAddr[11] == 0xFF) {
            outIsMappedV4 = true;
            in_addr v4{};
            std::memcpy(&v4.S_un.S_addr, &ucAddr[12], 4);
            char buf4[INET_ADDRSTRLEN]{};
            if (::inet_ntop(AF_INET, &v4, buf4, sizeof(buf4))) {
                outIp = buf4;
                return (outIp != "127.0.0.1" && outIp != "0.0.0.0");
            }
            return false;
        }
        char buf6[INET6_ADDRSTRLEN]{};
        if (!::inet_ntop(AF_INET6, ucAddr, buf6, sizeof(buf6))) return false;
        outIp = buf6;
        return !(outIp == "::1" || outIp == "::" || outIp.starts_with("fe80:") || outIp.starts_with("ff0"));
    }

    std::vector<TcpFlowRecord> NetworkCore::CaptureActiveTcpFlows() noexcept {
        
        StartRealKernelUdpSnifferOnce();

        std::vector<TcpFlowRecord> liveFlows;
        liveFlows.reserve(180);

        // 1. Capture 100% Real Active IPv6 TCP Flows (TCPv6 & Dual-Stack TCPv6/4)
        DWORD req6Size = sizeof(MIB_TCP6TABLE_OWNER_PID);
        ::GetExtendedTcpTable(nullptr, &req6Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        std::vector<std::uint8_t> table6Buffer;
        DWORD status6 = ERROR_INSUFFICIENT_BUFFER;
        for (int i = 0; i < 5 && status6 == ERROR_INSUFFICIENT_BUFFER; ++i) {
            req6Size += 4096;
            table6Buffer.resize(req6Size);
            status6 = ::GetExtendedTcpTable(table6Buffer.data(), &req6Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        }
        if (status6 == NO_ERROR && table6Buffer.size() >= sizeof(MIB_TCP6TABLE_OWNER_PID)) {
            const auto* pTable6 = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(table6Buffer.data());
            for (DWORD i = 0; i < pTable6->dwNumEntries; ++i) {
                const MIB_TCP6ROW_OWNER_PID& row6 = pTable6->table[i];
                if (row6.dwState != MIB_TCP_STATE_ESTAB && row6.dwState != MIB_TCP_STATE_CLOSE_WAIT && row6.dwState != MIB_TCP_STATE_SYN_SENT) continue;
                std::string remIp, locIp;
                bool isMappedV4 = false, locMapped = false;
                if (!ExtractCleanIPv6(row6.ucRemoteAddr, remIp, isMappedV4)) continue;
                (void)ExtractCleanIPv6(row6.ucLocalAddr, locIp, locMapped);
                TcpFlowRecord rec{};
                rec.processId = row6.dwOwningPid;
                rec.processName = ResolveProcessName(row6.dwOwningPid);
                rec.localAddress = locIp.empty() ? "0.0.0.0" : std::move(locIp);
                rec.localPort = ::ntohs(static_cast<u_short>(row6.dwLocalPort));
                rec.remoteAddress = std::move(remIp);
                rec.remotePort = ::ntohs(static_cast<u_short>(row6.dwRemotePort));
                rec.protocolTag = isMappedV4 ? "TCPv6/4" : "TCPv6";
                liveFlows.push_back(std::move(rec));
            }
        }

        // 2. Capture 100% Real Active IPv4 TCP Flows (TCPv4)
        DWORD reqSize = sizeof(MIB_TCPTABLE_OWNER_PID);
        ::GetExtendedTcpTable(nullptr, &reqSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        std::vector<std::uint8_t> tableBuffer;
        DWORD status = ERROR_INSUFFICIENT_BUFFER;
        for (int i = 0; i < 5 && status == ERROR_INSUFFICIENT_BUFFER; ++i) {
            reqSize += 4096;
            tableBuffer.resize(reqSize);
            status = ::GetExtendedTcpTable(tableBuffer.data(), &reqSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        }
        if (status == NO_ERROR && tableBuffer.size() >= sizeof(MIB_TCPTABLE_OWNER_PID)) {
            const auto* pTable = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(tableBuffer.data());
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const MIB_TCPROW_OWNER_PID& row = pTable->table[i];
                if (row.dwState != MIB_TCP_STATE_ESTAB && row.dwState != MIB_TCP_STATE_SYN_SENT) continue;
                std::string remIp = IpToString(row.dwRemoteAddr);
                if (remIp == "127.0.0.1" || remIp == "0.0.0.0" || remIp.starts_with("169.254.")) continue;
                TcpFlowRecord rec{};
                rec.processId = row.dwOwningPid;
                rec.processName = ResolveProcessName(row.dwOwningPid);
                rec.localAddress = IpToString(row.dwLocalAddr);
                rec.localPort = ::ntohs(static_cast<u_short>(row.dwLocalPort));
                rec.remoteAddress = std::move(remIp);
                rec.remotePort = ::ntohs(static_cast<u_short>(row.dwRemotePort));
                rec.protocolTag = "TCPv4";
                liveFlows.push_back(std::move(rec));
            }
        }

        // 3. Join Kernel UDP Table (LocalPort -> PID) with Real Wire Sniffer (LocalPort -> RemoteIP:Port)
        const auto now = std::chrono::steady_clock::now();
        DWORD udpSize = 0;
        if (::GetExtendedUdpTable(nullptr, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER && udpSize > 0) {
            std::vector<std::uint8_t> udpBuf(udpSize + 2048);
            udpSize = static_cast<DWORD>(udpBuf.size());
            if (::GetExtendedUdpTable(udpBuf.data(), &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                const auto* pUdp = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(udpBuf.data());
                std::scoped_lock lk(g_udpSniffMutex);
                for (DWORD i = 0; i < pUdp->dwNumEntries; ++i) {
                    const auto& uRow = pUdp->table[i];
                    if (uRow.dwOwningPid <= 4) continue;
                    const std::uint16_t lPort = ::ntohs(static_cast<u_short>(uRow.dwLocalPort));
                    auto itReal = g_realUdpPortMap.find(lPort);
                    if (itReal != g_realUdpPortMap.end()) {
                        const auto ageMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - itReal->second.lastPacketTime).count();
                        if (ageMs <= 12000) {
                            TcpFlowRecord qRec{};
                            qRec.processId = uRow.dwOwningPid;
                            qRec.processName = ResolveProcessName(uRow.dwOwningPid);
                            qRec.localAddress = IpToString(uRow.dwLocalAddr);
                            qRec.localPort = lPort;
                            qRec.remoteAddress = IpToString(itReal->second.remoteIpNetOrder);
                            qRec.remotePort = itReal->second.remotePort;
                            qRec.protocolTag = (itReal->second.remotePort == 443) ? "QUICv4" : "UDPv4";
                            liveFlows.push_back(std::move(qRec));
                        }
                    }
                }
            }
        }

        // 4. Sub-200ms Transient Socket Trap Cache (3.5s Hold Window)
        std::scoped_lock lock(g_udpSniffMutex);
        std::unordered_set<std::string> currentKeys;
        for (const auto& f : liveFlows) {
            std::string key = std::to_string(f.processId) + "|" + f.remoteAddress + ":" + std::to_string(f.remotePort) + "|" + f.protocolTag;
            currentKeys.insert(key);
            g_transientFlowCache[key] = { f, now };
        }

        for (auto it = g_transientFlowCache.begin(); it != g_transientFlowCache.end(); ) {
            const auto ageMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.lastSeen).count();
            if (ageMs > 3500) {
                it = g_transientFlowCache.erase(it);
            } else {
                if (!currentKeys.contains(it->first) && liveFlows.size() < 180) {
                    liveFlows.push_back(it->second.record);
                }
                ++it;
            }
        }

        return liveFlows;
    }

} // namespace TitanNet::Core
