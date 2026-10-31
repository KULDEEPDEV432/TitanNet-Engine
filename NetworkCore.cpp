#include "NetworkCore.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace TitanNet::Core {

    std::string NetworkCore::WideToUtf8(std::wstring_view wideStr) noexcept {
        if (wideStr.empty()) {
            return {};
        }

        const int srcLen = static_cast<int>(wideStr.size());
        const int reqBytes = ::WideCharToMultiByte(
            CP_UTF8, 0, wideStr.data(), srcLen, nullptr, 0, nullptr, nullptr
        );

        if (reqBytes <= 0) {
            return {};
        }

        std::string utf8Str(static_cast<std::size_t>(reqBytes), '\0');
        ::WideCharToMultiByte(
            CP_UTF8, 0, wideStr.data(), srcLen, utf8Str.data(), reqBytes, nullptr, nullptr
        );

        return utf8Str;
    }

    std::string NetworkCore::IpToString(std::uint32_t netByteOrderIp) noexcept {
        in_addr addr{};
        addr.S_un.S_addr = netByteOrderIp;

        char buffer[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr) {
            return "0.0.0.0";
        }
        return std::string(buffer);
    }

    std::string NetworkCore::ResolveProcessName(std::uint32_t pid) noexcept {
        if (pid == 0) return "[System Idle]";
        if (pid == 4) return "[Windows Kernel]";

        ScopedHandle procHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!procHandle.IsValid()) {
            return "[Protected/Elevated]";
        }

        wchar_t pathBuffer[MAX_PATH]{};
        DWORD bufferLen = MAX_PATH;

        if (!::QueryFullProcessImageNameW(procHandle.Get(), 0, pathBuffer, &bufferLen)) {
            return "[Unknown Process]";
        }

        std::wstring_view fullPath(pathBuffer, bufferLen);
        const std::size_t lastSlash = fullPath.find_last_of(L"\\/");
        std::wstring_view fileName = (lastSlash != std::wstring_view::npos)
            ? fullPath.substr(lastSlash + 1)
            : fullPath;

        return WideToUtf8(fileName);
    }

    std::vector<AdapterRecord> NetworkCore::EnumerateActiveAdapters() noexcept {
        std::vector<AdapterRecord> results;

        ULONG bufferSize = 16384;
        std::vector<std::uint8_t> rawBuffer;

        constexpr int kMaxRetries = 5;
        DWORD apiStatus = ERROR_BUFFER_OVERFLOW;

        for (int i = 0; i < kMaxRetries && apiStatus == ERROR_BUFFER_OVERFLOW; ++i) {
            rawBuffer.resize(bufferSize);
            auto* pAddr = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(rawBuffer.data());

            ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
            apiStatus = ::GetAdaptersAddresses(AF_INET, flags, nullptr, pAddr, &bufferSize);
        }

        if (apiStatus != NO_ERROR) {
            return results;
        }

        const auto* pCurr = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(rawBuffer.data());
        for (; pCurr != nullptr; pCurr = pCurr->Next) {
            if (pCurr->OperStatus != IfOperStatusUp || pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                continue;
            }

            // Kernel NDIS Hardware Byte Counter (GetIfEntry2)
            std::uint64_t rxOctets = 0;
            std::uint64_t txOctets = 0;
            MIB_IF_ROW2 ifRow{};
            ifRow.InterfaceIndex = pCurr->IfIndex;
            if (::GetIfEntry2(&ifRow) == NO_ERROR) {
                rxOctets = ifRow.InOctets;
                txOctets = ifRow.OutOctets;
            }

            const auto* pUni = pCurr->FirstUnicastAddress;
            for (; pUni != nullptr; pUni = pUni->Next) {
                if (pUni->Address.lpSockaddr == nullptr) {
                    continue;
                }
                if (pUni->Address.lpSockaddr->sa_family != AF_INET) {
                    continue;
                }

                const auto* sa4 = reinterpret_cast<const sockaddr_in*>(pUni->Address.lpSockaddr);

                AdapterRecord rec{};
                rec.interfaceIndex = pCurr->IfIndex;
                rec.friendlyName = WideToUtf8(pCurr->FriendlyName ? pCurr->FriendlyName : L"");
                rec.hardwareDescription = WideToUtf8(pCurr->Description ? pCurr->Description : L"");
                rec.ipv4Address = IpToString(sa4->sin_addr.S_un.S_addr);
                rec.txLinkSpeedMbps = (pCurr->TransmitLinkSpeed == MAXULONG64) ? 0 : (pCurr->TransmitLinkSpeed / 1'000'000ULL);
                rec.rxLinkSpeedMbps = (pCurr->ReceiveLinkSpeed == MAXULONG64) ? 0 : (pCurr->ReceiveLinkSpeed / 1'000'000ULL);
                rec.rxBytesTotal = rxOctets;
                rec.txBytesTotal = txOctets;

                results.push_back(std::move(rec));
            }
        }

        return results;
    }

    std::vector<TcpFlowRecord> NetworkCore::CaptureActiveTcpFlows() noexcept {
        std::vector<TcpFlowRecord> flows;

        DWORD reqSize = sizeof(MIB_TCPTABLE_OWNER_PID);
        ::GetExtendedTcpTable(nullptr, &reqSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);

        std::vector<std::uint8_t> tableBuffer;
        constexpr int kMaxRetries = 5;
        DWORD status = ERROR_INSUFFICIENT_BUFFER;

        for (int i = 0; i < kMaxRetries && status == ERROR_INSUFFICIENT_BUFFER; ++i) {
            reqSize += 4096;
            if (reqSize < sizeof(MIB_TCPTABLE)) {
                reqSize = sizeof(MIB_TCPTABLE) + 4096;
            }
            tableBuffer.resize(reqSize);

            status = ::GetExtendedTcpTable(
                tableBuffer.data(),
                &reqSize,
                TRUE,
                AF_INET,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0
            );
        }

        if (status != NO_ERROR || tableBuffer.size() < sizeof(MIB_TCPTABLE_OWNER_PID)) {
            return flows;
        }

        const auto* pTable = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(tableBuffer.data());
        flows.reserve(pTable->dwNumEntries);

        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID& row = pTable->table[i];

            if (row.dwState != MIB_TCP_STATE_ESTAB) {
                continue;
            }

            TcpFlowRecord rec{};
            rec.processId = row.dwOwningPid;
            rec.processName = ResolveProcessName(row.dwOwningPid);
            rec.localAddress = IpToString(row.dwLocalAddr);
            rec.localPort = ::ntohs(static_cast<u_short>(row.dwLocalPort));
            rec.remoteAddress = IpToString(row.dwRemoteAddr);
            rec.remotePort = ::ntohs(static_cast<u_short>(row.dwRemotePort));

            flows.push_back(std::move(rec));
        }

        return flows;
    }

} // namespace TitanNet::Core