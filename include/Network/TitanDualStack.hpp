#pragma once
#include "TitanSafety.hpp"
#include <iphlpapi.h>
#include <vector>
#include <cstdint>

namespace TitanV2::Network {
    struct ProcessIdentity {
        DWORD pid = 0;
        ULONGLONG creationTime = 0;
    };

    class DualStackTelemetry {
    public:
        // Fixes Bug #19: Prevents PID Reuse Race Condition (TOCTOU) by verifying creation timestamp
        static bool VerifyProcessIdentity(DWORD pid, ULONGLONG expectedTime, ULONGLONG* outActualTime = nullptr) noexcept {
            if (pid == 0 || pid == 4) return false;
            HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!hProc) return false;

            FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
            bool ok = (::GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser) != FALSE);
            ::CloseHandle(hProc);
            if (!ok) return false;

            ULARGE_INTEGER uli{};
            uli.LowPart = ftCreate.dwLowDateTime;
            uli.HighPart = ftCreate.dwHighDateTime;
            if (outActualTime) *outActualTime = uli.QuadPart;
            return (expectedTime == 0) || (uli.QuadPart == expectedTime);
        }

        // Fixes Bug #10 & #20: Dynamic std::vector buffer + AF_INET6 Dual-Stack socket counting
        static uint32_t CountActiveIPv6Endpoints() noexcept {
            uint32_t totalV6 = 0;
            ULONG tcpSize = 0;
            if (::GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER && tcpSize > 0) {
                std::vector<uint8_t> buf(tcpSize);
                if (::GetExtendedTcpTable(buf.data(), &tcpSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    totalV6 += *reinterpret_cast<const DWORD*>(buf.data());
                }
            }
            ULONG udpSize = 0;
            if (::GetExtendedUdpTable(nullptr, &udpSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER && udpSize > 0) {
                std::vector<uint8_t> buf(udpSize);
                if (::GetExtendedUdpTable(buf.data(), &udpSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                    totalV6 += *reinterpret_cast<const DWORD*>(buf.data());
                }
            }
            return totalV6;
        }
    };
}
