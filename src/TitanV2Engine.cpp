#include "TitanSafety.hpp"
#include "TitanV2Engine.hpp"

#include <softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <sfc.h>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <format>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "amsi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "sfc.lib")

namespace TitanNet::V2 {

    namespace {
        constexpr DWORD kSioLoopbackFastPath = 0x98000010;
    }

    TitanV2EnterpriseEngine::TitanV2EnterpriseEngine() noexcept {
        wfpOnline_.store(InitWfpKernelBridge(), std::memory_order_relaxed);
        amsiOnline_.store(InitAmsiEngine(), std::memory_order_relaxed);
    }

    TitanV2EnterpriseEngine::~TitanV2EnterpriseEngine() noexcept {
        Stop();
        if (amsiSession_ && amsiContext_) {
            ::AmsiCloseSession(amsiContext_, amsiSession_);
            amsiSession_ = nullptr;
        }
        if (amsiContext_) {
            ::AmsiUninitialize(amsiContext_);
            amsiContext_ = nullptr;
        }
        if (wfpEngineHandle_) {
            ::FwpmEngineClose0(wfpEngineHandle_);
            wfpEngineHandle_ = nullptr;
        }
    }

    bool TitanV2EnterpriseEngine::InitWfpKernelBridge() noexcept {
        FWPM_SESSION0 session{};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        const DWORD status = ::FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &wfpEngineHandle_);
        return (status == ERROR_SUCCESS && wfpEngineHandle_ != nullptr);
    }

    bool TitanV2EnterpriseEngine::BlockIpInWfpKernel(std::string_view ipStr) noexcept {
        if (!wfpEngineHandle_ || ipStr.empty()) return false;
        if (ipStr.starts_with("127.") || ipStr.starts_with("192.168.") || ipStr.starts_with("10.") ||
            ipStr == "::1" || ipStr.starts_with("fe80:")) return false;

        std::string key(ipStr);
        if (wfpBlockedIps_.contains(key)) return true;

        wchar_t ruleName[] = L"TitanNet v2.0 Dual-Stack WFP Kernel Quarantine Filter";

        // 1. Check if IPv6 Address -> Block in FWPM_LAYER_ALE_AUTH_CONNECT_V6 & RECV_ACCEPT_V6
        if (key.find(':') != std::string::npos) {
            in6_addr addr6{};
            if (::inet_pton(AF_INET6, key.c_str(), &addr6) != 1) return false;

            FWP_BYTE_ARRAY16 byteArr16{};
            std::memcpy(byteArr16.byteArray16, &addr6, 16);

            FWPM_FILTER_CONDITION0 cond6{};
            cond6.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            cond6.matchType = FWP_MATCH_EQUAL;
            cond6.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
            cond6.conditionValue.byteArray16 = &byteArr16;

            FWPM_FILTER0 outFilter6{};
            outFilter6.displayData.name = ruleName;
            outFilter6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            outFilter6.action.type = FWP_ACTION_BLOCK;
            outFilter6.weight.type = FWP_EMPTY;
            outFilter6.numFilterConditions = 1;
            outFilter6.filterCondition = &cond6;

            UINT64 outId6 = 0;
            const DWORD stOut6 = ::FwpmFilterAdd0(wfpEngineHandle_, &outFilter6, nullptr, &outId6);

            FWPM_FILTER0 inFilter6 = outFilter6;
            inFilter6.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
            UINT64 inId6 = 0;
            (void)::FwpmFilterAdd0(wfpEngineHandle_, &inFilter6, nullptr, &inId6);

            if (stOut6 == ERROR_SUCCESS) {
                wfpBlockedIps_.insert(std::move(key));
                wfpBlockCount_.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            return false;
        }

        // 2. IPv4 Address -> Block in FWPM_LAYER_ALE_AUTH_CONNECT_V4 & RECV_ACCEPT_V4
        in_addr addr{};
        if (::inet_pton(AF_INET, key.c_str(), &addr) != 1) return false;
        const std::uint32_t hostOrderIp = ::ntohl(addr.S_un.S_addr);

        FWPM_FILTER_CONDITION0 cond{};
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = hostOrderIp;

        FWPM_FILTER0 outFilter{};
        outFilter.displayData.name = ruleName;
        outFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        outFilter.action.type = FWP_ACTION_BLOCK;
        outFilter.weight.type = FWP_EMPTY;
        outFilter.numFilterConditions = 1;
        outFilter.filterCondition = &cond;

        UINT64 outId = 0;
        const DWORD stOut = ::FwpmFilterAdd0(wfpEngineHandle_, &outFilter, nullptr, &outId);

        FWPM_FILTER0 inFilter = outFilter;
        inFilter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
        UINT64 inId = 0;
        (void)::FwpmFilterAdd0(wfpEngineHandle_, &inFilter, nullptr, &inId);

        if (stOut == ERROR_SUCCESS) {
            wfpBlockedIps_.insert(std::move(key));
            wfpBlockCount_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        return false;
    }

    std::uint64_t TitanV2EnterpriseEngine::ComputeFlowCryptoHash(const Core::TcpFlowRecord& flow) noexcept {
        std::string payload = flow.processName + "|" + flow.remoteAddress + ":" + std::to_string(flow.remotePort);
        std::span<const uint8_t> spanData(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
        std::string shaHex = TitanV2::Core::ComputeSHA256(spanData);
        if (shaHex.size() >= 16) {
            return std::stoull(shaHex.substr(0, 16), nullptr, 16);
        }
        return 0x9F4A2C108B7E6D51ULL;
    }

    void TitanV2EnterpriseEngine::PushZeroCopySlot(
        const Core::TcpFlowRecord& flow, std::uint16_t score,
        std::uint64_t hash, std::uint64_t ioBytes) noexcept {

        const std::uint64_t seq = ringCursor_.fetch_add(1, std::memory_order_relaxed);
        ZeroCopyRingSlot& slot = zeroCopyRing_[seq % kRingSize];

        slot.pid = flow.processId;
        slot.remotePort = flow.remotePort;
        slot.threatScore = score;
        slot.cryptoFlowHash = hash;
        slot.ioTransferBytes = ioBytes;

        const std::size_t pLen = (std::min)(flow.processName.size(), sizeof(slot.processName) - 1);
        std::memcpy(slot.processName, flow.processName.data(), pLen);
        slot.processName[pLen] = '\0';

        const std::size_t ipLen = (std::min)(flow.remoteAddress.size(), sizeof(slot.remoteIp) - 1);
        std::memcpy(slot.remoteIp, flow.remoteAddress.data(), ipLen);
        slot.remoteIp[ipLen] = '\0';

        slot.sequence.store(seq + 1, std::memory_order_release);
    }

    bool TitanV2EnterpriseEngine::InitAmsiEngine() noexcept {
        if (SUCCEEDED(::AmsiInitialize(L"TitanNet_v2_Enterprise_EDR", &amsiContext_))) {
            return SUCCEEDED(::AmsiOpenSession(amsiContext_, &amsiSession_));
        }
        return false;
    }

    bool TitanV2EnterpriseEngine::VerifyFileAuthenticodeSignature(const wchar_t* filePath) noexcept {
        if (!filePath || filePath[0] == L'\0') return false;

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath;

        GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        LONG status = ::WinVerifyTrust(nullptr, &actionGuid, &trustData);
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        (void)::WinVerifyTrust(nullptr, &actionGuid, &trustData);
        if (status == ERROR_SUCCESS) return true;

        if (::SfcIsFileProtected(nullptr, filePath) != FALSE) return true;

        HANDLE hFile = ::CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            HCATADMIN hCatAdmin = nullptr;
            bool catSigned = false;
            if (::CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0)) {
                DWORD hashLen = 0;
                if (::CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, nullptr, 0) && hashLen > 0) {
                    std::vector<BYTE> hashBuf(hashLen);
                    if (::CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hashBuf.data(), 0)) {
                        HCATINFO hCatInfo = ::CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashBuf.data(), hashLen, 0, nullptr);
                        if (hCatInfo != nullptr) {
                            catSigned = true;
                            ::CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                        }
                    }
                }
                ::CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
            ::CloseHandle(hFile);
            if (catSigned) return true;
        }

        std::wstring lowerPath(filePath);
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
        if (lowerPath.starts_with(L"c:\\windows\\") ||
            lowerPath.starts_with(L"c:\\program files\\windowsapps\\") ||
            lowerPath.starts_with(L"c:\\program files\\microsoft\\") ||
            lowerPath.starts_with(L"c:\\program files (x86)\\microsoft\\")) {
            return true;
        }
        return false;
    }

    std::uint64_t TitanV2EnterpriseEngine::QueryProcessKernelIoBytes(std::uint32_t pid) noexcept {
        if (pid <= 4) return 0;
        Core::ScopedHandle hProc(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProc.IsValid()) return 0;

        IO_COUNTERS io{};
        if (::GetProcessIoCounters(hProc.Get(), &io)) {
            return io.ReadTransferCount + io.WriteTransferCount;
        }
        return 0;
    }

    bool TitanV2EnterpriseEngine::VerifyProcessAuthenticodeAndAmsi(
        std::uint32_t pid,
        bool& outIsSigned,
        bool& outIsMalware) noexcept {

        outIsSigned = true;
        outIsMalware = false;
        if (pid <= 4) return true;

        ULONGLONG actualCreateTime = 0;
        if (!TitanV2::Network::DualStackTelemetry::VerifyProcessIdentity(pid, pidCreationTimeCache_[pid], &actualCreateTime)) {
            authenticodeCache_.erase(pid);
            amsiScannedPids_.erase(pid);
            pidCreationTimeCache_[pid] = actualCreateTime;
        }

        auto itSig = authenticodeCache_.find(pid);
        if (itSig != authenticodeCache_.end() && amsiScannedPids_.contains(pid)) {
            outIsSigned = itSig->second;
            return true;
        }

        Core::ScopedHandle hProc(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProc.IsValid()) {
            authenticodeCache_[pid] = true;
            amsiScannedPids_.insert(pid);
            outIsSigned = true;
            return true;
        }

        wchar_t exePath[MAX_PATH]{};
        DWORD pathLen = MAX_PATH;
        if (!::QueryFullProcessImageNameW(hProc.Get(), 0, exePath, &pathLen) || pathLen == 0) {
            return true;
        }

        if (itSig == authenticodeCache_.end()) {
            const bool isSigned = VerifyFileAuthenticodeSignature(exePath);
            if (authenticodeCache_.size() > 512) authenticodeCache_.clear();
            authenticodeCache_[pid] = isSigned;
            outIsSigned = isSigned;
        } else {
            outIsSigned = itSig->second;
        }

        if (!amsiScannedPids_.contains(pid) && amsiContext_ && amsiSession_) {
            Core::ScopedHandle hFile(::CreateFileW(
                exePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr
            ));

            bool foundMalwareOrPacked = false;
            if (hFile.IsValid()) {
                LARGE_INTEGER fileSize{};
                if (::GetFileSizeEx(hFile.Get(), &fileSize) && fileSize.QuadPart > 64) {
                    // Map up to 64 MB of the full PE image zero-copy into RAM for deep AMSI & Section Entropy inspection!
                    const DWORD mapBytes = static_cast<DWORD>((std::min)(fileSize.QuadPart, LONGLONG(64 * 1024 * 1024)));
                    HANDLE hMap = ::CreateFileMappingW(hFile.Get(), nullptr, PAGE_READONLY, 0, mapBytes, nullptr);
                    if (hMap != nullptr) {
                        const auto* basePtr = static_cast<const std::uint8_t*>(::MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, mapBytes));
                        if (basePtr != nullptr) {
                            AMSI_RESULT amsiRes = AMSI_RESULT_CLEAN;
                            const HRESULT hr = ::AmsiScanBuffer(
                                amsiContext_, const_cast<std::uint8_t*>(basePtr), mapBytes, exePath, amsiSession_, &amsiRes
                            );
                            if (SUCCEEDED(hr) && AmsiResultIsMalware(amsiRes)) {
                                foundMalwareOrPacked = true;
                            }

                            // Real PE Section Header Parser & Shannon Entropy Analyzer (Detects Packed/Encrypted Malware)
                            if (!foundMalwareOrPacked && !outIsSigned && mapBytes > sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) {
                                const auto* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(basePtr);
                                if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE && dosHdr->e_lfanew > 0 &&
                                    static_cast<DWORD>(dosHdr->e_lfanew) + sizeof(IMAGE_NT_HEADERS) <= mapBytes) {
                                    const auto* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS*>(basePtr + dosHdr->e_lfanew);
                                    if (ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                                        const auto* secHdr = IMAGE_FIRST_SECTION(ntHdr);
                                        const WORD numSecs = (std::min)(ntHdr->FileHeader.NumberOfSections, WORD(16));
                                        for (WORD s = 0; s < numSecs; ++s) {
                                            if ((secHdr[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
                                                const DWORD rawOff = secHdr[s].PointerToRawData;
                                                const DWORD rawSz  = (std::min)(secHdr[s].SizeOfRawData, DWORD(2 * 1024 * 1024));
                                                if (rawOff > 0 && rawSz >= 512 && rawOff + rawSz <= mapBytes) {
                                                    std::array<std::uint32_t, 256> hist{};
                                                    for (DWORD b = 0; b < rawSz; ++b) hist[basePtr[rawOff + b]]++;
                                                    double ent = 0.0;
                                                    const double invSz = 1.0 / static_cast<double>(rawSz);
                                                    for (std::uint32_t c : hist) {
                                                        if (c > 0) {
                                                            const double p = static_cast<double>(c) * invSz;
                                                            ent -= p * std::log2(p);
                                                        }
                                                    }
                                                    if (ent > 7.45) { // Encrypted/Packed Unsigned Executable Code Section
                                                        foundMalwareOrPacked = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            ::UnmapViewOfFile(basePtr);
                        }
                        ::CloseHandle(hMap);
                    }
                }
            }

            amsiScanCount_.fetch_add(1, std::memory_order_relaxed);
            if (amsiScannedPids_.size() > 512) amsiScannedPids_.clear();
            amsiScannedPids_.insert(pid);

            if (foundMalwareOrPacked) {
                outIsMalware = true;
                return false;
            }
        }
        return true;
    }

    bool TitanV2EnterpriseEngine::EvaluateMultivariateAnomaly(
        const Core::TcpFlowRecord& flow,
        std::size_t currentBurst,
        bool isAuthenticodeSigned,
        std::uint64_t& outIoBytes,
        std::string& outTag,
        std::uint16_t& outScore) noexcept {

        outScore = 0;
        outTag.clear();
        outIoBytes = QueryProcessKernelIoBytes(flow.processId);

        std::time_t now = std::time(nullptr);
        std::tm localTm{};
        bool isOddHour = false;
        if (::localtime_s(&localTm, &now) == 0) {
            isOddHour = (localTm.tm_hour >= 1 && localTm.tm_hour < 5);
        }
        oddHoursActive_.store(isOddHour, std::memory_order_relaxed);

        auto& st = processStats_[flow.processName];
        st.count++;
        const double x = static_cast<double>(currentBurst);
        const double delta = x - st.meanConn;
        st.meanConn += delta / static_cast<double>(st.count);
        const double delta2 = x - st.meanConn;
        st.m2Conn += delta * delta2;

        const std::uint64_t ioDelta = (outIoBytes > st.lastIoBytes && st.lastIoBytes > 0)
            ? (outIoBytes - st.lastIoBytes)
            : 0;
        st.lastIoBytes = outIoBytes;

        const bool isStandardWebPort = (flow.remotePort == 443 || flow.remotePort == 80 || flow.remotePort == 53);
        if (!isAuthenticodeSigned && !isStandardWebPort) {
            outScore += 45;
            outTag = "[UNSIGNED-NONSTD-PORT]";
        }

        double zScore = 0.0;
        if (st.count >= 6 && currentBurst > 25) {
            const double variance = st.m2Conn / static_cast<double>(st.count - 1);
            const double stdDev = std::sqrt((std::max)(variance, 1.0));
            zScore = (x - st.meanConn) / stdDev;
            if (zScore >= 3.0) {
                outScore += 60;
                outTag = "[WELFORD-Z-SPIKE]";
            }
        }

        if (!isAuthenticodeSigned && isOddHour && ioDelta > 5 * 1024 * 1024) {
            outScore += 55;
            outTag = "[UNSIGNED-NIGHT-EXFIL]";
        }

        const float f0_ioRate   = std::clamp(static_cast<float>(ioDelta) / (2.0f * 1024.0f * 1024.0f), 0.01f, 1.0f);
        const float f1_burst    = std::clamp(static_cast<float>(currentBurst) / 24.0f, 0.02f, 1.0f);
        const float f2_unsigned = isAuthenticodeSigned ? 0.02f : 0.75f;
        const float f3_portDev  = isStandardWebPort ? 0.04f : 0.80f;
        const float f4_zNorm    = std::clamp(static_cast<float>(zScore) / 4.0f, 0.01f, 1.0f);
        const float f5_oddHour  = isOddHour ? 0.45f : 0.04f;

        const std::array<float, 6> mlVec = { f0_ioRate, f1_burst, f2_unsigned, f3_portDev, f4_zNorm, f5_oddHour };
        const float mlLoss = TitanV2::AI::GlobalNeuralEngine().ObserveAndScore(mlVec);

        TitanV2::AI::FlowAiAudit audit{};
        audit.mseLoss = mlLoss;
        const float penalty = (mlLoss * 24.0f) + (f1_burst * 6.5f) + (f2_unsigned * 14.0f) + (f3_portDev * 5.0f);
        audit.trustPercent = std::clamp(99.6f - penalty, 18.0f, 99.6f);

        if (ioDelta > 16384) {
            audit.xaiReason = std::format("[XAI] {} | IO:{}KB | MSE:{:.3f}",
                isAuthenticodeSigned ? "Signed" : "Unsig", ioDelta / 1024, mlLoss);
        } else {
            audit.xaiReason = std::format("[XAI] {} | Burst:{} | MSE:{:.3f}",
                isAuthenticodeSigned ? "Signed" : "Unsig", currentBurst, mlLoss);
        }
        TitanV2::AI::GlobalNeuralEngine().RecordPidAiAudit(flow.processId, audit);

        if (mlLoss > 0.75f && !isAuthenticodeSigned) {
            outScore += 35;
            outTag += "[NEURAL-AUTOENCODER-ANOMALY]";
        }

        if (outScore >= 75) {
            threatsCount_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        return false;
    }

    void TitanV2EnterpriseEngine::ExecuteRealKernelRoutingBond(
        const std::vector<Core::AdapterRecord>& adapters,
        const std::vector<Fusion::FusionRouteNode>& routes) noexcept {

        std::uint64_t bondedCount = 0;
        std::uint32_t bestIfIndex = 0;
        double        bestUcbScore = -1.0;
        bool          fastPathOk = false;
        bool          ecmpActive = false;

        std::unordered_map<std::uint32_t, Fusion::FusionRouteNode> routeMap;
        for (const auto& r : routes) {
            routeMap[r.interfaceIndex] = r;
        }

        for (const auto& nic : adapters) {
            if (nic.ipv4Address.empty() || nic.ipv4Address == "0.0.0.0" ||
                nic.ipv4Address.starts_with("192.168.137.")) {
                continue;
            }

            Shield::ScopedSocket sock(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
            if (!sock.IsValid()) continue;

            const DWORD netIfIndex = ::htonl(nic.interfaceIndex);
            if (::setsockopt(sock.Get(), IPPROTO_IP, IP_UNICAST_IF,
                reinterpret_cast<const char*>(&netIfIndex), sizeof(netIfIndex)) == 0) {
                ++bondedCount;
            }

            int fastPathVal = 1;
            DWORD bytesRet = 0;
            if (::WSAIoctl(sock.Get(), kSioLoopbackFastPath, &fastPathVal, sizeof(fastPathVal),
                nullptr, 0, &bytesRet, nullptr, nullptr) == 0) {
                fastPathOk = true;
            }

            double latencyMs = 35.0;
            bool   gwOnline = true;
            auto itRoute = routeMap.find(nic.interfaceIndex);
            if (itRoute != routeMap.end()) {
                latencyMs = (std::max)(1.0, itRoute->second.latencyMs);
                gwOnline = itRoute->second.gatewayOnline;
            }

            const auto ucbState = TitanV2::AI::GlobalNeuralEngine().UpdateAndQueryUcb1Bandit(
                nic.interfaceIndex, latencyMs, gwOnline, static_cast<double>((std::max)(nic.rxLinkSpeedMbps, 10ULL))
            );

            if (ucbState.lastUcbScore > bestUcbScore && gwOnline) {
                bestUcbScore = ucbState.lastUcbScore;
                bestIfIndex = nic.interfaceIndex;
            }

            const std::wstring wDesc(nic.hardwareDescription.begin(), nic.hardwareDescription.end());
            if (TitanV2::Network::SmartBondController::IsVpnOrVirtualAdapter(0, wDesc)) {
                continue;
            }

            MIB_IPINTERFACE_ROW ifRow{};
            ::InitializeIpInterfaceEntry(&ifRow);
            ifRow.Family = AF_INET;
            ifRow.InterfaceIndex = nic.interfaceIndex;

            if (::GetIpInterfaceEntry(&ifRow) == NO_ERROR) {
                const ULONG aiMetric = TitanV2::AI::MicroNeuralEngine::ComputeOptimalRouteMetric(
                    static_cast<float>(latencyMs), gwOnline ? 0.0f : 100.0f, static_cast<float>(nic.rxLinkSpeedMbps)
                );
                const ULONG targetMetric = gwOnline ? aiMetric : 250UL;

                if (ifRow.Metric != targetMetric || ifRow.UseAutomaticMetric) {
                    ifRow.UseAutomaticMetric = FALSE;
                    ifRow.Metric = targetMetric;
                    ifRow.SitePrefixLength = 0;
                    (void)::SetIpInterfaceEntry(&ifRow);
                }
            }
        }

        PMIB_IPFORWARD_TABLE2 pRouteTable = nullptr;
        if (::GetIpForwardTable2(AF_INET, &pRouteTable) == NO_ERROR && pRouteTable != nullptr) {
            std::size_t activeDefaultGateways = 0;
            for (ULONG i = 0; i < pRouteTable->NumEntries; ++i) {
                MIB_IPFORWARD_ROW2& row = pRouteTable->Table[i];
                if (row.DestinationPrefix.PrefixLength == 0 &&
                    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr == 0) {
                    auto itR = routeMap.find(row.InterfaceIndex);
                    if (itR != routeMap.end()) {
                        if (itR->second.gatewayOnline) {
                            ++activeDefaultGateways;
                            if (bondedCount >= 2 && row.Metric != 10) {
                                row.Metric = 10;
                                (void)::SetIpForwardEntry2(&row);
                            }
                        } else if (row.Metric < 200) {
                            row.Metric = 250;
                            (void)::SetIpForwardEntry2(&row);
                        }
                    }
                }
            }
            ecmpActive = (activeDefaultGateways >= 2);
            ::FreeMibTable(pRouteTable);
        }

        const std::uint32_t prevPrimary = primaryNicIdx_.load(std::memory_order_relaxed);
        if (prevPrimary != 0 && bestIfIndex != 0 && prevPrimary != bestIfIndex) {
            failoverCount_.fetch_add(1, std::memory_order_relaxed);
        }
        if (bestIfIndex != 0) {
            primaryNicIdx_.store(bestIfIndex, std::memory_order_relaxed);
        }
        activeBonds_.store(bondedCount, std::memory_order_relaxed);
        ecmpRoutingActive_.store(ecmpActive, std::memory_order_relaxed);
        fastPathReady_.store(fastPathOk || bondedCount > 0, std::memory_order_relaxed);
    }

    void TitanV2EnterpriseEngine::RecordAlert(
        std::uint32_t pid, std::string_view proc, std::string_view ep,
        std::string_view tag, std::uint64_t hash, bool blocked) noexcept {

        V2ThreatFeedItem item{};
        item.pid = pid;
        item.processName = std::string(proc);
        item.endpoint = std::string(ep);
        item.moduleTag = std::string(tag);
        item.flowHash = hash;
        item.quarantined = blocked;

        std::scoped_lock lock(stateMutex_);
        if (recentAlerts_.empty() ||
            recentAlerts_.front().endpoint != item.endpoint ||
            recentAlerts_.front().moduleTag != item.moduleTag) {
            recentAlerts_.push_front(std::move(item));
            if (recentAlerts_.size() > 12) {
                recentAlerts_.pop_back();
            }
        }
    }

    void TitanV2EnterpriseEngine::SubmitTelemetryFrame(
        const std::vector<Core::AdapterRecord>& adapters,
        const std::vector<Core::TcpFlowRecord>& flows,
        const std::vector<Fusion::FusionRouteNode>& routes) noexcept {

        std::unique_lock lock(inputMutex_, std::try_to_lock);
        if (lock.owns_lock()) {
            pendingAdapters_ = adapters;
            pendingFlows_ = flows;
            pendingRoutes_ = routes;
            hasNewInput_.store(true, std::memory_order_release);
        }
    }

    void TitanV2EnterpriseEngine::Start() noexcept {
        if (isRunning_.exchange(true)) return;
        workerThread_ = std::jthread([this](std::stop_token st) { BackgroundWorker(st); });
    }

    void TitanV2EnterpriseEngine::Stop() noexcept {
        isRunning_.store(false);
        if (workerThread_.joinable()) {
            workerThread_.request_stop();
            workerThread_.join();
        }
    }

    void TitanV2EnterpriseEngine::BackgroundWorker(std::stop_token st) noexcept {
        while (!st.stop_requested() && isRunning_.load(std::memory_order_relaxed)) {
            if (!hasNewInput_.exchange(false, std::memory_order_acquire)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            std::vector<Core::AdapterRecord>     adapters;
            std::vector<Core::TcpFlowRecord>     flows;
            std::vector<Fusion::FusionRouteNode> routes;
            {
                std::scoped_lock lock(inputMutex_);
                adapters = std::move(pendingAdapters_);
                flows = std::move(pendingFlows_);
                routes = std::move(pendingRoutes_);
            }

            ExecuteRealKernelRoutingBond(adapters, routes);

            std::unordered_map<std::string, std::size_t> bursts;
            for (const auto& f : flows) {
                bursts[f.processName]++;
            }

            std::unordered_map<std::uint32_t, EdrProcessVerdict> currentVerdicts;
            std::uint64_t liveSignedPids = 0;
            std::uint64_t liveUnsignedPids = 0;

            for (const auto& f : flows) {
                const std::uint64_t cryptoHash = ComputeFlowCryptoHash(f);

                bool isSigned = true;
                bool isMalware = false;
                (void)VerifyProcessAuthenticodeAndAmsi(f.processId, isSigned, isMalware);

                std::string   aiTag;
                std::uint16_t aiScore = 0;
                std::uint64_t ioBytes = 0;
                const bool isAiAnomaly = EvaluateMultivariateAnomaly(
                    f, bursts[f.processName], isSigned, ioBytes, aiTag, aiScore
                );

                PushZeroCopySlot(f, aiScore, cryptoHash, ioBytes);

                EdrProcessVerdict verdict = isSigned
                    ? EdrProcessVerdict::SignedClean
                    : EdrProcessVerdict::UnsignedClean;

                if (isMalware || isAiAnomaly) {
                    const bool wfpBlocked = BlockIpInWfpKernel(f.remoteAddress);
                    const bool tcpKilled = Shield::TitanShieldEngine::TerminateKernelTcpConnection(
                        f.localAddress, f.localPort, f.remoteAddress, f.remotePort
                    );

                    verdict = isMalware
                        ? EdrProcessVerdict::MalwareBlocked
                        : EdrProcessVerdict::BehavioralAlert;

                    const std::string ep = std::format("{}:{}", f.remoteAddress, f.remotePort);
                    const std::string tag = isMalware ? "[AMSI-PE-MALWARE]" : aiTag;
                    RecordAlert(f.processId, f.processName, ep, tag, cryptoHash, (wfpBlocked || tcpKilled));
                }

                if (currentVerdicts.find(f.processId) == currentVerdicts.end()) {
                    if (verdict == EdrProcessVerdict::SignedClean) ++liveSignedPids;
                    else ++liveUnsignedPids;
                }
                currentVerdicts[f.processId] = verdict;
            }

            // Store exact live Signed vs Unsigned counts so top-right KPI card always matches active flows!
            signedCount_.store(liveSignedPids, std::memory_order_relaxed);
            unsignedCount_.store(liveUnsignedPids, std::memory_order_relaxed);

            {
                std::scoped_lock lock(stateMutex_);
                pidVerdictMap_ = std::move(currentVerdicts);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    V2EnterpriseReport TitanV2EnterpriseEngine::GetReport() const noexcept {
        V2EnterpriseReport rep{};
        rep.wfpActive = wfpOnline_.load(std::memory_order_relaxed);
        rep.amsiActive = amsiOnline_.load(std::memory_order_relaxed);
        rep.fastPathOffloadReady = fastPathReady_.load(std::memory_order_relaxed);
        rep.oddHoursWatchActive = oddHoursActive_.load(std::memory_order_relaxed);
        rep.ecmpKernelRoutingActive = ecmpRoutingActive_.load(std::memory_order_relaxed);
        rep.wfpBlocksTotal = wfpBlockCount_.load(std::memory_order_relaxed);
        rep.amsiPeScansTotal = amsiScanCount_.load(std::memory_order_relaxed);
        rep.authenticodeSignedCount = signedCount_.load(std::memory_order_relaxed);
        rep.authenticodeUnsignedCount = unsignedCount_.load(std::memory_order_relaxed);
        rep.behavioralThreatsCaught = threatsCount_.load(std::memory_order_relaxed);
        rep.bondedLinksCount = activeBonds_.load(std::memory_order_relaxed);
        rep.failoverSwitches = failoverCount_.load(std::memory_order_relaxed);
        rep.zeroCopyRingCount = ringCursor_.load(std::memory_order_relaxed);
        rep.primaryBondNicIndex = primaryNicIdx_.load(std::memory_order_relaxed);

        {
            std::unique_lock lock(stateMutex_, std::try_to_lock);
            if (lock.owns_lock()) {
                rep.liveAlerts.assign(recentAlerts_.begin(), recentAlerts_.end());
                rep.pidVerdicts = pidVerdictMap_;
            }
        }
        return rep;
    }

} // namespace TitanNet::V2



