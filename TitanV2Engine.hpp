#pragma once

// ============================================================================
// TitanNet v2.0 — 100% Real Native Win32 / Kernel-Bridge Enterprise Engine
// Zero Hardcoded Lists | Real WinVerifyTrust Authenticode | Real MIB Routing
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>
#include <fwpmu.h>
#include <amsi.h>
#include <mstcpip.h>

#include "TitanTypes.hpp"
#include "NetworkCore.hpp"
#include "TitanShield.hpp"
#include "TitanFusion.hpp"

#include <array>
#include <string>
#include <string_view>
#include <vector>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <thread>
#include <cstdint>

namespace TitanNet::V2 {

    // Real Per-Process Cryptographic & Behavioral Audit Verdict
    enum class EdrProcessVerdict : std::uint8_t {
        PendingScan = 0,
        SignedClean = 1, // Verified via Microsoft WinVerifyTrust + Clean AMSI PE Header
        UnsignedClean = 2, // No Authenticode signature, but clean AMSI + normal behavior
        BehavioralAlert = 3, // High Welford Z-score / High I/O Anomaly / Odd-Hours spike
        MalwareBlocked = 4  // AMSI Malware match or quarantined in WFP Kernel Firewall
    };

    struct alignas(64) ZeroCopyRingSlot {
        std::atomic<std::uint64_t> sequence{ 0 };
        std::uint32_t              pid{ 0 };
        std::uint16_t              remotePort{ 0 };
        std::uint16_t              threatScore{ 0 };
        std::uint64_t              cryptoFlowHash{ 0 };
        std::uint64_t              ioTransferBytes{ 0 };
        char                       processName[32]{};
        char                       remoteIp[20]{};
    };

    struct V2ThreatFeedItem {
        std::uint32_t pid{ 0 };
        std::string   processName;
        std::string   endpoint;
        std::string   moduleTag;
        std::uint64_t flowHash{ 0 };
        bool          quarantined{ false };
    };

    struct V2EnterpriseReport {
        bool          wfpActive{ false };
        bool          amsiActive{ false };
        bool          fastPathOffloadReady{ false };
        bool          oddHoursWatchActive{ false };
        bool          ecmpKernelRoutingActive{ false };
        std::uint64_t wfpBlocksTotal{ 0 };
        std::uint64_t amsiPeScansTotal{ 0 };
        std::uint64_t authenticodeSignedCount{ 0 };
        std::uint64_t authenticodeUnsignedCount{ 0 };
        std::uint64_t behavioralThreatsCaught{ 0 };
        std::uint64_t bondedLinksCount{ 0 };
        std::uint64_t failoverSwitches{ 0 };
        std::uint64_t zeroCopyRingCount{ 0 };
        std::uint32_t primaryBondNicIndex{ 0 };
        std::string   engineStatus;
        std::vector<V2ThreatFeedItem> liveAlerts;
        std::unordered_map<std::uint32_t, EdrProcessVerdict> pidVerdicts;
    };

    class TitanV2EnterpriseEngine final {
    private:
        static constexpr std::size_t kRingSize = 256;

        // Online Welford Statistical State (Mean, M2 Variance, Count) per Process
        struct WelfordStats {
            std::uint64_t count{ 0 };
            double        meanConn{ 0.0 };
            double        m2Conn{ 0.0 };
            std::uint64_t lastIoBytes{ 0 };
        };

        std::array<ZeroCopyRingSlot, kRingSize>     zeroCopyRing_{};
        std::atomic<std::uint64_t>                  ringCursor_{ 0 };

        HANDLE                                      wfpEngineHandle_{ nullptr };
        HAMSICONTEXT                                amsiContext_{ nullptr };
        HAMSISESSION                                amsiSession_{ nullptr };
        std::jthread                                workerThread_{};

        mutable std::mutex                          inputMutex_{};
        std::vector<Core::AdapterRecord>            pendingAdapters_{};
        std::vector<Core::TcpFlowRecord>            pendingFlows_{};
        std::vector<Fusion::FusionRouteNode>        pendingRoutes_{};
        std::atomic<bool>                           hasNewInput_{ false };

        mutable std::mutex                          stateMutex_{};
        std::deque<V2ThreatFeedItem>                recentAlerts_{};
        std::unordered_map<std::uint32_t, EdrProcessVerdict> pidVerdictMap_{};

        // Worker-thread internal caches
        std::unordered_set<std::string>             wfpBlockedIps_{};
        std::unordered_map<std::uint32_t, bool>     authenticodeCache_{};
        std::unordered_set<std::uint32_t>           amsiScannedPids_{};
        std::unordered_map<std::string, WelfordStats> processStats_{};

        // Lock-Free Atomic Counters
        std::atomic<bool>                           isRunning_{ false };
        std::atomic<bool>                           wfpOnline_{ false };
        std::atomic<bool>                           amsiOnline_{ false };
        std::atomic<bool>                           fastPathReady_{ false };
        std::atomic<bool>                           oddHoursActive_{ false };
        std::atomic<bool>                           ecmpRoutingActive_{ false };
        std::atomic<std::uint64_t>                  wfpBlockCount_{ 0 };
        std::atomic<std::uint64_t>                  amsiScanCount_{ 0 };
        std::atomic<std::uint64_t>                  signedCount_{ 0 };
        std::atomic<std::uint64_t>                  unsignedCount_{ 0 };
        std::atomic<std::uint64_t>                  threatsCount_{ 0 };
        std::atomic<std::uint64_t>                  activeBonds_{ 0 };
        std::atomic<std::uint64_t>                  failoverCount_{ 0 };
        std::atomic<std::uint32_t>                  primaryNicIdx_{ 0 };

        // Phase 11: Real Dual-Layer WFP Kernel Filter
        bool InitWfpKernelBridge() noexcept;
        bool BlockIpInWfpKernel(std::string_view ipStr) noexcept;

        // Phase 12 & 13: Cryptographic Hash & Zero-Copy Ring
        [[nodiscard]] static std::uint64_t ComputeFlowCryptoHash(const Core::TcpFlowRecord& flow) noexcept;
        void PushZeroCopySlot(const Core::TcpFlowRecord& flow, std::uint16_t score,
            std::uint64_t hash, std::uint64_t ioBytes) noexcept;

        // Phase 14: Real Multi-Feature Welford Anomaly + Kernel Process I/O + Authenticode Weighting
        bool EvaluateMultivariateAnomaly(
            const Core::TcpFlowRecord& flow,
            std::size_t currentBurst,
            bool isAuthenticodeSigned,
            std::uint64_t& outIoBytes,
            std::string& outTag,
            std::uint16_t& outScore) noexcept;

        // Phase 15: Real Kernel IPv4 Interface Metric & ECMP Route Table Controller (iphlpapi.lib)
        void ExecuteRealKernelRoutingBond(
            const std::vector<Core::AdapterRecord>& adapters,
            const std::vector<Fusion::FusionRouteNode>& routes) noexcept;

        // Phase 16: Real Microsoft WinVerifyTrust Authenticode + AMSI 4KB PE Header Scanner
        bool InitAmsiEngine() noexcept;
        bool VerifyProcessAuthenticodeAndAmsi(
            std::uint32_t pid,
            bool& outIsSigned,
            bool& outIsMalware) noexcept;

        static bool VerifyFileAuthenticodeSignature(const wchar_t* filePath) noexcept;
        static std::uint64_t QueryProcessKernelIoBytes(std::uint32_t pid) noexcept;

        void RecordAlert(std::uint32_t pid, std::string_view proc, std::string_view ep,
            std::string_view tag, std::uint64_t hash, bool blocked) noexcept;

        void BackgroundWorker(std::stop_token st) noexcept;

    public:
        TitanV2EnterpriseEngine() noexcept;
        ~TitanV2EnterpriseEngine() noexcept;

        TitanV2EnterpriseEngine(const TitanV2EnterpriseEngine&) = delete;
        TitanV2EnterpriseEngine& operator=(const TitanV2EnterpriseEngine&) = delete;

        void Start() noexcept;
        void Stop() noexcept;

        void SubmitTelemetryFrame(
            const std::vector<Core::AdapterRecord>& adapters,
            const std::vector<Core::TcpFlowRecord>& flows,
            const std::vector<Fusion::FusionRouteNode>& routes = {}) noexcept;

        [[nodiscard]] V2EnterpriseReport GetReport() const noexcept;
    };

    using TitanV2AutonomousEngine = TitanV2EnterpriseEngine;

} // namespace TitanNet::V2