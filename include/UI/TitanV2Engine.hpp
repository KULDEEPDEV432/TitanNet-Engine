#pragma once
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
#include "TitanMicroML.hpp"
#include "TitanSmartBond.hpp"
#include "TitanDualStack.hpp"
#include "TitanCrypto.hpp"

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

    enum class EdrProcessVerdict : std::uint8_t {
        PendingScan = 0,
        SignedClean = 1,
        UnsignedClean = 2,
        BehavioralAlert = 3,
        MalwareBlocked = 4
    };

    struct alignas(64) ZeroCopyRingSlot {
        std::atomic<std::uint64_t> sequence{ 0 };
        std::uint32_t              pid{ 0 };
        std::uint16_t              remotePort{ 0 };
        std::uint16_t              threatScore{ 0 };
        std::uint64_t              cryptoFlowHash{ 0 };
        std::uint64_t              ioTransferBytes{ 0 };
        char                       processName[32]{};
        char                       remoteIp[48]{};
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

        std::unordered_set<std::string>             wfpBlockedIps_{};
        std::unordered_map<std::uint32_t, bool>     authenticodeCache_{};
        std::unordered_map<std::uint32_t, ULONGLONG> pidCreationTimeCache_{};
        std::unordered_set<std::uint32_t>           amsiScannedPids_{};
        std::unordered_map<std::string, WelfordStats> processStats_{};
        TitanV2::AI::MicroNeuralEngine              microMlEngine_{};

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

        bool InitWfpKernelBridge() noexcept;
        bool BlockIpInWfpKernel(std::string_view ipStr) noexcept;

        [[nodiscard]] static std::uint64_t ComputeFlowCryptoHash(const Core::TcpFlowRecord& flow) noexcept;
        void PushZeroCopySlot(const Core::TcpFlowRecord& flow, std::uint16_t score,
            std::uint64_t hash, std::uint64_t ioBytes) noexcept;

        bool EvaluateMultivariateAnomaly(
            const Core::TcpFlowRecord& flow,
            std::size_t currentBurst,
            bool isAuthenticodeSigned,
            std::uint64_t& outIoBytes,
            std::string& outTag,
            std::uint16_t& outScore) noexcept;

        void ExecuteRealKernelRoutingBond(
            const std::vector<Core::AdapterRecord>& adapters,
            const std::vector<Fusion::FusionRouteNode>& routes) noexcept;

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
