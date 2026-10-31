#pragma once
#pragma once

#include "TitanTypes.hpp"
#include "TitanShield.hpp"
#include "TitanFusion.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace TitanNet::Autonomic {

    struct SystemHealthReport {
        std::uint32_t healthScorePercent{ 100 };
        std::uint64_t totalAutoRepairs{ 0 };
        std::uint64_t corruptSpikesFiltered{ 0 };
        std::string   boundSnifferIp;
        std::string   lastHealAction{ "ALL SYSTEMS NOMINAL" };
    };

    class TitanAutonomicSupervisor final {
    private:
        mutable std::mutex                          healMutex_{};
        std::unordered_map<std::uint32_t, double>   ewmaRxSpeed_{};
        std::unordered_map<std::uint32_t, std::uint64_t> prevRxBytes_{};
        std::string                                 currentSnifferIp_{};
        std::string                                 lastHealAction_{ "AI WATCHDOG: 100% HEALTHY" };
        std::uint32_t                               stagnantPacketTicks_{ 0 };
        std::uint64_t                               lastPacketCount_{ 0 };
        std::atomic<std::uint64_t>                  totalAutoRepairs_{ 0 };
        std::atomic<std::uint64_t>                  corruptSpikesFiltered_{ 0 };
        std::atomic<std::uint32_t>                  healthScore_{ 100 };

        // Selects the NIC that actually carries active internet traffic & highest link score
        [[nodiscard]] std::string SelectOptimalAdapterIpLocked(
            const std::vector<Core::AdapterRecord>& adapters,
            const std::vector<Fusion::FusionRouteNode>& routes) noexcept;

    public:
        TitanAutonomicSupervisor() noexcept = default;
        ~TitanAutonomicSupervisor() noexcept = default;

        TitanAutonomicSupervisor(const TitanAutonomicSupervisor&) = delete;
        TitanAutonomicSupervisor& operator=(const TitanAutonomicSupervisor&) = delete;

        // AI Data Sanity Filter: Blocks impossible kernel counter jumps (> 2.5 GB/s spike)
        [[nodiscard]] double SanitizeThroughput(
            std::uint32_t interfaceIndex,
            double rawBytesPerSec) noexcept;

        // 24x7 Self-Healing Audit: Re-binds Sniffer on IP change or "0 Pkts" blindness
        void AuditAndHeal(
            const std::vector<Core::AdapterRecord>& adapters,
            const std::vector<Fusion::FusionRouteNode>& routes,
            Shield::TitanShieldEngine& shield,
            double currentTotalRxRate) noexcept;

        [[nodiscard]] SystemHealthReport GetHealthReport() const noexcept;
    };

} // namespace TitanNet::Autonomic