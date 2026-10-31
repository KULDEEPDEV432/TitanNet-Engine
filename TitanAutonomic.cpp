#include "TitanAutonomic.hpp"

#include <algorithm>
#include <format>

namespace TitanNet::Autonomic {

    double TitanAutonomicSupervisor::SanitizeThroughput(
        std::uint32_t interfaceIndex,
        double rawBytesPerSec) noexcept {

        std::scoped_lock lock(healMutex_);

        // Reject negative values or impossible kernel NDIS counter wrap spikes (> 2.5 GB/s)
        constexpr double kMaxRealisticBytesPerSec = 2.5 * 1024.0 * 1024.0 * 1024.0;
        if (rawBytesPerSec < 0.0 || rawBytesPerSec > kMaxRealisticBytesPerSec) {
            corruptSpikesFiltered_.fetch_add(1, std::memory_order_relaxed);
            return ewmaRxSpeed_[interfaceIndex];
        }

        // Smooth reading via EWMA (Alpha = 0.75 for responsive yet spike-free telemetry)
        double& ewma = ewmaRxSpeed_[interfaceIndex];
        if (ewma <= 0.01) {
            ewma = rawBytesPerSec;
        }
        else {
            ewma = (0.75 * rawBytesPerSec) + (0.25 * ewma);
        }
        return ewma;
    }

    std::string TitanAutonomicSupervisor::SelectOptimalAdapterIpLocked(
        const std::vector<Core::AdapterRecord>& adapters,
        const std::vector<Fusion::FusionRouteNode>& routes) noexcept {

        if (adapters.empty()) return {};

        std::unordered_map<std::uint32_t, bool> gatewayOnlineMap;
        for (const auto& rt : routes) {
            gatewayOnlineMap[rt.interfaceIndex] = rt.gatewayOnline;
        }

        const Core::AdapterRecord* bestNic = &adapters.front();
        double bestScore = -1.0;

        for (const auto& nic : adapters) {
            if (nic.ipv4Address.empty() || nic.ipv4Address == "0.0.0.0") continue;

            double score = static_cast<double>(nic.rxLinkSpeedMbps);

            // Bonus +5000 if this NIC has a verified online internet gateway
            if (gatewayOnlineMap[nic.interfaceIndex]) {
                score += 5000.0;
            }

            // Bonus +10000 if real RX bytes moved on this NIC since last tick
            const std::uint64_t lastBytes = prevRxBytes_[nic.interfaceIndex];
            if (lastBytes > 0 && nic.rxBytesTotal > lastBytes) {
                score += 10000.0;
            }
            prevRxBytes_[nic.interfaceIndex] = nic.rxBytesTotal;

            // Deprioritize Windows ICS virtual local sharing subnet (192.168.137.1)
            if (nic.ipv4Address.starts_with("192.168.137.")) {
                score -= 4000.0;
            }

            if (score > bestScore) {
                bestScore = score;
                bestNic = &nic;
            }
        }

        return bestNic->ipv4Address;
    }

    void TitanAutonomicSupervisor::AuditAndHeal(
        const std::vector<Core::AdapterRecord>& adapters,
        const std::vector<Fusion::FusionRouteNode>& routes,
        Shield::TitanShieldEngine& shield,
        double currentTotalRxRate) noexcept {

        std::scoped_lock lock(healMutex_);

        if (adapters.empty()) {
            healthScore_.store(65, std::memory_order_relaxed);
            lastHealAction_ = "WAITING FOR ACTIVE NIC (WIFI/LAN OFFLINE)";
            return;
        }

        const std::string optimalIp = SelectOptimalAdapterIpLocked(adapters, routes);
        if (optimalIp.empty()) return;

        const std::uint64_t currentPkts = shield.GetPacketsInspected();
        if (currentPkts == lastPacketCount_ && currentTotalRxRate > 2048.0) {
            stagnantPacketTicks_++;
        }
        else {
            stagnantPacketTicks_ = 0;
        }
        lastPacketCount_ = currentPkts;

        // Condition 1: Initial Bind or Optimal Active NIC Changed (e.g., from #17 to #11 Wi-Fi)
        const bool nicChanged = (currentSnifferIp_ != optimalIp);

        // Condition 2: Sniffer is blind (0 new packets for 4 seconds while RX traffic > 2 KB/s)
        const bool snifferBlind = (stagnantPacketTicks_ >= 4);

        if (nicChanged || snifferBlind) {
            shield.Stop();
            shield.Start(optimalIp);

            const bool wasInitial = currentSnifferIp_.empty();
            currentSnifferIp_ = optimalIp;
            stagnantPacketTicks_ = 0;

            if (!wasInitial) {
                totalAutoRepairs_.fetch_add(1, std::memory_order_relaxed);
                lastHealAction_ = std::format("AUTO-HEALED SNIFFER -> REBOUND TO {}", optimalIp);
            }
            else {
                lastHealAction_ = std::format("AI BOUND OPTIMAL NIC ({})", optimalIp);
            }
        }

        healthScore_.store(100, std::memory_order_relaxed);
    }

    SystemHealthReport TitanAutonomicSupervisor::GetHealthReport() const noexcept {
        std::scoped_lock lock(healMutex_);
        SystemHealthReport rep{};
        rep.healthScorePercent = healthScore_.load(std::memory_order_relaxed);
        rep.totalAutoRepairs = totalAutoRepairs_.load(std::memory_order_relaxed);
        rep.corruptSpikesFiltered = corruptSpikesFiltered_.load(std::memory_order_relaxed);
        rep.boundSnifferIp = currentSnifferIp_;
        rep.lastHealAction = lastHealAction_;
        return rep;
    }

} // namespace TitanNet::Autonomic