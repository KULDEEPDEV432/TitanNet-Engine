#include "TitanBond.hpp"

#include <cmath>
#include <algorithm>

namespace TitanNet::Bond {

    void TitanBondAggregator::UpdateBondingMatrix(
        const std::vector<Core::AdapterRecord>& adapters,
        const std::vector<Fusion::FusionRouteNode>& routes,
        double currentAggregatedRxBytesPerSec,
        Fusion::TitanFusionEngine& fusion) noexcept {

        std::scoped_lock lock(bondMutex_);

        std::size_t onlineCount = 0;
        double totalPredictiveScore = 0.0;
        std::unordered_map<std::uint32_t, double> linkScores;

        for (const auto& rt : routes) {
            auto& state = linkStates_[rt.interfaceIndex];
            state.interfaceIndex = rt.interfaceIndex;
            state.ipv4Address = rt.ipv4Address;

            if (rt.gatewayOnline && rt.latencyMs > 0.1) {
                onlineCount++;

                // Calculate AI Jitter (Ping fluctuation delta)
                if (state.ewmaLatencyMs > 0.1) {
                    const double delta = std::abs(rt.latencyMs - state.ewmaLatencyMs);
                    state.jitterMs = (0.7 * state.jitterMs) + (0.3 * delta);
                    state.ewmaLatencyMs = (0.7 * state.ewmaLatencyMs) + (0.3 * rt.latencyMs);
                }
                else {
                    state.ewmaLatencyMs = rt.latencyMs;
                    state.jitterMs = 1.0;
                }

                // AI Predictive Score: Penalize high jitter before packet loss happens
                const double speedFactor = static_cast<double>((std::max)(rt.linkSpeedMbps, 10ULL));
                const double stabilityPen = state.ewmaLatencyMs + (state.jitterMs * 2.5) + 5.0;
                const double predictiveVal = speedFactor / stabilityPen;

                linkScores[rt.interfaceIndex] = predictiveVal;
                totalPredictiveScore += predictiveVal;
            }
            else {
                state.chunkRatioPercent = 0;
            }
        }

        // Distribute parallel byte-chunk striping ratios across all online NICs
        for (auto& [ifIdx, state] : linkStates_) {
            if (totalPredictiveScore > 0.0 && linkScores.contains(ifIdx)) {
                state.chunkRatioPercent = static_cast<std::uint32_t>(
                    std::round((linkScores[ifIdx] / totalPredictiveScore) * 100.0)
                    );
            }
            else {
                state.chunkRatioPercent = 0;
            }
        }

        // Dispatch parallel striped sockets across active links
        if (onlineCount >= 1) {
            const std::size_t stripesToDispatch = (std::min)(onlineCount, static_cast<std::size_t>(3));
            for (std::size_t i = 0; i < stripesToDispatch; ++i) {
                std::string boundIp;
                auto stripedSock = fusion.CreateLoadBalancedSocket(boundIp);
                if (stripedSock.IsValid()) {
                    totalStripedChunks_.fetch_add(1, std::memory_order_relaxed);
                    for (auto& [ifIdx, st] : linkStates_) {
                        if (st.ipv4Address == boundIp) {
                            st.chunksCompleted++;
                            break;
                        }
                    }
                }
            }
        }

        activeBondedLinks_.store(onlineCount, std::memory_order_relaxed);
        combinedSpeedBytesPerSec_.store(currentAggregatedRxBytesPerSec, std::memory_order_relaxed);
    }

    std::vector<BondedLinkState> TitanBondAggregator::GetBondedLinks() const noexcept {
        std::scoped_lock lock(bondMutex_);
        std::vector<BondedLinkState> out;
        out.reserve(linkStates_.size());
        for (const auto& [ifIdx, st] : linkStates_) {
            out.push_back(st);
        }
        return out;
    }

} // namespace TitanNet::Bond