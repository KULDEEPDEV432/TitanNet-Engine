#pragma once
#pragma once

#include "TitanTypes.hpp"
#include "TitanFusion.hpp"

#include <vector>
#include <unordered_map>
#include <string>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace TitanNet::Bond {

    struct BondedLinkState {
        std::uint32_t interfaceIndex{ 0 };
        std::string   ipv4Address;
        double        ewmaLatencyMs{ 0.0 };
        double        jitterMs{ 0.0 };          // AI Ping Stability Metric
        std::uint32_t chunkRatioPercent{ 0 };   // Parallel Chunk Striping Share %
        std::uint64_t chunksCompleted{ 0 };
    };

    class TitanBondAggregator final {
    private:
        mutable std::mutex                                  bondMutex_{};
        std::unordered_map<std::uint32_t, BondedLinkState>  linkStates_{};
        std::atomic<double>                                 combinedSpeedBytesPerSec_{ 0.0 };
        std::atomic<std::uint64_t>                          totalStripedChunks_{ 0 };
        std::atomic<std::size_t>                            activeBondedLinks_{ 0 };

    public:
        TitanBondAggregator() noexcept = default;
        ~TitanBondAggregator() noexcept = default;

        TitanBondAggregator(const TitanBondAggregator&) = delete;
        TitanBondAggregator& operator=(const TitanBondAggregator&) = delete;

        // AI Jitter Prediction & Multi-NIC Bandwidth Aggregation
        void UpdateBondingMatrix(
            const std::vector<Core::AdapterRecord>& adapters,
            const std::vector<Fusion::FusionRouteNode>& routes,
            double currentAggregatedRxBytesPerSec,
            Fusion::TitanFusionEngine& fusion) noexcept;

        [[nodiscard]] std::vector<BondedLinkState> GetBondedLinks() const noexcept;
        [[nodiscard]] double GetCombinedSpeedBytesPerSec() const noexcept { return combinedSpeedBytesPerSec_.load(); }
        [[nodiscard]] std::uint64_t GetTotalStripedChunks() const noexcept { return totalStripedChunks_.load(); }
        [[nodiscard]] std::size_t GetActiveBondedLinks() const noexcept { return activeBondedLinks_.load(); }
    };

} // namespace TitanNet::Bond