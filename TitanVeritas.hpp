#pragma once
#pragma once

#include "TitanTypes.hpp"
#include "TitanShield.hpp"
#include "TitanSentinel.hpp"
#include "TitanAutonomic.hpp"

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace TitanNet::Veritas {

    struct TruthVerificationReport {
        bool          isDataLiveAndReal{ true };
        bool          isAiDecisionValid{ true };
        bool          isAppMemorySecure{ true };
        std::uint32_t processHandleCount{ 0 };
        std::uint64_t integrityHash{ 0 };
        std::string   veritasBadge;
    };

    class TitanVeritasAuditor final {
    private:
        mutable std::mutex         veritasMutex_{};
        std::uint64_t              lastClockTick_{ 0 };
        std::uint64_t              lastVerifiedHash_{ 0 };
        std::uint32_t              baselineHandles_{ 0 };
        std::atomic<std::uint64_t> totalAuditsPassed_{ 0 };

        // 64-Bit FNV-1a Cryptographic Rolling Hash for Real-Time Data Proof
        [[nodiscard]] static std::uint64_t ComputeLiveTelemetryHash(
            std::size_t adapterCount,
            std::size_t flowCount,
            double rxSpeed,
            std::uint64_t qpcTick) noexcept;

        // Converts 64-bit hash to compact Hex string (e.g., 0x9F4A2C10)
        [[nodiscard]] static std::string ToHexHashString(std::uint64_t hashVal) noexcept;

    public:
        TitanVeritasAuditor() noexcept = default;
        ~TitanVeritasAuditor() noexcept = default;

        TitanVeritasAuditor(const TitanVeritasAuditor&) = delete;
        TitanVeritasAuditor& operator=(const TitanVeritasAuditor&) = delete;

        // Audits all 8 Phases + App Self-Security + Real-Time Kernel Ground Truth
        [[nodiscard]] TruthVerificationReport AuditEngineTruth(
            const std::vector<Core::AdapterRecord>& adapters,
            const std::vector<Core::TcpFlowRecord>& flows,
            const std::vector<AI::ThreatAssessment>& aiAssessments,
            double currentRxBytesPerSec) noexcept;

        [[nodiscard]] std::uint64_t GetTotalAuditsPassed() const noexcept {
            return totalAuditsPassed_.load(std::memory_order_relaxed);
        }
    };

} // namespace TitanNet::Veritas