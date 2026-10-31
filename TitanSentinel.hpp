#pragma once

#include "TitanTypes.hpp"
#include "TitanShield.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace TitanNet::AI {

    struct ThreatAssessment {
        std::uint32_t processId{ 0 };
        std::string   processName;
        std::string   remoteEndpoint;
        std::uint32_t threatScore{ 0 };
        std::string   aiVerdict;
        std::string   reasonTag;
        bool          actionTaken{ false };
    };

    class TitanSentinelEngine final {
    private:
        mutable std::mutex                        aiMutex_{};
        std::deque<ThreatAssessment>              recentAssessments_{};
        std::unordered_map<std::uint32_t, bool>   windowVisibilityCache_{};
        std::unordered_map<std::string, int>      connectionBurstCounter_{};
        std::unordered_set<std::string>           immuneProcesses_{};
        std::atomic<std::uint64_t>                totalFlowsAudited_{ 0 };
        std::atomic<std::uint64_t>                aiAutonomousBlocks_{ 0 };

        // Layer 0: Critical System & Developer Immunity Check
        [[nodiscard]] bool IsImmuneSystemFlow(const Core::TcpFlowRecord& flow) const noexcept;

        // Layer 1: Shannon Entropy Calculator for SNI Domain Randomness
        [[nodiscard]] static double CalculateDomainEntropy(std::string_view domain) noexcept;

        // Layer 2: Imposter System Process Path Verifier (Checks Windows folder)
        [[nodiscard]] static bool IsImposterSystemProcess(std::uint32_t pid, std::string_view procName) noexcept;

        // Layer 3: Ghost Process Detector (Checks if PID owns any visible window)
        [[nodiscard]] static bool HasVisibleDesktopWindow(std::uint32_t pid) noexcept;

        // Layer 4: Heuristic Telemetry Pattern Matcher
        [[nodiscard]] static bool HasTelemetryBehavioralSignature(std::string_view text) noexcept;

    public:
        TitanSentinelEngine() noexcept;
        ~TitanSentinelEngine() noexcept = default;

        TitanSentinelEngine(const TitanSentinelEngine&) = delete;
        TitanSentinelEngine& operator=(const TitanSentinelEngine&) = delete;

        void EvaluateAndEnforce(
            const std::vector<Core::TcpFlowRecord>& activeFlows,
            const std::vector<Shield::ShieldEvent>& sniEvents) noexcept;

        [[nodiscard]] std::vector<ThreatAssessment> GetRecentAssessments() const noexcept;
        [[nodiscard]] std::uint64_t GetTotalFlowsAudited() const noexcept { return totalFlowsAudited_.load(); }
        [[nodiscard]] std::uint64_t GetAiAutonomousBlocks() const noexcept { return aiAutonomousBlocks_.load(); }
    };

} // namespace TitanNet::AI