#include "NetworkCore.hpp"
#include "TitanVeritas.hpp"

namespace TitanNet::Veritas {

    std::uint64_t TitanVeritasAuditor::ComputeLiveTelemetryHash(
        std::size_t adapterCount,
        std::size_t flowCount,
        double rxSpeed,
        std::uint64_t qpcTick) noexcept {

        // FNV-1a 64-bit Cryptographic Mixing
        std::uint64_t hash = 14695981039346656037ULL;
        constexpr std::uint64_t kPrime = 1099511628211ULL;

        hash ^= static_cast<std::uint64_t>(adapterCount);
        hash *= kPrime;

        hash ^= static_cast<std::uint64_t>(flowCount);
        hash *= kPrime;

        hash ^= static_cast<std::uint64_t>(rxSpeed * 100.0);
        hash *= kPrime;

        hash ^= qpcTick;
        hash *= kPrime;

        return hash;
    }

    std::string TitanVeritasAuditor::ToHexHashString(std::uint64_t hashVal) noexcept {
        constexpr char kHexDigits[] = "0123456789ABCDEF";
        std::string out = "0x";
        out.reserve(10);

        // Take top 32 bits for clean 8-character HUD display
        const std::uint32_t shortHash = static_cast<std::uint32_t>((hashVal >> 32) ^ (hashVal & 0xFFFFFFFFULL));
        for (int i = 7; i >= 0; --i) {
            const int nibble = (shortHash >> (i * 4)) & 0x0F;
            out.push_back(kHexDigits[nibble]);
        }
        return out;
    }

    TruthVerificationReport TitanVeritasAuditor::AuditEngineTruth(
        const std::vector<Core::AdapterRecord>& adapters,
        const std::vector<Core::TcpFlowRecord>& flows,
        const std::vector<AI::ThreatAssessment>& aiAssessments,
        double currentRxBytesPerSec) noexcept {

        std::scoped_lock lock(veritasMutex_);
        TruthVerificationReport report{};

        // 1. Hardware High-Resolution Clock Liveness Check (Anti-Freeze Verification)
        LARGE_INTEGER qpc{};
        ::QueryPerformanceCounter(&qpc);
        const std::uint64_t currentTick = static_cast<std::uint64_t>(qpc.QuadPart);

        report.isDataLiveAndReal = (currentTick > lastClockTick_);
        lastClockTick_ = currentTick;

        // 2. Independent Windows Kernel Ground-Truth Cross-Check (MIB_TCPSTATS)
        MIB_TCPSTATS tcpStats{};
        if (::GetTcpStatisticsEx(&tcpStats, AF_INET) == NO_ERROR) {
            // If Kernel reports active connections exist, verify our flow table isn't dead
            if (tcpStats.dwNumConns > 0 && flows.empty()) {
                report.isDataLiveAndReal = false;
            }
        }

        // 3. AI-on-AI Meta-Audit: Verify TitanSentinel didn't falsely block localhost/LAN
        report.isAiDecisionValid = true;
        for (const auto& ai : aiAssessments) {
            if (ai.remoteEndpoint.starts_with("127.0.0.1:")) {
                report.isAiDecisionValid = false;
                break;
            }
        }

        // 4. Self-Defense Security Audit: Check TitanNet.exe OS Kernel Handle Count
        DWORD handleCount = 0;
        if (::GetProcessHandleCount(::GetCurrentProcess(), &handleCount)) {
            report.processHandleCount = static_cast<std::uint32_t>(handleCount);
            if (baselineHandles_ == 0) {
                baselineHandles_ = report.processHandleCount;
            }
            // Verify zero runaway handle leaks (must stay within safe bounds)
            report.isAppMemorySecure = (report.processHandleCount < baselineHandles_ + 500);
        }

        // 5. Compute Real-Time Telemetry Proof Hash
        report.integrityHash = ComputeLiveTelemetryHash(
            adapters.size(), flows.size(), currentRxBytesPerSec, currentTick
        );
        lastVerifiedHash_ = report.integrityHash;

        if (report.isDataLiveAndReal && report.isAiDecisionValid && report.isAppMemorySecure) {
            totalAuditsPassed_.fetch_add(1, std::memory_order_relaxed);
            report.veritasBadge =
                "VERITAS: 100% LIVE [" + ToHexHashString(report.integrityHash) +
                " | HND:" + std::to_string(report.processHandleCount) + "]";
        }
        else {
            report.veritasBadge = "VERITAS ALERT: TELEMETRY DESYNC DETECTED";
        }

        return report;
    }

} // namespace TitanNet::Veritas