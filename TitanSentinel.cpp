#include "NetworkCore.hpp"
#include "TitanSentinel.hpp"

#include <cmath>
#include <array>
#include <algorithm>
#include <cctype>

namespace TitanNet::AI {

    namespace {

        struct WindowSearchContext {
            DWORD targetPid{ 0 };
            bool  foundVisibleWindow{ false };
        };

        BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) noexcept {
            auto* ctx = reinterpret_cast<WindowSearchContext*>(lParam);
            if (ctx == nullptr) return FALSE;

            DWORD winPid = 0;
            ::GetWindowThreadProcessId(hwnd, &winPid);
            if (winPid == ctx->targetPid && ::IsWindowVisible(hwnd)) {
                ctx->foundVisibleWindow = true;
                return FALSE;
            }
            return TRUE;
        }

        std::string ToLowerAscii(std::string_view input) noexcept {
            std::string out;
            out.reserve(input.size());
            for (unsigned char ch : input) {
                out.push_back(static_cast<char>(std::tolower(ch)));
            }
            return out;
        }

    } // namespace

    TitanSentinelEngine::TitanSentinelEngine() noexcept {
        immuneProcesses_ = {
            "titannet.exe",
            "devenv.exe",
            "msedge.exe",
            "chrome.exe",
            "firefox.exe",
            "brave.exe",
            "code.exe",
            "explorer.exe",
            "[system idle]",
            "[windows kernel]"
        };
    }

    bool TitanSentinelEngine::IsImmuneSystemFlow(const Core::TcpFlowRecord& flow) const noexcept {
        if (flow.remotePort == 53 || flow.localPort == 53) return true;
        if (flow.remoteAddress.starts_with("127.") ||
            flow.remoteAddress.starts_with("192.168.") ||
            flow.remoteAddress.starts_with("10.")) {
            return true;
        }

        const std::string lowerProc = ToLowerAscii(flow.processName);
        if (immuneProcesses_.contains(lowerProc)) {
            if (lowerProc == "explorer.exe" && IsImposterSystemProcess(flow.processId, flow.processName)) {
                return false;
            }
            return true;
        }

        return false;
    }

    double TitanSentinelEngine::CalculateDomainEntropy(std::string_view domain) noexcept {
        if (domain.empty()) return 0.0;

        std::string_view host = domain;
        if (const std::size_t lastDot = host.find_last_of('.'); lastDot != std::string_view::npos && lastDot > 0) {
            host = host.substr(0, lastDot);
        }

        std::array<std::size_t, 256> freq{};
        std::size_t validCount = 0;

        for (unsigned char ch : host) {
            if (ch != '.') {
                freq[ch]++;
                validCount++;
            }
        }

        if (validCount == 0) return 0.0;

        double entropy = 0.0;
        const double invLen = 1.0 / static_cast<double>(validCount);

        for (std::size_t count : freq) {
            if (count > 0) {
                const double p = static_cast<double>(count) * invLen;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    bool TitanSentinelEngine::IsImposterSystemProcess(std::uint32_t pid, std::string_view procName) noexcept {
        const std::string lowerName = ToLowerAscii(procName);

        const bool isCoreOsBinary = (
            lowerName == "svchost.exe" ||
            lowerName == "lsass.exe" ||
            lowerName == "csrss.exe" ||
            lowerName == "services.exe" ||
            lowerName == "wininit.exe" ||
            lowerName == "explorer.exe"
            );

        if (!isCoreOsBinary) return false;

        Core::ScopedHandle hProc(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProc.IsValid()) {
            return false;
        }

        wchar_t fullPath[MAX_PATH]{};
        DWORD len = MAX_PATH;
        if (!::QueryFullProcessImageNameW(hProc.Get(), 0, fullPath, &len)) {
            return false;
        }

        std::wstring pathLower(fullPath, len);
        std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);

        if (!pathLower.starts_with(L"c:\\windows\\")) {
            return true;
        }

        return false;
    }

    bool TitanSentinelEngine::HasVisibleDesktopWindow(std::uint32_t pid) noexcept {
        if (pid <= 4) return false;
        WindowSearchContext ctx{ static_cast<DWORD>(pid), false };
        ::EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&ctx));
        return ctx.foundVisibleWindow;
    }

    bool TitanSentinelEngine::HasTelemetryBehavioralSignature(std::string_view text) noexcept {
        const std::string lower = ToLowerAscii(text);

        constexpr std::string_view kBehavioralTokens[] = {
            "telemetry", "watson", "diagtrack", "werfault", "wermgr",
            "compattel", "vctip", "ceip", "crashreport", "appinsights",
            "metrics.", "vortex.", "settings-win.data"
        };

        for (std::string_view token : kBehavioralTokens) {
            if (lower.find(token) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    void TitanSentinelEngine::EvaluateAndEnforce(
        const std::vector<Core::TcpFlowRecord>& activeFlows,
        const std::vector<Shield::ShieldEvent>& sniEvents) noexcept {

        std::scoped_lock lock(aiMutex_);
        connectionBurstCounter_.clear();

        std::unordered_map<std::string, std::string> ipToSni;
        for (const auto& ev : sniEvents) {
            if (!ev.sniDomain.empty() && !ev.wasBlocked) {
                ipToSni[ev.destIp] = ev.sniDomain;
            }
        }

        for (const auto& flow : activeFlows) {
            totalFlowsAudited_.fetch_add(1, std::memory_order_relaxed);
            connectionBurstCounter_[flow.processName]++;

            if (IsImmuneSystemFlow(flow)) {
                continue;
            }

            std::uint32_t score = 0;
            std::string   reasons;

            if (IsImposterSystemProcess(flow.processId, flow.processName)) {
                score += 90;
                reasons += "[IMPOSTER-PATH] ";
            }

            if (HasTelemetryBehavioralSignature(flow.processName)) {
                score += 55;
                reasons += "[TELEMETRY-TOKEN] ";
            }

            bool hasWin = false;
            if (auto it = windowVisibilityCache_.find(flow.processId); it != windowVisibilityCache_.end()) {
                hasWin = it->second;
            }
            else {
                hasWin = HasVisibleDesktopWindow(flow.processId);
                windowVisibilityCache_[flow.processId] = hasWin;
            }

            if (!hasWin && flow.processName != "svchost.exe") {
                score += 30;
                reasons += "[GHOST-BG] ";
            }

            if (auto sniIt = ipToSni.find(flow.remoteAddress); sniIt != ipToSni.end()) {
                const std::string& domain = sniIt->second;
                const double entropy = CalculateDomainEntropy(domain);

                if (entropy >= 3.75) {
                    score += 35;
                    reasons += "[HIGH-ENTROPY] ";
                }
                if (HasTelemetryBehavioralSignature(domain)) {
                    score += 45;
                    reasons += "[SNI-TRACKER] ";
                }
            }

            if (flow.remotePort == 8883 || flow.remotePort == 9354) {
                score += 25;
                reasons += "[MQTT-PORT] ";
            }

            if (score > 100) score = 100;

            if (score >= 50) {
                ThreatAssessment rec{};
                rec.processId = flow.processId;
                rec.processName = flow.processName;
                rec.remoteEndpoint = flow.remoteAddress + ":" + std::to_string(flow.remotePort);
                rec.threatScore = score;
                rec.reasonTag = reasons.empty() ? "[HEURISTIC]" : reasons;

                if (score >= 85) {
                    const bool killed = Shield::TitanShieldEngine::TerminateKernelTcpConnection(
                        flow.localAddress, flow.localPort,
                        flow.remoteAddress, flow.remotePort
                    );
                    rec.actionTaken = killed;
                    rec.aiVerdict = killed ? "AI KILLED" : "AI FLAGGED";
                    aiAutonomousBlocks_.fetch_add(1, std::memory_order_relaxed);
                }
                else {
                    rec.aiVerdict = "AI WATCHING";
                }

                if (recentAssessments_.empty() ||
                    recentAssessments_.front().processName != rec.processName ||
                    recentAssessments_.front().remoteEndpoint != rec.remoteEndpoint) {
                    recentAssessments_.push_front(std::move(rec));
                    if (recentAssessments_.size() > 8) {
                        recentAssessments_.pop_back();
                    }
                }
            }
        }
    }

    std::vector<ThreatAssessment> TitanSentinelEngine::GetRecentAssessments() const noexcept {
        std::scoped_lock lock(aiMutex_);
        return { recentAssessments_.begin(), recentAssessments_.end() };
    }

} // namespace TitanNet::AI