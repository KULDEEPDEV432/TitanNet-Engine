#include "NetworkCore.hpp"
#include "TitanShield.hpp"
#include "TitanFusion.hpp"
#include "TitanSentinel.hpp"
#include "TitanAutonomic.hpp"
#include "TitanBond.hpp"
#include "TitanVeritas.hpp"
#include "TitanAegis.hpp"
#include "TitanNeuralUI.hpp"

#include <chrono>
#include <unordered_map>
#include <algorithm>
#include <string>

namespace TitanNet::NeuralUI {

    struct NicByteTracker {
        std::uint64_t lastRx{ 0 };
        std::uint64_t lastTx{ 0 };
        bool          initialized{ false };
    };

    struct TitanNeuralPipeline::EngineContext {
        Shield::TitanShieldEngine           shield{};
        Fusion::TitanFusionEngine           fusion{};
        AI::TitanSentinelEngine             sentinel{};
        Autonomic::TitanAutonomicSupervisor autonomic{};
        Bond::TitanBondAggregator           bond{};
        Veritas::TitanVeritasAuditor        veritas{};
        Aegis::TitanAegisDefense            aegis{};
        std::unordered_map<std::uint32_t, NicByteTracker> nicTrackers{};
    };

    TitanNeuralPipeline::TitanNeuralPipeline() noexcept
        : ctx_(std::make_unique<EngineContext>()) {
    }

    TitanNeuralPipeline::~TitanNeuralPipeline() noexcept {
        Stop();
    }

    void TitanNeuralPipeline::Start() noexcept {
        if (!ctx_ || workerThread_.joinable()) return;

        // Activate Phase 10: 5-Layer AI Self-Defense Armor before starting threads
        ctx_->aegis.InitializeArmor();

        ctx_->fusion.Start();
        workerThread_ = std::jthread([this](std::stop_token st) {
            TelemetryWorker(st);
            });
    }

    void TitanNeuralPipeline::Stop() noexcept {
        if (workerThread_.joinable()) {
            workerThread_.request_stop();
            workerThread_.join();
        }
        if (ctx_) {
            ctx_->fusion.Stop();
            ctx_->shield.Stop();
        }
    }

    void TitanNeuralPipeline::TelemetryWorker(std::stop_token stopToken) noexcept {
        auto lastTick = std::chrono::steady_clock::now();

        while (!stopToken.stop_requested()) {
            const auto now = std::chrono::steady_clock::now();
            double elapsedSec = std::chrono::duration<double>(now - lastTick).count();
            if (elapsedSec <= 0.05) elapsedSec = 1.0;
            lastTick = now;

            // Phase 10: Audit 5-Layer Self-Defense & In-RAM Code Integrity First
            const auto aegisState = ctx_->aegis.AuditSelfDefense();

            // Phase 1 & Phase 3
            std::vector<Core::AdapterRecord> adapters = Core::NetworkCore::EnumerateActiveAdapters();
            std::vector<Core::TcpFlowRecord> flows = Core::NetworkCore::CaptureActiveTcpFlows();
            ctx_->fusion.SyncAdapters(adapters);
            std::vector<Fusion::FusionRouteNode> routes = ctx_->fusion.GetRouteTable();

            // Phase 6: Throughput Sanitization
            double combinedRx = 0.0;
            double combinedTx = 0.0;

            for (const auto& nic : adapters) {
                auto& trk = ctx_->nicTrackers[nic.interfaceIndex];
                if (trk.initialized) {
                    double rawRx = 0.0;
                    double rawTx = 0.0;
                    if (nic.rxBytesTotal >= trk.lastRx) {
                        rawRx = static_cast<double>(nic.rxBytesTotal - trk.lastRx) / elapsedSec;
                    }
                    if (nic.txBytesTotal >= trk.lastTx) {
                        rawTx = static_cast<double>(nic.txBytesTotal - trk.lastTx) / elapsedSec;
                    }
                    combinedRx += ctx_->autonomic.SanitizeThroughput(nic.interfaceIndex, rawRx);
                    combinedTx += rawTx;
                }
                trk.lastRx = nic.rxBytesTotal;
                trk.lastTx = nic.txBytesTotal;
                trk.initialized = true;
            }

            // Phase 6: Self-Healing Watchdog
            ctx_->autonomic.AuditAndHeal(adapters, routes, ctx_->shield, combinedRx);

            // Phase 2 & Phase 5: AI Threat Sentinel
            (void)ctx_->shield.EnforceTelemetryPolicy(flows);
            std::vector<Shield::ShieldEvent> sniEvents = ctx_->shield.GetRecentEvents();
            ctx_->sentinel.EvaluateAndEnforce(flows, sniEvents);
            const auto aiAssessments = ctx_->sentinel.GetRecentAssessments();

            // Phase 7: Multi-Link Speed Bonding
            ctx_->bond.UpdateBondingMatrix(adapters, routes, combinedRx, ctx_->fusion);

            // Phase 9: TitanVeritas Ground-Truth Audit
            const auto truthRep = ctx_->veritas.AuditEngineTruth(
                adapters, flows, aiAssessments, combinedRx
            );

            std::vector<Shield::ShieldEvent> enrichedFeed;

            // Row 1: Phase 10 (TitanAegis 5-Layer Self-Defense Armor Status)
            {
                Shield::ShieldEvent aegisEv{};
                aegisEv.sourceIp = "PHASE-10 AEGIS";
                aegisEv.destIp = "5-AI SHIELD";
                aegisEv.destPort = static_cast<std::uint16_t>(aegisState.activeDefenseLayers);
                aegisEv.sniDomain = aegisState.aegisStatusText;
                aegisEv.wasBlocked = !aegisState.layer3CodeRamIntact;
                enrichedFeed.push_back(std::move(aegisEv));
            }

            // Row 2: Phase 9 (TitanVeritas Ground-Truth Live Hash Proof)
            {
                Shield::ShieldEvent proofEv{};
                proofEv.sourceIp = "PHASE-9 VERITAS";
                proofEv.destIp = "AUDIT #" + std::to_string(ctx_->veritas.GetTotalAuditsPassed());
                proofEv.destPort = static_cast<std::uint16_t>(truthRep.processHandleCount);
                proofEv.sniDomain = truthRep.veritasBadge;
                proofEv.wasBlocked = !truthRep.isDataLiveAndReal;
                enrichedFeed.push_back(std::move(proofEv));
            }

            for (const auto& ai : aiAssessments) {
                if (enrichedFeed.size() >= 7) break;
                Shield::ShieldEvent ev{};
                ev.sourceIp = "PID:" + std::to_string(ai.processId) + " (" + std::to_string(ai.threatScore) + "%)";
                ev.destIp = ai.processName.substr(0, 14);
                ev.destPort = static_cast<std::uint16_t>(ai.threatScore);
                ev.sniDomain = ai.aiVerdict + " " + ai.reasonTag;
                ev.wasBlocked = (ai.threatScore >= 85);
                enrichedFeed.push_back(std::move(ev));
            }
            for (const auto& sni : sniEvents) {
                if (enrichedFeed.size() >= 7) break;
                enrichedFeed.push_back(sni);
            }

            {
                std::scoped_lock lock(snapshotMutex_);
                latestSnapshot_.adapters = std::move(adapters);
                latestSnapshot_.tcpFlows = std::move(flows);
                latestSnapshot_.routes = std::move(routes);
                latestSnapshot_.totalRxBytesPerSec = combinedRx;
                latestSnapshot_.totalTxBytesPerSec = combinedTx;
                latestSnapshot_.peakRxBytesPerSec = (std::max)(latestSnapshot_.peakRxBytesPerSec, combinedRx);

                latestSnapshot_.rxHistory.push_back(combinedRx);
                latestSnapshot_.txHistory.push_back(combinedTx);
                if (latestSnapshot_.rxHistory.size() > 60) latestSnapshot_.rxHistory.pop_front();
                if (latestSnapshot_.txHistory.size() > 60) latestSnapshot_.txHistory.pop_front();

                latestSnapshot_.onlineGateways = ctx_->fusion.GetOnlineGatewayCount();
                latestSnapshot_.socketsDispatched = ctx_->bond.GetTotalStripedChunks();
                latestSnapshot_.shieldEvents = std::move(enrichedFeed);
                latestSnapshot_.packetsInspected = ctx_->shield.GetPacketsInspected();
                latestSnapshot_.telemetryBlocked =
                    ctx_->shield.GetConnectionsBlocked() +
                    ctx_->sentinel.GetAiAutonomousBlocks() +
                    aegisState.tamperAttemptsBlocked;

                latestSnapshot_.shieldStatus =
                    "AEGIS: " + std::to_string(aegisState.activeDefenseLayers) +
                    "/5 ARMED | " + truthRep.veritasBadge;
            }

            for (int i = 0; i < 10 && !stopToken.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    UI::DashboardSnapshot TitanNeuralPipeline::GetLatestSnapshot() const noexcept {
        std::scoped_lock lock(snapshotMutex_);
        return latestSnapshot_;
    }

} // namespace TitanNet::NeuralUI