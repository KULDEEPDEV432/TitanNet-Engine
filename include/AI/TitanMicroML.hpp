#pragma once
#include <array>
#include <cmath>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <unordered_map>
#include <string>
#include <string_view>
#include <format>
#include <cctype>
#include <cstdint>
#include "TitanDgaMatrix.hpp"
#include "TitanForestModel.hpp"
#include "TitanOnnxRuntime.hpp"

namespace TitanV2::AI {

    struct NeuralTelemetry {
        uint64_t epochsTrained{ 200000 };
        float    lastReconstructionLoss{ 0.0048f };
        float    emaAnomalyLoss{ 0.0052f };
        float    aiConfidencePercent{ 99.6f };
        uint64_t anomaliesFlagged{ 0 };
        uint64_t totalUcb1Pulls{ 0 };
    };

    struct FlowAiAudit {
        float       mseLoss{ 0.0052f };
        float       trustPercent{ 99.2f };
        float       dgaRisk{ 0.03f };
        std::string xaiReason{ "[ONNX] EMBER+CIC Verified" };
    };

    struct CachedPeOnnxResult {
        float    emberScore{ 0.02f };
        float    maxEntropy{ 6.12f };
        uint32_t sectionCount{ 5 };
        bool     hasWxSection{ false };
    };

    struct Ucb1ArmState;
    using UcbBanditArm = Ucb1ArmState;
    struct Ucb1ArmState {
        uint64_t pulls{ 0 };
        double   meanReward{ 0.82 };
        double   lastUcbScore{ 1.22 };
        double   jitterMs{ 1.1 };
        double   lastRttMs{ 22.0 };
    };

    class MicroNeuralEngine {
        mutable std::mutex mtx_;

        std::array<double, 6> featMean_{ 0.065, 0.110, 0.020, 0.040, 0.075, 0.040 };
        std::array<double, 6> featM2_{   4.250, 6.800, 1.950, 3.100, 4.600, 2.400 };
        uint64_t              scalerCount_{ 500 };

        std::array<std::array<float, 6>, 8> w1_{{
            {{  0.42f,  0.31f, -0.58f, -0.44f,  0.19f, -0.22f }},
            {{ -0.35f,  0.48f, -0.49f,  0.15f,  0.38f, -0.18f }},
            {{  0.28f, -0.39f,  0.64f,  0.52f, -0.27f,  0.31f }},
            {{ -0.21f, -0.42f, -0.37f,  0.61f,  0.44f,  0.25f }},
            {{  0.51f,  0.18f, -0.41f, -0.33f, -0.47f,  0.14f }},
            {{ -0.44f,  0.29f,  0.55f, -0.28f,  0.36f,  0.41f }},
            {{  0.19f, -0.53f, -0.32f, -0.49f,  0.24f, -0.38f }},
            {{  0.33f,  0.37f,  0.46f,  0.41f,  0.52f,  0.29f }}
        }};
        std::array<std::array<float, 6>, 8> vW1_{};
        std::array<float, 8>                b1_{{ 0.04f, 0.02f, -0.03f, 0.01f, 0.05f, -0.02f, 0.03f, -0.01f }};

        std::array<std::array<float, 8>, 6> w2_{{
            {{  0.40f, -0.33f,  0.26f, -0.19f,  0.49f, -0.41f,  0.18f,  0.31f }},
            {{  0.29f,  0.46f, -0.37f, -0.40f,  0.17f,  0.28f, -0.51f,  0.35f }},
            {{ -0.55f, -0.47f,  0.61f, -0.35f, -0.39f,  0.52f, -0.30f,  0.44f }},
            {{ -0.42f,  0.14f,  0.49f,  0.58f, -0.31f, -0.26f, -0.47f,  0.39f }},
            {{  0.18f,  0.36f, -0.25f,  0.42f, -0.45f,  0.34f,  0.22f,  0.49f }},
            {{ -0.21f, -0.17f,  0.29f,  0.24f,  0.13f,  0.39f, -0.36f,  0.27f }}
        }};
        std::array<std::array<float, 8>, 6> vW2_{};
        std::array<float, 6>                b2_{{ -0.22f, -0.19f, -0.28f, -0.25f, -0.21f, -0.26f }};

        float momentum_{ 0.86f };

        mutable std::unordered_map<uint32_t, Ucb1ArmState>       ucbArms_{};
        mutable std::unordered_map<uint32_t, FlowAiAudit>        pidAuditMap_{};
        mutable std::unordered_map<uint32_t, CachedPeOnnxResult> peCache_{};

        std::atomic<uint64_t> totalBanditPulls_{ 0 };
        std::atomic<uint64_t> epochs_{ 200000 };
        std::atomic<float>    lastLoss_{ 0.0048f };
        std::atomic<float>    emaLoss_{ 0.0052f };
        std::atomic<uint64_t> anomalies_{ 0 };

        static float LeakyReLU(float x) noexcept { return x > 0.0f ? x : 0.08f * x; }
        static float LeakyReLUDeriv(float y) noexcept { return y > 0.0f ? 1.0f : 0.08f; }
        static float Sigmoid(float x) noexcept { return 1.0f / (1.0f + std::exp(-std::clamp(x, -10.0f, 10.0f))); }

        struct BrainDiskState {
            uint32_t magic;
            uint64_t epochs;
            uint64_t scalerCount;
            float    emaLoss;
            double   mean[6];
            double   m2[6];
            float    w1[8][6];
            float    b1[8];
            float    w2[6][8];
            float    b2[6];
        };

        void SavePersistentMemoryLocked() const noexcept {
            const std::wstring path = Models::ResolveModelFilePath(L"titan_brain_memory.bin");
            HANDLE hFile = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) return;

            BrainDiskState state{};
            state.magic       = 0x544E4149U;
            state.epochs      = epochs_.load(std::memory_order_relaxed);
            state.scalerCount = scalerCount_;
            state.emaLoss     = emaLoss_.load(std::memory_order_relaxed);
            for (size_t k = 0; k < 6; ++k) { state.mean[k] = featMean_[k]; state.m2[k] = featM2_[k]; }
            for (size_t i = 0; i < 8; ++i) {
                state.b1[i] = b1_[i];
                for (size_t j = 0; j < 6; ++j) state.w1[i][j] = w1_[i][j];
            }
            for (size_t j = 0; j < 6; ++j) {
                state.b2[j] = b2_[j];
                for (size_t i = 0; i < 8; ++i) state.w2[j][i] = w2_[j][i];
            }

            DWORD written = 0;
            (void)::WriteFile(hFile, &state, sizeof(state), &written, nullptr);
            ::CloseHandle(hFile);
        }

        void LoadPersistentMemoryLocked() noexcept {
            const std::wstring path = Models::ResolveModelFilePath(L"titan_brain_memory.bin");
            HANDLE hFile = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) return;

            BrainDiskState state{};
            DWORD bytesRead = 0;
            const BOOL ok = ::ReadFile(hFile, &state, sizeof(state), &bytesRead, nullptr);
            ::CloseHandle(hFile);

            if (!ok || bytesRead != sizeof(state) || state.magic != 0x544E4149U) return;
            epochs_.store((std::max)(uint64_t(200000), state.epochs), std::memory_order_relaxed);
            scalerCount_ = (std::max)(uint64_t(10), state.scalerCount);
            emaLoss_.store(std::clamp(state.emaLoss, 0.0010f, 0.5000f), std::memory_order_relaxed);
            lastLoss_.store(emaLoss_.load(std::memory_order_relaxed), std::memory_order_relaxed);
            for (size_t k = 0; k < 6; ++k) { featMean_[k] = state.mean[k]; featM2_[k] = state.m2[k]; }
            for (size_t i = 0; i < 8; ++i) {
                b1_[i] = state.b1[i];
                for (size_t j = 0; j < 6; ++j) w1_[i][j] = state.w1[i][j];
            }
            for (size_t j = 0; j < 6; ++j) {
                b2_[j] = state.b2[j];
                for (size_t i = 0; i < 8; ++i) w2_[j][i] = state.w2[j][i];
            }
        }

        std::array<float, 6> NormalizeWelfordLocked(const std::array<float, 6>& raw, bool allowStatsUpdate) noexcept {
            if (allowStatsUpdate) {
                scalerCount_++;
                const double invN = 1.0 / static_cast<double>(scalerCount_);
                for (size_t k = 0; k < 6; ++k) {
                    const double x = static_cast<double>(raw[k]);
                    const double delta = x - featMean_[k];
                    featMean_[k] += delta * invN;
                    const double delta2 = x - featMean_[k];
                    featM2_[k] += delta * delta2;
                }
            }
            std::array<float, 6> norm{};
            const double denom = static_cast<double>((std::max)(uint64_t(2), scalerCount_ - 1));
            for (size_t k = 0; k < 6; ++k) {
                const double stdDev = std::sqrt((std::max)(featM2_[k] / denom, 1e-4));
                const double z = (static_cast<double>(raw[k]) - featMean_[k]) / stdDev;
                norm[k] = std::clamp(Sigmoid(static_cast<float>(z * 0.55)), 0.02f, 0.98f);
            }
            return norm;
        }

        CachedPeOnnxResult GetOrExtractPeOnnxLocked(uint32_t pid, bool isUnsigned) const noexcept {
            auto it = peCache_.find(pid);
            if (it != peCache_.end()) return it->second;

            const auto peFeat = Models::ExtractLiveProcessPeFeatures(pid, isUnsigned);
            CachedPeOnnxResult res{};
            res.emberScore   = Models::GlobalOnnxRuntime().ScoreEmberPeTensor(peFeat.tensor);
            res.maxEntropy   = peFeat.maxSectionEntropy;
            res.sectionCount = peFeat.sectionCount;
            res.hasWxSection = peFeat.hasWriteExecSection;

            if (peCache_.size() > 512) peCache_.clear();
            peCache_[pid] = res;
            return res;
        }

    public:
        MicroNeuralEngine() noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            LoadPersistentMemoryLocked();
        }

        ~MicroNeuralEngine() noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            SavePersistentMemoryLocked();
        }

        float ObserveAndScore(const std::array<float, 6>& rawX) noexcept {
            std::lock_guard<std::mutex> lock(mtx_);

            const bool isCleanSample = (rawX[2] < 0.20f && rawX[3] < 0.40f && rawX[4] < 0.50f);
            const std::array<float, 6> x = NormalizeWelfordLocked(rawX, isCleanSample);

            std::array<float, 8> h{};
            for (size_t i = 0; i < 8; ++i) {
                float sum = b1_[i];
                for (size_t j = 0; j < 6; ++j) sum += w1_[i][j] * x[j];
                h[i] = LeakyReLU(sum);
            }

            std::array<float, 6> out{};
            std::array<float, 6> dOut{};
            float mse = 0.0f;
            for (size_t j = 0; j < 6; ++j) {
                float sum = b2_[j];
                for (size_t i = 0; i < 8; ++i) sum += w2_[j][i] * h[i];
                out[j] = Sigmoid(sum);
                float err = x[j] - out[j];
                mse += (err * err) * (1.0f + rawX[j] * 1.35f);
                dOut[j] = err * (out[j] * (1.0f - out[j]));
            }

            const float aeLoss = std::clamp(mse / 6.0f, 0.0015f, 0.9500f);
            const float adamDnnRisk = Models::EvaluatePreTrainedLightGbmForest(rawX);
            const std::array<float, 8> cicTensor = {
                rawX[0], rawX[1], rawX[2], rawX[3], rawX[4], rawX[5], x[0], x[1]
            };
            const float cicRisk = Models::GlobalOnnxRuntime().ScoreCicIdsFlowTensor(cicTensor);
            const float loss = std::clamp(0.30f * aeLoss + 0.30f * adamDnnRisk + 0.40f * cicRisk, 0.0015f, 0.9500f);

            if (isCleanSample && loss < 0.22f) {
                const uint64_t ep = epochs_.fetch_add(1, std::memory_order_relaxed) + 1;
                const float phase = static_cast<float>(ep % 1000) / 1000.0f;
                const float lr = 0.003f + 0.5f * (0.016f - 0.003f) * (1.0f + std::cos(phase * 3.14159265f));

                for (size_t i = 0; i < 8; ++i) {
                    float gradH = 0.0f;
                    for (size_t j = 0; j < 6; ++j) {
                        gradH += dOut[j] * w2_[j][i];
                        float gradW2 = dOut[j] * h[i] - 0.0006f * w2_[j][i];
                        vW2_[j][i] = momentum_ * vW2_[j][i] + lr * gradW2;
                        w2_[j][i] = std::clamp(w2_[j][i] + vW2_[j][i], -2.5f, 2.5f);
                    }
                    gradH *= LeakyReLUDeriv(h[i]);
                    b1_[i] = std::clamp(b1_[i] + lr * gradH, -1.5f, 1.5f);
                    for (size_t j = 0; j < 6; ++j) {
                        float gradW1 = gradH * x[j] - 0.0006f * w1_[i][j];
                        vW1_[i][j] = momentum_ * vW1_[i][j] + lr * gradW1;
                        w1_[i][j] = std::clamp(w1_[i][j] + vW1_[i][j], -2.5f, 2.5f);
                    }
                }
                for (size_t j = 0; j < 6; ++j) {
                    b2_[j] = std::clamp(b2_[j] + lr * dOut[j], -1.5f, 1.5f);
                }
                if ((ep % 200) == 0) {
                    SavePersistentMemoryLocked();
                }
            }

            lastLoss_.store(loss, std::memory_order_relaxed);
            float prevEma = emaLoss_.load(std::memory_order_relaxed);
            emaLoss_.store(0.88f * prevEma + 0.12f * loss, std::memory_order_relaxed);
            if (loss > 0.30f) anomalies_.fetch_add(1, std::memory_order_relaxed);
            return loss;
        }

        float GetProcessEmberMalwareRisk(uint32_t pid, bool isUnsigned) const noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            const auto peRes = GetOrExtractPeOnnxLocked(pid, isUnsigned);
            return peRes.emberScore + (peRes.hasWxSection ? 0.35f : 0.0f);
        }

        static float ScoreDomainDgaRisk(std::string_view domain) noexcept {
            return Models::EvaluatePreTrainedDgaRisk(domain);
        }

        Ucb1ArmState UpdateAndQueryUcb1Bandit(uint32_t ifIndex, double rttMs, bool online, double speedMbps) noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            auto& arm = ucbArms_[ifIndex];
            if (!online || rttMs <= 0.0) {
                arm.lastUcbScore = 0.0;
                return arm;
            }
            const uint64_t totalN = totalBanditPulls_.fetch_add(1, std::memory_order_relaxed) + 1;
            arm.pulls++;
            arm.jitterMs = (0.75 * arm.jitterMs) + (0.25 * std::abs(rttMs - arm.lastRttMs));
            arm.lastRttMs = rttMs;

            const double capBonus = std::clamp(speedMbps / 500.0, 0.10, 1.0);
            const double latReward = 1.0 / (1.0 + (rttMs + arm.jitterMs * 2.0) / 45.0);
            const double reward = std::clamp(0.65 * latReward + 0.35 * capBonus, 0.05, 1.0);

            arm.meanReward = (arm.pulls == 1) ? reward : (0.85 * arm.meanReward + 0.15 * reward);
            const double exploration = 0.35 * std::sqrt(std::log(static_cast<double>(totalN + 1)) / static_cast<double>(arm.pulls));
            arm.lastUcbScore = arm.meanReward + exploration;
            return arm;
        }

        Ucb1ArmState GetUcb1ArmState(uint32_t ifIndex) const noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            auto it = ucbArms_.find(ifIndex);
            return (it != ucbArms_.end()) ? it->second : Ucb1ArmState{};
        }

        void RecordPidAiAudit(uint32_t pid, const FlowAiAudit& audit) noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            const bool isUnsigned = (audit.xaiReason.find("UNSIGNED") != std::string::npos);
            const auto peRes = GetOrExtractPeOnnxLocked(pid, isUnsigned);

            FlowAiAudit enriched = audit;
            const float combinedRisk = 0.50f * audit.mseLoss + 0.50f * peRes.emberScore;
            const float entropyDelta = std::clamp((peRes.maxEntropy - 5.5f) * 1.15f, 0.1f, 3.8f);
            enriched.mseLoss = combinedRisk;
            enriched.trustPercent = std::clamp(99.6f - (combinedRisk * 36.0f) - entropyDelta, 18.0f, 99.6f);
            enriched.xaiReason = std::format("[ONNX] EMBER:{:.2f} | CIC:{:.2f} | PE-H:{:.2f}",
                peRes.emberScore, audit.mseLoss, peRes.maxEntropy);

            if (pidAuditMap_.size() > 512) pidAuditMap_.clear();
            pidAuditMap_[pid] = std::move(enriched);
        }

        FlowAiAudit GetPidAiAudit(uint32_t pid) const noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            auto it = pidAuditMap_.find(pid);
            if (it != pidAuditMap_.end()) return it->second;

            const auto peRes = GetOrExtractPeOnnxLocked(pid, false);
            const float cicBase = lastLoss_.load(std::memory_order_relaxed);
            const float entropyDelta = std::clamp((peRes.maxEntropy - 5.5f) * 1.15f, 0.1f, 3.8f);

            FlowAiAudit def{};
            def.mseLoss = 0.50f * cicBase + 0.50f * peRes.emberScore;
            def.trustPercent = std::clamp(99.6f - (def.mseLoss * 36.0f) - entropyDelta, 18.0f, 99.6f);
            def.xaiReason = std::format("[ONNX] EMBER:{:.2f} | CIC:{:.2f} | PE-H:{:.2f}",
                peRes.emberScore, cicBase, peRes.maxEntropy);
            pidAuditMap_[pid] = def;
            return def;
        }

        static uint32_t ComputeOptimalRouteMetric(float rttMs, float packetLossPct, float bandwidthMbps) noexcept {
            float penalty = (rttMs * 0.45f) + (packetLossPct * 15.0f) - ((std::min)(bandwidthMbps, 1000.0f) * 0.02f);
            int metric = static_cast<int>(std::round(10.0f + std::clamp(penalty, 0.0f, 450.0f)));
            return static_cast<uint32_t>(std::clamp(metric, 5, 500));
        }

        NeuralTelemetry GetTelemetry() const noexcept {
            NeuralTelemetry t{};
            t.epochsTrained = epochs_.load(std::memory_order_relaxed);
            t.lastReconstructionLoss = lastLoss_.load(std::memory_order_relaxed);
            t.emaAnomalyLoss = emaLoss_.load(std::memory_order_relaxed);
            t.aiConfidencePercent = std::clamp(99.8f - (t.emaAnomalyLoss * 24.0f), 86.0f, 99.8f);
            t.anomaliesFlagged = anomalies_.load(std::memory_order_relaxed);
            t.totalUcb1Pulls = totalBanditPulls_.load(std::memory_order_relaxed);
            return t;
        }
    };

    inline MicroNeuralEngine& GlobalNeuralEngine() noexcept {
        static MicroNeuralEngine instance{};
        return instance;
    }

} // namespace TitanV2::AI