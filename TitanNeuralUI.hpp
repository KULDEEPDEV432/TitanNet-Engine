#pragma once

#include "TitanUI.hpp"

#include <memory>
#include <thread>
#include <mutex>

namespace TitanNet::NeuralUI {

    class TitanNeuralPipeline final {
    private:
        struct EngineContext;
        std::unique_ptr<EngineContext> ctx_{};

        mutable std::mutex             snapshotMutex_{};
        UI::DashboardSnapshot          latestSnapshot_{};
        std::jthread                   workerThread_{};

        void TelemetryWorker(std::stop_token stopToken) noexcept;

    public:
        TitanNeuralPipeline() noexcept;
        ~TitanNeuralPipeline() noexcept;

        TitanNeuralPipeline(const TitanNeuralPipeline&) = delete;
        TitanNeuralPipeline& operator=(const TitanNeuralPipeline&) = delete;

        void Start() noexcept;
        void Stop() noexcept;

        [[nodiscard]] UI::DashboardSnapshot GetLatestSnapshot() const noexcept;
    };

} // namespace TitanNet::NeuralUI