// Step 1 Fix: Pure Windows GUI Subsystem (No Black CMD Window)
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

#include "TitanUI.hpp"
#include "TitanNeuralUI.hpp"

#include <chrono>
#include <thread>

int main() {
    TitanNet::UI::TitanDashboardUI          dashboard;
    TitanNet::NeuralUI::TitanNeuralPipeline neuralEngine;

    if (!dashboard.Initialize(::GetModuleHandleW(nullptr))) {
        return -1;
    }

    // Start Autonomous Background AI Pipeline (Phases 1 to 10)
    neuralEngine.Start();

    // Pure 60 FPS DirectX GPU Render Loop (Phase 4)
    while (dashboard.ProcessMessages()) {
        const auto snapshot = neuralEngine.GetLatestSnapshot();
        dashboard.RenderFrame(snapshot);
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    neuralEngine.Stop();
    return 0;
}