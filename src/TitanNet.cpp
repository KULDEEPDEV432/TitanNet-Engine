#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "TitanSafety.hpp"
#include "TitanLogger.hpp"
#include "TitanRuntimeGuard.hpp"
#include "TitanDirect2D.hpp"
#include "TitanProUI.hpp"
#include "TitanBrandAdmin.hpp"
#include "TitanNeuralUI.hpp"
#include "TitanV2Engine.hpp"

#include <chrono>
#include <thread>

namespace {
    LONG WINAPI TitanV2_TopLevelSEHFilter(EXCEPTION_POINTERS* pInfo) noexcept {
        DWORD code = (pInfo && pInfo->ExceptionRecord) ? pInfo->ExceptionRecord->ExceptionCode : 0;
        TitanV2::Core::Logger::Write("CRITICAL_CRASH", "Unhandled SEH Exception Code: " + std::to_string(code));
        return EXCEPTION_EXECUTE_HANDLER;
    }
}

int main() {
    ::SetUnhandledExceptionFilter(TitanV2_TopLevelSEHFilter);

    // 1. Silent Zero-UAC Administrator Elevation
    if (TitanNet::Brand::EnsureSilentAdministratorLaunch()) {
        return 0;
    }

    // 2. Single-Instance Guard: Only exit if an actual VISIBLE window exists!
    TitanV2::Core::SingleInstanceGuard uiInstanceGuard(L"Local\\TitanNet_v2_ActiveDashboard_Mutex");
    const std::wstring cmdLine = ::GetCommandLineW();
    if (uiInstanceGuard.IsAlreadyRunning() && cmdLine.find(L"--uninstall") == std::wstring::npos) {
        HWND hExisting = ::FindWindowW(L"TitanProDirectXWindowClass", nullptr);
        if (hExisting && ::IsWindow(hExisting)) {
            ::ShowWindow(hExisting, SW_RESTORE);
            ::SetForegroundWindow(hExisting);
            return 0;
        }
    }

    TitanV2::Core::Logger::Write("BOOT", "TitanNet v2.0 Enterprise Engine starting.");
    TitanV2::Core::RuntimeLifecycle::InstallMainThreadHook();

    auto dashboard    = std::make_unique<TitanNet::ProUI::TitanProDashboardUI>();
    auto neuralEngine = std::make_unique<TitanNet::NeuralUI::TitanNeuralPipeline>();
    auto v2Engine     = std::make_unique<TitanNet::V2::TitanV2EnterpriseEngine>();

    if (!dashboard->Initialize(::GetModuleHandleW(nullptr))) {
        TitanV2::Core::RuntimeLifecycle::RemoveMainThreadHook();
        return 0;
    }

    TitanNet::Brand::ApplyWindowAndTaskbarIcon();

    neuralEngine->Start();
    v2Engine->Start();

    while (dashboard->ProcessMessages()) {
        TitanNet::Brand::SyncInstallerBrandingAndAdminTask();

        auto snapshot = neuralEngine->GetLatestSnapshot();
        v2Engine->SubmitTelemetryFrame(snapshot.adapters, snapshot.tcpFlows, snapshot.routes);
        snapshot.v2 = v2Engine->GetReport();

        dashboard->RenderFrame(snapshot);

        const DWORD frameDelayMs = TitanV2::UI::EcoRenderController::GetOptimalFrameDelayMs(dashboard->GetHwnd());
        std::this_thread::sleep_for(std::chrono::milliseconds(frameDelayMs));
    }

    TitanV2::Core::RuntimeLifecycle::RemoveMainThreadHook();
    TitanV2::Core::Logger::Write("SHUTDOWN", "TitanNet v2.0 exited cleanly.");
    // Fast clean exit so background socket/WFP threads never hang the process as a zombie
    ::ExitProcess(0);
    return 0;
}
