#pragma once
#include "TitanSafety.hpp"
#include "TitanLogger.hpp"
#include "TitanDirect2D.hpp"

namespace TitanV2::Core {
    class RuntimeLifecycle {
        inline static HHOOK hWndHook_ = nullptr;

        static LRESULT CALLBACK CallWndProcHook(int nCode, WPARAM wParam, LPARAM lParam) noexcept {
            if (nCode >= 0 && lParam != 0) {
                const CWPSTRUCT* cwp = reinterpret_cast<const CWPSTRUCT*>(lParam);
                switch (cwp->message) {
                case WM_POWERBROADCAST:
                    if (cwp->wParam == PBT_APMRESUMEAUTOMATIC || cwp->wParam == PBT_APMRESUMESUSPEND) {
                        Logger::Write("POWER", "Resumed from Sleep/Hibernate. Network & WFP handles re-validated.");
                    } else if (cwp->wParam == PBT_APMSUSPEND) {
                        Logger::Write("POWER", "Entering Sleep/Hibernate mode.");
                    }
                    break;

                case WM_DPICHANGED: {
                    uint32_t newDpi = HIWORD(cwp->wParam);
                    TitanV2::UI::EcoRenderController::UpdateDpi(newDpi);
                    const RECT* prc = reinterpret_cast<const RECT*>(cwp->lParam);
                    if (prc) {
                        ::SetWindowPos(cwp->hwnd, nullptr, prc->left, prc->top,
                            prc->right - prc->left, prc->bottom - prc->top,
                            SWP_NOZORDER | SWP_NOACTIVATE);
                    }
                    break;
                }
                }
            }
            return ::CallNextHookEx(hWndHook_, nCode, wParam, lParam);
        }

    public:
        static void InstallMainThreadHook() noexcept {
            if (!hWndHook_) {
                hWndHook_ = ::SetWindowsHookExW(WH_CALLWNDPROC, CallWndProcHook, nullptr, ::GetCurrentThreadId());
                Logger::Write("LIFECYCLE", "Installed Thread-Safe WH_CALLWNDPROC Hook for PowerBroadcast & High-DPI.");
            }
        }

        static void RemoveMainThreadHook() noexcept {
            if (hWndHook_) {
                ::UnhookWindowsHookEx(hWndHook_);
                hWndHook_ = nullptr;
            }
        }
    };
}
