#pragma once
#include "TitanSafety.hpp"
#include "TitanLogger.hpp"
#include <d2d1.h>
#include <atomic>
#include <cstdint>

namespace TitanV2::UI {
    class EcoRenderController {
        inline static std::atomic<bool> isWindowFocused_{ true };
        inline static std::atomic<bool> isWindowMinimized_{ false };
        inline static std::atomic<uint32_t> currentDpi_{ 96 };
        inline static std::atomic<uint64_t> deviceLostRecoveries_{ 0 };

    public:
        // Fixes Bug #1 & #2: Dynamic Frame Pacing (60 FPS Active, 15 FPS Background Eco-Mode, 0 FPS Minimized)
        static DWORD GetOptimalFrameDelayMs(HWND hWnd) noexcept {
            if (hWnd) {
                isWindowMinimized_.store(::IsIconic(hWnd) != FALSE, std::memory_order_relaxed);
                isWindowFocused_.store(::GetForegroundWindow() == hWnd, std::memory_order_relaxed);
            }
            if (isWindowMinimized_.load(std::memory_order_relaxed)) return 120; // Deep Eco Sleep when minimized
            if (!isWindowFocused_.load(std::memory_order_relaxed)) return 66;   // ~15 FPS when user is gaming/unfocused
            return 16;                                                         // ~60 FPS smooth when active
        }

        // Fixes Bug #17: Direct2D GPU Reset / Resolution Change Recovery (D2DERR_RECREATE_TARGET)
        static bool NeedsTargetRecreation(HRESULT hr) noexcept {
            if (hr == D2DERR_RECREATE_TARGET) {
                deviceLostRecoveries_.fetch_add(1, std::memory_order_relaxed);
                TitanV2::Core::Logger::Write("DIRECT2D", "D2DERR_RECREATE_TARGET caught. Recreating render target safely.");
                return true;
            }
            return false;
        }

        // Fixes Bug #18: PerMonitorV2 High-DPI Coordinate Scaling Helper
        static float GetDpiScaleFactor(HWND hWnd) noexcept {
            if (hWnd) {
                UINT dpi = ::GetDpiForWindow(hWnd);
                if (dpi >= 96 && dpi <= 480) {
                    currentDpi_.store(dpi, std::memory_order_relaxed);
                }
            }
            return static_cast<float>(currentDpi_.load(std::memory_order_relaxed)) / 96.0f;
        }

        static void UpdateDpi(uint32_t newDpi) noexcept {
            if (newDpi >= 96 && newDpi <= 480) currentDpi_.store(newDpi, std::memory_order_relaxed);
        }
    };
}
