#pragma once
#pragma once

#include "TitanTypes.hpp"
#include "TitanShield.hpp"
#include "TitanFusion.hpp"

#include <objbase.h>
#include <unknwn.h>
#include <d2d1.h>
#include <dwrite.h>
#include <wrl/client.h>

#include <vector>
#include <deque>
#include <string>
#include <string_view>

namespace TitanNet::UI {

    using Microsoft::WRL::ComPtr;

    // 60 FPS Dashboard ko har frame mein milne wala Telemetry Snapshot
    struct DashboardSnapshot {
        double                                  totalRxBytesPerSec{ 0.0 };
        double                                  totalTxBytesPerSec{ 0.0 };
        double                                  peakRxBytesPerSec{ 10240.0 };
        std::deque<double>                      rxHistory{}; // Last 60 seconds graph points
        std::deque<double>                      txHistory{};
        std::vector<Core::AdapterRecord>        adapters{};
        std::vector<Fusion::FusionRouteNode>    routes{};
        std::vector<Shield::ShieldEvent>        shieldEvents{};
        std::vector<Core::TcpFlowRecord>        tcpFlows{};
        std::uint64_t                           packetsInspected{ 0 };
        std::uint64_t                           telemetryBlocked{ 0 };
        std::uint64_t                           socketsDispatched{ 0 };
        std::size_t                             onlineGateways{ 0 };
        std::string                             shieldStatus;
    };

    class TitanDashboardUI final {
    private:
        HWND                            hwnd_{ nullptr };
        ComPtr<ID2D1Factory>            d2dFactory_{};
        ComPtr<IDWriteFactory>          dwriteFactory_{};
        ComPtr<ID2D1HwndRenderTarget>   renderTarget_{};

        // RAII GPU Color Brushes
        ComPtr<ID2D1SolidColorBrush>    bgBrush_{};
        ComPtr<ID2D1SolidColorBrush>    cardBrush_{};
        ComPtr<ID2D1SolidColorBrush>    borderBrush_{};
        ComPtr<ID2D1SolidColorBrush>    textPrimaryBrush_{};
        ComPtr<ID2D1SolidColorBrush>    textMutedBrush_{};
        ComPtr<ID2D1SolidColorBrush>    cyanBrush_{};
        ComPtr<ID2D1SolidColorBrush>    greenBrush_{};
        ComPtr<ID2D1SolidColorBrush>    amberBrush_{};
        ComPtr<ID2D1SolidColorBrush>    redBrush_{};

        // RAII GPU Typography Formats
        ComPtr<IDWriteTextFormat>       titleFont_{};
        ComPtr<IDWriteTextFormat>       headerFont_{};
        ComPtr<IDWriteTextFormat>       metricFont_{};
        ComPtr<IDWriteTextFormat>       monoFont_{};

        bool CreateDeviceResources() noexcept;
        void DiscardDeviceResources() noexcept;

        void DrawCard(D2D1_RECT_F rect, std::wstring_view title) noexcept;
        void DrawBandwidthGraph(D2D1_RECT_F rect, const DashboardSnapshot& snap) noexcept;
        void DrawTextLine(std::wstring_view text, IDWriteTextFormat* font,
            D2D1_RECT_F rect, ID2D1SolidColorBrush* brush) noexcept;

        [[nodiscard]] static std::wstring Utf8ToWide(std::string_view utf8Str) noexcept;
        [[nodiscard]] static std::wstring FormatSpeedWide(double bytesPerSec) noexcept;

        static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) noexcept;

    public:
        TitanDashboardUI() noexcept = default;
        ~TitanDashboardUI() noexcept;

        TitanDashboardUI(const TitanDashboardUI&) = delete;
        TitanDashboardUI& operator=(const TitanDashboardUI&) = delete;

        // 1280x820 Dark-Mode GPU Window initialize karta hai
        [[nodiscard]] bool Initialize(HINSTANCE hInstance) noexcept;

        // Non-blocking Win32 Event Pump (Returns false when window is closed)
        [[nodiscard]] bool ProcessMessages() noexcept;

        // 60 FPS Hardware-Accelerated Frame Render
        void RenderFrame(const DashboardSnapshot& snapshot) noexcept;
    };

} // namespace TitanNet::UI