#include "TitanUI.hpp"

#include <format>
#include <algorithm>

// Automatic DirectX / Direct2D / DirectWrite GPU Linking
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

namespace TitanNet::UI {

    TitanDashboardUI::~TitanDashboardUI() noexcept {
        DiscardDeviceResources();
        if (hwnd_ != nullptr) {
            ::DestroyWindow(hwnd_);
            hwnd_ = nullptr;
        }
    }

    std::wstring TitanDashboardUI::Utf8ToWide(std::string_view utf8Str) noexcept {
        if (utf8Str.empty()) return {};
        const int srcLen = static_cast<int>(utf8Str.size());
        const int reqChars = ::MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), srcLen, nullptr, 0);
        if (reqChars <= 0) return {};

        std::wstring wide(static_cast<std::size_t>(reqChars), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), srcLen, wide.data(), reqChars);
        return wide;
    }

    std::wstring TitanDashboardUI::FormatSpeedWide(double bytesPerSec) noexcept {
        if (bytesPerSec >= 1024.0 * 1024.0) {
            return std::format(L"{:.2f} MB/s", bytesPerSec / (1024.0 * 1024.0));
        }
        return std::format(L"{:.1f} KB/s", bytesPerSec / 1024.0);
    }

    LRESULT CALLBACK TitanDashboardUI::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) noexcept {
        if (uMsg == WM_DESTROY) {
            ::PostQuitMessage(0);
            return 0;
        }
        return ::DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }

    bool TitanDashboardUI::Initialize(HINSTANCE hInstance) noexcept {
        HRESULT hr = ::D2D1CreateFactory(
            D2D1_FACTORY_TYPE_SINGLE_THREADED,
            d2dFactory_.ReleaseAndGetAddressOf()
        );
        if (FAILED(hr)) return false;

        hr = ::DWriteCreateFactory(
            DWRITE_FACTORY_TYPE_SHARED,
            __uuidof(IDWriteFactory),
            reinterpret_cast<IUnknown**>(dwriteFactory_.ReleaseAndGetAddressOf())
        );
        if (FAILED(hr)) return false;

        // Create GPU Typography Fonts
        dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD,
            DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 18.0f, L"en-us",
            titleFont_.ReleaseAndGetAddressOf());

        dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD,
            DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 12.5f, L"en-us",
            headerFont_.ReleaseAndGetAddressOf());

        dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD,
            DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 22.0f, L"en-us",
            metricFont_.ReleaseAndGetAddressOf());

        dwriteFactory_->CreateTextFormat(L"Consolas", nullptr, DWRITE_FONT_WEIGHT_NORMAL,
            DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 12.5f, L"en-us",
            monoFont_.ReleaseAndGetAddressOf());

        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
        wc.lpszClassName = L"TitanNetGpuDashboardClass";

        ::RegisterClassExW(&wc);

        hwnd_ = ::CreateWindowExW(
            0,
            wc.lpszClassName,
            L"TitanNet Engine v4.0 — 60 FPS DirectX GPU Command Center [Radar + Shield + Fusion]",
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 1280, 820,
            nullptr, nullptr, hInstance, nullptr
        );

        return (hwnd_ != nullptr);
    }

    bool TitanDashboardUI::CreateDeviceResources() noexcept {
        if (renderTarget_ != nullptr) return true;
        if (hwnd_ == nullptr) return false;

        RECT rc{};
        ::GetClientRect(hwnd_, &rc);
        D2D1_SIZE_U size = D2D1::SizeU(
            static_cast<UINT32>(rc.right - rc.left),
            static_cast<UINT32>(rc.bottom - rc.top)
        );

        HRESULT hr = d2dFactory_->CreateHwndRenderTarget(
            D2D1::RenderTargetProperties(),
            D2D1::HwndRenderTargetProperties(hwnd_, size),
            renderTarget_.ReleaseAndGetAddressOf()
        );
        if (FAILED(hr)) return false;

        // Cyber-Dark Gamer Theme Palette
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0x090D16), bgBrush_.ReleaseAndGetAddressOf());
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0x111827), cardBrush_.ReleaseAndGetAddressOf());
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0x1F2937), borderBrush_.ReleaseAndGetAddressOf());
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0xF9FAFB), textPrimaryBrush_.ReleaseAndGetAddressOf());
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0x9CA3AF), textMutedBrush_.ReleaseAndGetAddressOf());
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0x00F0FF), cyanBrush_.ReleaseAndGetAddressOf());
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0x10B981), greenBrush_.ReleaseAndGetAddressOf());
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0xF59E0B), amberBrush_.ReleaseAndGetAddressOf());
        renderTarget_->CreateSolidColorBrush(D2D1::ColorF(0xEF4444), redBrush_.ReleaseAndGetAddressOf());

        return true;
    }

    void TitanDashboardUI::DiscardDeviceResources() noexcept {
        bgBrush_.Reset();
        cardBrush_.Reset();
        borderBrush_.Reset();
        textPrimaryBrush_.Reset();
        textMutedBrush_.Reset();
        cyanBrush_.Reset();
        greenBrush_.Reset();
        amberBrush_.Reset();
        redBrush_.Reset();
        renderTarget_.Reset();
    }

    bool TitanDashboardUI::ProcessMessages() noexcept {
        MSG msg{};
        while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                return false;
            }
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
        return true;
    }

    void TitanDashboardUI::DrawTextLine(std::wstring_view text, IDWriteTextFormat* font,
        D2D1_RECT_F rect, ID2D1SolidColorBrush* brush) noexcept {
        if (!renderTarget_ || !font || !brush || text.empty()) return;
        renderTarget_->DrawTextW(
            text.data(),
            static_cast<UINT32>(text.size()),
            font,
            rect,
            brush,
            D2D1_DRAW_TEXT_OPTIONS_CLIP
        );
    }

    void TitanDashboardUI::DrawCard(D2D1_RECT_F rect, std::wstring_view title) noexcept {
        D2D1_ROUNDED_RECT rounded = D2D1::RoundedRect(rect, 8.0f, 8.0f);
        renderTarget_->FillRoundedRectangle(rounded, cardBrush_.Get());
        renderTarget_->DrawRoundedRectangle(rounded, borderBrush_.Get(), 1.5f);

        if (!title.empty()) {
            D2D1_RECT_F titleRect = D2D1::RectF(rect.left + 14.0f, rect.top + 10.0f, rect.right - 14.0f, rect.top + 30.0f);
            DrawTextLine(title, headerFont_.Get(), titleRect, cyanBrush_.Get());
        }
    }

    void TitanDashboardUI::DrawBandwidthGraph(D2D1_RECT_F rect, const DashboardSnapshot& snap) noexcept {
        DrawCard(rect, L"LIVE REAL-TIME NETWORK THROUGHPUT OSCILLOSCOPE (60-SECOND WINDOW)");

        const FLOAT plotLeft = rect.left + 16.0f;
        const FLOAT plotRight = rect.right - 16.0f;
        const FLOAT plotTop = rect.top + 38.0f;
        const FLOAT plotBottom = rect.bottom - 14.0f;
        const FLOAT plotWidth = plotRight - plotLeft;
        const FLOAT plotHeight = plotBottom - plotTop;

        if (plotWidth <= 10.0f || plotHeight <= 10.0f) return;

        // Subtle Grid Lines
        for (int i = 1; i <= 3; ++i) {
            const FLOAT y = plotTop + (plotHeight * static_cast<FLOAT>(i) / 4.0f);
            renderTarget_->DrawLine(D2D1::Point2F(plotLeft, y), D2D1::Point2F(plotRight, y), borderBrush_.Get(), 1.0f);
        }

        const double maxScale = (std::max)(snap.peakRxBytesPerSec * 1.15, 10240.0);

        auto drawWave = [&](const std::deque<double>& history, ID2D1SolidColorBrush* brush, FLOAT strokeWidth) {
            if (history.size() < 2) return;
            const std::size_t count = history.size();
            const FLOAT stepX = plotWidth / 59.0f;

            for (std::size_t i = 1; i < count; ++i) {
                const double v0 = std::clamp(history[i - 1] / maxScale, 0.0, 1.0);
                const double v1 = std::clamp(history[i] / maxScale, 0.0, 1.0);

                const FLOAT x0 = plotLeft + static_cast<FLOAT>(i - 1) * stepX;
                const FLOAT y0 = plotBottom - static_cast<FLOAT>(v0) * plotHeight;
                const FLOAT x1 = plotLeft + static_cast<FLOAT>(i) * stepX;
                const FLOAT y1 = plotBottom - static_cast<FLOAT>(v1) * plotHeight;

                renderTarget_->DrawLine(D2D1::Point2F(x0, y0), D2D1::Point2F(x1, y1), brush, strokeWidth);
            }
            };

        // Cyan = Download (RX), Green = Upload (TX)
        drawWave(snap.rxHistory, cyanBrush_.Get(), 2.5f);
        drawWave(snap.txHistory, greenBrush_.Get(), 1.8f);
    }

    void TitanDashboardUI::RenderFrame(const DashboardSnapshot& snap) noexcept {
        if (!CreateDeviceResources()) return;

        RECT rc{};
        ::GetClientRect(hwnd_, &rc);
        const UINT32 width = static_cast<UINT32>(rc.right - rc.left);
        const UINT32 height = static_cast<UINT32>(rc.bottom - rc.top);
        if (width == 0 || height == 0) return;

        renderTarget_->Resize(D2D1::SizeU(width, height));
        renderTarget_->BeginDraw();
        renderTarget_->Clear(D2D1::ColorF(0x090D16));

        const FLOAT w = static_cast<FLOAT>(width);
        const FLOAT h = static_cast<FLOAT>(height);

        // 1. Top Header Bar
        DrawTextLine(L"TITAN-NET C++20 SYSTEMS ENGINE  |  60 FPS DIRECTX COMMAND CENTER",
            titleFont_.Get(), D2D1::RectF(20.0f, 12.0f, w - 20.0f, 40.0f), textPrimaryBrush_.Get());

        const std::wstring statusRight = std::format(L"SHIELD: {}", Utf8ToWide(snap.shieldStatus));
        DrawTextLine(statusRight, headerFont_.Get(), D2D1::RectF(w - 520.0f, 16.0f, w - 20.0f, 40.0f), greenBrush_.Get());

        // 2. Top 3 Metric Cards
        const FLOAT cardW = (w - 60.0f) / 3.0f;
        const D2D1_RECT_F card1 = D2D1::RectF(20.0f, 46.0f, 20.0f + cardW, 126.0f);
        const D2D1_RECT_F card2 = D2D1::RectF(30.0f + cardW, 46.0f, 30.0f + cardW * 2.0f, 126.0f);
        const D2D1_RECT_F card3 = D2D1::RectF(40.0f + cardW * 2.0f, 46.0f, w - 20.0f, 126.0f);

        DrawCard(card1, L"PHASE 1 : TITAN-RADAR LIVE THROUGHPUT");
        DrawTextLine(std::format(L"RX: {}   |   TX: {}", FormatSpeedWide(snap.totalRxBytesPerSec), FormatSpeedWide(snap.totalTxBytesPerSec)),
            metricFont_.Get(), D2D1::RectF(card1.left + 14.0f, card1.top + 38.0f, card1.right - 14.0f, card1.bottom - 8.0f), textPrimaryBrush_.Get());

        DrawCard(card2, L"PHASE 2 : TITAN-SHIELD DEEP PACKET INSPECTOR");
        DrawTextLine(std::format(L"{} Pkts   |   {} Blocked", snap.packetsInspected, snap.telemetryBlocked),
            metricFont_.Get(), D2D1::RectF(card2.left + 14.0f, card2.top + 38.0f, card2.right - 14.0f, card2.bottom - 8.0f), greenBrush_.Get());

        DrawCard(card3, L"PHASE 3 : TITAN-FUSION MULTI-HOMED ROUTER");
        DrawTextLine(std::format(L"{} Gateways   |   {} Bound Sockets", snap.onlineGateways, snap.socketsDispatched),
            metricFont_.Get(), D2D1::RectF(card3.left + 14.0f, card3.top + 38.0f, card3.right - 14.0f, card3.bottom - 8.0f), amberBrush_.Get());

        // 3. Live Bandwidth Waveform Graph
        DrawBandwidthGraph(D2D1::RectF(20.0f, 138.0f, w - 20.0f, 285.0f), snap);

        // 4. Middle Split Panels (Left: NIC Fusion Load Share | Right: Live TLS SNI Feed)
        const FLOAT halfW = (w - 50.0f) / 2.0f;
        const D2D1_RECT_F fusionBox = D2D1::RectF(20.0f, 297.0f, 20.0f + halfW, 475.0f);
        const D2D1_RECT_F shieldBox = D2D1::RectF(30.0f + halfW, 297.0f, w - 20.0f, 475.0f);

        DrawCard(fusionBox, L"HARDWARE NICs & TITAN-FUSION LOAD BALANCER");
        FLOAT rowY = fusionBox.top + 38.0f;
        for (const auto& rt : snap.routes) {
            if (rowY + 34.0f > fusionBox.bottom) break;
            const std::wstring pingText = rt.gatewayOnline ? std::format(L"{:.1f} ms", rt.latencyMs) : L"OFFLINE";
            const std::wstring line = std::format(L"[#{}] {:<12} {:<15} Ping: {:<9} Share: {:>3}% ({} socks)",
                rt.interfaceIndex, Utf8ToWide(rt.friendlyName).substr(0, 12), Utf8ToWide(rt.ipv4Address),
                pingText, rt.weightPercent, rt.dispatchedSockets);

            DrawTextLine(line, monoFont_.Get(),
                D2D1::RectF(fusionBox.left + 14.0f, rowY, fusionBox.right - 14.0f, rowY + 18.0f),
                rt.gatewayOnline ? textPrimaryBrush_.Get() : textMutedBrush_.Get());

            // Visual Progress Bar for Traffic Weight %
            const FLOAT barLeft = fusionBox.left + 14.0f;
            const FLOAT barRight = fusionBox.right - 14.0f;
            const FLOAT barWidth = barRight - barLeft;
            const FLOAT fillW = barWidth * (static_cast<FLOAT>(rt.weightPercent) / 100.0f);

            renderTarget_->FillRectangle(D2D1::RectF(barLeft, rowY + 20.0f, barRight, rowY + 26.0f), borderBrush_.Get());
            if (fillW > 0.0f) {
                renderTarget_->FillRectangle(D2D1::RectF(barLeft, rowY + 20.0f, barLeft + fillW, rowY + 26.0f), cyanBrush_.Get());
            }
            rowY += 36.0f;
        }

        DrawCard(shieldBox, L"TITAN-SHIELD LIVE HTTPS TLS SNI INSPECTOR FEED");
        FLOAT sniY = shieldBox.top + 38.0f;
        if (snap.shieldEvents.empty()) {
            DrawTextLine(L"Listening on Kernel Raw Socket for HTTPS TLS ClientHello handshakes...",
                monoFont_.Get(), D2D1::RectF(shieldBox.left + 14.0f, sniY, shieldBox.right - 14.0f, sniY + 20.0f), textMutedBrush_.Get());
        }
        else {
            for (const auto& ev : snap.shieldEvents) {
                if (sniY + 20.0f > shieldBox.bottom) break;
                const std::wstring sniLine = std::format(L"{:<15} -> {:<20} | {}",
                    Utf8ToWide(ev.sourceIp),
                    Utf8ToWide(std::format("{}:{}", ev.destIp, ev.destPort)),
                    Utf8ToWide(ev.sniDomain).substr(0, 34));

                DrawTextLine(sniLine, monoFont_.Get(),
                    D2D1::RectF(shieldBox.left + 14.0f, sniY, shieldBox.right - 14.0f, sniY + 18.0f),
                    ev.wasBlocked ? redBrush_.Get() : greenBrush_.Get());
                sniY += 22.0f;
            }
        }

        // 5. Bottom Panel: Live Established Kernel TCP Table
        const D2D1_RECT_F tableBox = D2D1::RectF(20.0f, 487.0f, w - 20.0f, h - 16.0f);
        DrawCard(tableBox, std::format(L"ESTABLISHED KERNEL TCP FLOWS ({} Active Connections)", snap.tcpFlows.size()));

        FLOAT tblY = tableBox.top + 36.0f;
        DrawTextLine(L"PID       PROCESS (.EXE)              LOCAL ENDPOINT              REMOTE ENDPOINT",
            monoFont_.Get(), D2D1::RectF(tableBox.left + 14.0f, tblY, tableBox.right - 14.0f, tblY + 18.0f), amberBrush_.Get());
        tblY += 22.0f;

        for (const auto& flow : snap.tcpFlows) {
            if (tblY + 18.0f > tableBox.bottom - 6.0f) break;
            const std::wstring procName = Utf8ToWide(flow.processName).substr(0, 24);
            const std::wstring localEp = Utf8ToWide(std::format("{}:{}", flow.localAddress, flow.localPort));
            const std::wstring remoteEp = Utf8ToWide(std::format("{}:{}", flow.remoteAddress, flow.remotePort));

            const std::wstring rowStr = std::format(L"{:<9} {:<27} {:<27} {:<27}",
                flow.processId, procName, localEp, remoteEp);

            DrawTextLine(rowStr, monoFont_.Get(),
                D2D1::RectF(tableBox.left + 14.0f, tblY, tableBox.right - 14.0f, tblY + 18.0f), textPrimaryBrush_.Get());
            tblY += 19.0f;
        }

        HRESULT hr = renderTarget_->EndDraw();
        if (hr == D2DERR_RECREATE_TARGET) {
            DiscardDeviceResources();
        }
    }

} // namespace TitanNet::UI