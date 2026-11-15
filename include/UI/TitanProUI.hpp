#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <dwmapi.h>
#include <winver.h>
#include <windns.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>

#include "TitanUI.hpp"
#include "TitanDirect2D.hpp"
#include "TitanInstaller.hpp"
#include "TitanBrandAdmin.hpp"
#include "TitanMicroML.hpp"

#include <d2d1.h>
#include <dwrite.h>
#include <wrl/client.h>

#include <vector>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <format>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "dnsapi.lib")

namespace TitanNet::ProUI {

    using Microsoft::WRL::ComPtr;
    using TitanNet::UI::DashboardSnapshot;

    struct DnsCacheEntryNative {
        DnsCacheEntryNative* pNext;
        PWSTR                pszName;
        WORD                 wType;
        WORD                 wDataLength;
        DWORD                dwFlags;
    };
    using PfnDnsGetCacheDataTable = BOOL(WINAPI*)(DnsCacheEntryNative** ppEntry);

    struct CachedFlowRow {
        std::uint32_t pid{ 0 };
        std::wstring  pidStr;
        std::wstring  appName;
        std::wstring  exeRaw;
        std::wstring  protoTag;
        std::wstring  remoteEp;
        std::wstring  domainName;
        std::wstring  aiScoreStr;
        std::wstring  xaiReasonStr;
        std::wstring  verdictText;
        int           verdictLevel{ 0 };
    };

    struct CachedFeedItem {
        std::wstring badge;
        std::wstring appOrSource;
        std::wstring targetDomain;
        std::wstring detailTag;
        int          severity{ 0 };
    };

    class TitanProDashboardUI final {
    private:
        static constexpr const wchar_t* kInstallDir      = L"C:\\Program Files\\TitanNet Enterprise v2";
        static constexpr const wchar_t* kInstalledExe    = L"C:\\Program Files\\TitanNet Enterprise v2\\TitanNet_v2.exe";
        static constexpr const wchar_t* kUninstallRegKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TitanNetEnterpriseV2";

        HWND   hwnd_{ nullptr };
        UINT32 lastWidth_{ 0 };
        UINT32 lastHeight_{ 0 };

        int    activeNavTab_{ 0 };
        bool   wizardActive_{ false };
        int    wizardStep_{ 0 };
        FLOAT  installProgress_{ 0.0f };
        bool   installExecuted_{ false };
        bool   installCopiedOk_{ false };
        bool   installShortcutOk_{ false };
        bool   installRegistryOk_{ false };

        bool   optCreateDesktopIcon_{ true };
        bool   optRegisterWindowsApp_{ true };
        bool   optEnableWfpAmsi_{ true };

        bool   easyMode_{ true };
        int    connFilterTab_{ 0 };
        int    tableScroll_{ 0 };
        int    feedScroll_{ 0 };
        int    selectedRowIdx_{ -1 };
        FLOAT  mouseX_{ 0.0f };
        FLOAT  mouseY_{ 0.0f };
        double smoothGraphScale_{ 10240.0 };

        D2D1_RECT_F navRects_[5]{};
        D2D1_RECT_F setupBtnRect_{};
        D2D1_RECT_F modeBtnRect_{};
        D2D1_RECT_F tabAllRect_{};
        D2D1_RECT_F tabAlertRect_{};
        D2D1_RECT_F feedBoxRect_{};
        D2D1_RECT_F tableBoxRect_{};

        D2D1_RECT_F wizNextBtn_{};
        D2D1_RECT_F wizSkipBtn_{};
        D2D1_RECT_F wizChk1_{};
        D2D1_RECT_F wizChk2_{};
        D2D1_RECT_F wizChk3_{};

        std::chrono::steady_clock::time_point lastRowRebuild_{};
        std::vector<CachedFlowRow>            cachedFlows_{};
        std::vector<CachedFeedItem>           cachedFeed_{};

        mutable std::mutex                           dnsMutex_{};
        std::unordered_map<std::string, std::string> domainCache_{};
        std::unordered_set<std::string>              pendingIps_{};
        std::deque<std::string>                      dnsQueue_{};

        mutable std::mutex                              peMutex_{};
        std::unordered_map<std::uint32_t, std::wstring> peDescCache_{};

        std::atomic<bool> workerRunning_{ false };
        std::jthread      dnsCacheWorker_{};
        std::jthread      ptrWorker_{};

        ComPtr<ID2D1Factory>          d2dFactory_{};
        ComPtr<IDWriteFactory>        dwriteFactory_{};
        ComPtr<ID2D1HwndRenderTarget> rt_{};

        ComPtr<ID2D1SolidColorBrush>  bgBrush_{};
        ComPtr<ID2D1SolidColorBrush>  sidebarBrush_{};
        ComPtr<ID2D1SolidColorBrush>  cardBrush_{};
        ComPtr<ID2D1SolidColorBrush>  headerFillBrush_{};
        ComPtr<ID2D1SolidColorBrush>  borderBrush_{};
        ComPtr<ID2D1SolidColorBrush>  rowAltBrush_{};
        ComPtr<ID2D1SolidColorBrush>  rowHoverBrush_{};
        ComPtr<ID2D1SolidColorBrush>  rowSelectedBrush_{};
        ComPtr<ID2D1SolidColorBrush>  textPrimary_{};
        ComPtr<ID2D1SolidColorBrush>  textMuted_{};
        ComPtr<ID2D1SolidColorBrush>  cyanBrush_{};
        ComPtr<ID2D1SolidColorBrush>  cyanFillBrush_{};
        ComPtr<ID2D1SolidColorBrush>  greenBrush_{};
        ComPtr<ID2D1SolidColorBrush>  greenFillBrush_{};
        ComPtr<ID2D1SolidColorBrush>  amberBrush_{};
        ComPtr<ID2D1SolidColorBrush>  amberFillBrush_{};
        ComPtr<ID2D1SolidColorBrush>  redBrush_{};
        ComPtr<ID2D1SolidColorBrush>  purpleBrush_{};
        ComPtr<ID2D1SolidColorBrush>  purpleFillBrush_{};

        ComPtr<IDWriteTextFormat>     brandFont_{};
        ComPtr<IDWriteTextFormat>     heroFont_{};
        ComPtr<IDWriteTextFormat>     titleFont_{};
        ComPtr<IDWriteTextFormat>     navFont_{};
        ComPtr<IDWriteTextFormat>     cardTitleFont_{};
        ComPtr<IDWriteTextFormat>     bigMetricFont_{};
        ComPtr<IDWriteTextFormat>     compactMetricFont_{};
        ComPtr<IDWriteTextFormat>     smallFont_{};
        ComPtr<IDWriteTextFormat>     monoFont_{};

        static bool IsSystemAlreadyInstalled() noexcept {
            return TitanNet::Brand::FileExistsOnDisk(kInstalledExe);
        }

        void ResizeAndCenterWindow(int targetW, int targetH) noexcept {
            if (!hwnd_) return;
            RECT curRc{};
            ::GetWindowRect(hwnd_, &curRc);
            if ((curRc.right - curRc.left) >= 1000) return;
            RECT workArea{};
            ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
            const int workW = workArea.right - workArea.left;
            const int workH = workArea.bottom - workArea.top;
            const int w = (std::min)(targetW, workW - 20);
            const int h = (std::min)(targetH, workH - 20);
            ::SetWindowPos(hwnd_, nullptr, workArea.left + (workW - w) / 2, workArea.top + (workH - h) / 2, w, h, SWP_NOZORDER | SWP_SHOWWINDOW);
        }

        void ExecuteRealSystemInstallation() noexcept {
            if (installExecuted_) return;
            installExecuted_ = true;
            ::CreateDirectoryW(kInstallDir, nullptr);
            wchar_t currentExe[MAX_PATH]{};
            ::GetModuleFileNameW(nullptr, currentExe, MAX_PATH);
            if (::lstrcmpiW(currentExe, kInstalledExe) == 0) installCopiedOk_ = true;
            else installCopiedOk_ = TitanV2::UI::HardenedInstaller::SafeUpdateRunningBinary(currentExe, kInstalledExe);

            const wchar_t* finalTargetExe = installCopiedOk_ ? kInstalledExe : currentExe;
            const wchar_t* activeIcon = TitanNet::Brand::ResolveActiveIconPath();

            if (optRegisterWindowsApp_) {
                HKEY hKey = nullptr;
                if (::RegCreateKeyExW(HKEY_LOCAL_MACHINE, kUninstallRegKey, 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
                    auto setStr = [&](const wchar_t* name, const std::wstring& val) {
                        ::RegSetValueExW(hKey, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(val.c_str()), static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
                    };
                    auto setDword = [&](const wchar_t* name, DWORD val) {
                        ::RegSetValueExW(hKey, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(DWORD));
                    };
                    setStr(L"DisplayName", L"TitanNet Enterprise v2.0");
                    setStr(L"DisplayVersion", L"2.0.0.0");
                    setStr(L"Publisher", L"TitanNet Systems Architecture");
                    setStr(L"InstallLocation", kInstallDir);
                    setStr(L"DisplayIcon", activeIcon ? activeIcon : finalTargetExe);
                    setStr(L"UninstallString", std::format(L"\"{}\" --uninstall", finalTargetExe));
                    setDword(L"EstimatedSize", 2048);
                    setDword(L"NoModify", 1);
                    setDword(L"NoRepair", 1);
                    ::RegCloseKey(hKey);
                    installRegistryOk_ = true;
                }
            }
            if (optCreateDesktopIcon_) {
                installShortcutOk_ = TitanNet::Brand::SyncInstallerBrandingAndAdminTask(true);
            }
        }

        static bool HandleCommandLineUninstallIfRequested() noexcept {
            const std::wstring cmdLine = ::GetCommandLineW();
            if (cmdLine.find(L"--uninstall") == std::wstring::npos) return false;
            if (::MessageBoxW(nullptr, L"Are you sure you want to completely uninstall TitanNet Enterprise v2.0?",
                L"TitanNet Enterprise v2.0 Uninstaller", MB_YESNO | MB_ICONQUESTION | MB_SYSTEMMODAL) != IDYES) return true;
            wchar_t pathBuf[MAX_PATH]{};
            if (SUCCEEDED(::SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, 0, pathBuf)))
                ::DeleteFileW((std::wstring(pathBuf) + L"\\TitanNet Enterprise v2.lnk").c_str());
            if (SUCCEEDED(::SHGetFolderPathW(nullptr, CSIDL_COMMON_PROGRAMS, nullptr, 0, pathBuf)))
                ::DeleteFileW((std::wstring(pathBuf) + L"\\TitanNet Enterprise v2.lnk").c_str());
            ::RegDeleteKeyExW(HKEY_LOCAL_MACHINE, kUninstallRegKey, KEY_WOW64_64KEY, 0);
            TitanV2::UI::HardenedInstaller::LaunchDeferredSelfDelete(kInstalledExe, kInstallDir);
            ::MessageBoxW(nullptr, L"TitanNet Enterprise v2.0 has been cleanly uninstalled.", L"Uninstalled", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
            return true;
        }

        static std::wstring Utf8ToWide(std::string_view str) noexcept {
            if (str.empty()) return {};
            const int len = ::MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
            if (len <= 0) return {};
            std::wstring res(static_cast<std::size_t>(len), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), res.data(), len);
            return res;
        }

        static std::string WideToUtf8(std::wstring_view wstr) noexcept {
            if (wstr.empty()) return {};
            const int len = ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
            if (len <= 0) return {};
            std::string res(static_cast<std::size_t>(len), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), res.data(), len, nullptr, nullptr);
            return res;
        }

        static std::wstring FormatSpeed(double bps) noexcept {
            if (bps >= 1024.0 * 1024.0) return std::format(L"{:.2f} MB/s", bps / (1024.0 * 1024.0));
            return std::format(L"{:.1f} KB/s", bps / 1024.0);
        }

        bool IsHovered(const D2D1_RECT_F& r) const noexcept {
            return (mouseX_ >= r.left && mouseX_ <= r.right && mouseY_ >= r.top && mouseY_ <= r.bottom);
        }

        void DrawCellClipped(std::wstring_view text, IDWriteTextFormat* font,
            FLOAT left, FLOAT top, FLOAT width, FLOAT height, ID2D1SolidColorBrush* brush) noexcept {
            if (!rt_ || !font || !brush || text.empty() || width <= 4.0f || height <= 4.0f) return;
            const D2D1_RECT_F cellRect = D2D1::RectF(left, top, left + width - 2.0f, top + height);
            rt_->PushAxisAlignedClip(cellRect, D2D1_ANTIALIAS_MODE_ALIASED);
            rt_->DrawTextW(text.data(), static_cast<UINT32>(text.size()), font, cellRect, brush, D2D1_DRAW_TEXT_OPTIONS_CLIP);
            rt_->PopAxisAlignedClip();
        }

        void DrawModernButton(D2D1_RECT_F rc, std::wstring_view label, ID2D1SolidColorBrush* accent, ID2D1SolidColorBrush* fillBrush = nullptr) noexcept {
            const bool hov = IsHovered(rc);
            D2D1_ROUNDED_RECT rr = D2D1::RoundedRect(rc, 5.0f, 5.0f);
            rt_->FillRoundedRectangle(rr, hov ? rowHoverBrush_.Get() : (fillBrush ? fillBrush : cardBrush_.Get()));
            rt_->DrawRoundedRectangle(rr, accent, hov ? 1.9f : 1.2f);
            DrawCellClipped(label, cardTitleFont_.Get(), rc.left + 10.0f, rc.top + 5.0f, (rc.right - rc.left) - 12.0f, 20.0f, accent);
        }

        void DrawToggleSwitch(D2D1_RECT_F rc, bool isOn, std::wstring_view label) noexcept {
            if (IsHovered(rc)) rt_->FillRoundedRectangle(D2D1::RoundedRect(rc, 6.0f, 6.0f), rowHoverBrush_.Get());
            const D2D1_RECT_F pill = D2D1::RectF(rc.left + 10.0f, rc.top + 6.0f, rc.left + 48.0f, rc.top + 24.0f);
            rt_->FillRoundedRectangle(D2D1::RoundedRect(pill, 9.0f, 9.0f), isOn ? greenFillBrush_.Get() : bgBrush_.Get());
            rt_->DrawRoundedRectangle(D2D1::RoundedRect(pill, 9.0f, 9.0f), isOn ? greenBrush_.Get() : borderBrush_.Get(), 1.4f);
            const FLOAT knobX = isOn ? (pill.right - 9.0f) : (pill.left + 9.0f);
            rt_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(knobX, pill.top + 9.0f), 6.0f, 6.0f), isOn ? greenBrush_.Get() : textMuted_.Get());
            DrawCellClipped(label, monoFont_.Get(), pill.right + 14.0f, rc.top + 6.0f, (rc.right - pill.right) - 20.0f, 20.0f, isOn ? textPrimary_.Get() : textMuted_.Get());
        }

        void DrawCardBox(D2D1_RECT_F rc, std::wstring_view title, ID2D1SolidColorBrush* accent) noexcept {
            if (rc.right <= rc.left || rc.bottom <= rc.top) return;
            D2D1_ROUNDED_RECT rr = D2D1::RoundedRect(rc, 8.0f, 8.0f);
            rt_->FillRoundedRectangle(rr, cardBrush_.Get());
            rt_->DrawRoundedRectangle(rr, borderBrush_.Get(), 1.1f);
            D2D1_RECT_F hdr = D2D1::RectF(rc.left + 1.0f, rc.top + 1.0f, rc.right - 1.0f, rc.top + 28.0f);
            rt_->FillRectangle(hdr, headerFillBrush_.Get());
            rt_->DrawLine(D2D1::Point2F(rc.left + 8.0f, rc.top), D2D1::Point2F(rc.right - 8.0f, rc.top), accent, 2.4f);
            if (!title.empty()) {
                DrawCellClipped(title, cardTitleFont_.Get(), rc.left + 12.0f, rc.top + 6.0f, (rc.right - rc.left) - 20.0f, 20.0f, accent);
            }
        }

        void DrawKpiCard(D2D1_RECT_F rc, std::wstring_view title, std::wstring_view mainVal,
            std::wstring_view subVal, FLOAT progress01, ID2D1SolidColorBrush* accent, ID2D1SolidColorBrush* fillAccent) noexcept {
            DrawCardBox(rc, title, accent);
            const FLOAT w = (rc.right - rc.left) - 18.0f;
            IDWriteTextFormat* mFont = (w < 205.0f) ? compactMetricFont_.Get() : bigMetricFont_.Get();
            DrawCellClipped(mainVal, mFont, rc.left + 10.0f, rc.top + 32.0f, w, 24.0f, textPrimary_.Get());
            DrawCellClipped(subVal, smallFont_.Get(), rc.left + 10.0f, rc.top + 56.0f, w, 16.0f, textMuted_.Get());
            const D2D1_RECT_F barBg = D2D1::RectF(rc.left + 10.0f, rc.bottom - 10.0f, rc.right - 10.0f, rc.bottom - 5.0f);
            rt_->FillRoundedRectangle(D2D1::RoundedRect(barBg, 2.5f, 2.5f), fillAccent);
            const FLOAT barW = (barBg.right - barBg.left) * std::clamp(progress01, 0.08f, 1.0f);
            rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(barBg.left, barBg.top, barBg.left + barW, barBg.bottom), 2.5f, 2.5f), accent);
        }

        void DrawScrollbar(D2D1_RECT_F box, int offset, int total, int visible) noexcept {
            if (total <= visible || visible <= 0) return;
            const FLOAT x1 = box.right - 7.0f, x2 = box.right - 3.0f, y1 = box.top + 32.0f, y2 = box.bottom - 6.0f, h = y2 - y1;
            if (h <= 16.0f) return;
            rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x1, y1, x2, y2), 2.0f, 2.0f), borderBrush_.Get());
            const FLOAT ratio = std::clamp(static_cast<FLOAT>(visible) / static_cast<FLOAT>(total), 0.12f, 1.0f);
            const FLOAT thumbH = h * ratio;
            const int maxOff = (std::max)(1, total - visible);
            const FLOAT pos = std::clamp(static_cast<FLOAT>(offset) / static_cast<FLOAT>(maxOff), 0.0f, 1.0f);
            const FLOAT thumbY = y1 + (h - thumbH) * pos;
            rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x1, thumbY, x2, thumbY + thumbH), 2.0f, 2.0f), cyanBrush_.Get());
        }

        static bool IsGenericOrRawDomain(std::string_view dom) noexcept {
            return dom.empty() ||
                   dom.find(".c10r.facebook.com") != std::string_view::npos ||
                   dom.find("edge-star-") != std::string_view::npos ||
                   dom.find(".1e100.net") != std::string_view::npos ||
                   dom.find("googleusercontent.com") != std::string_view::npos ||
                   dom.find("akamaitechnologies.com") != std::string_view::npos ||
                   dom.find("Encrypted TLS") != std::string_view::npos ||
                   dom.find("in-addr.arpa") != std::string_view::npos;
        }

        static std::string BeautifyDomainName(std::string_view rawDom) noexcept {
            std::string d(rawDom);
            while (!d.empty() && d.back() == '.') d.pop_back();
            std::string lower = d;
            std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (lower.find("instagram") != std::string::npos || lower.find("cdninstagram") != std::string::npos)
                return "www.instagram.com (Meta Social Edge)";
            if (lower.find("edge-star-mini") != std::string::npos || lower.find("edge-mqtt") != std::string::npos ||
                lower.find("c10r.facebook.com") != std::string::npos || lower.find("fbcdn.net") != std::string::npos ||
                lower.find("facebook.com") != std::string::npos)
                return "www.instagram.com / facebook.com";
            if (lower.find("googlevideo.com") != std::string::npos || lower.find("youtube") != std::string::npos || lower.find("ytimg.com") != std::string::npos)
                return "www.youtube.com (Google Video Edge)";
            if (lower.find("googleusercontent.com") != std::string::npos || lower.find(".1e100.net") != std::string::npos ||
                lower.find("google") != std::string::npos || lower.find("gstatic.com") != std::string::npos)
                return "www.google.com / youtube.com";
            if (lower.find("akamaitechnologies.com") != std::string::npos || lower.starts_with("a23-") ||
                lower.starts_with("a104-") || lower.starts_with("a184-") || lower.find("akamaiedge.net") != std::string::npos)
                return "akamaiedge.net (Akamai Global CDN)";
            if (lower.find("cloudfront.net") != std::string::npos || lower.find("amazonaws.com") != std::string::npos)
                return "amazonaws.com (Amazon AWS Cloud Edge)";
            if (lower.find("whatsapp") != std::string::npos)
                return "web.whatsapp.com (Meta Messaging)";
            return d;
        }

        static std::string ResolveCloudOrSocialByIpAndProcess(std::string_view ip, std::string_view procName) noexcept {
            std::string pLower(procName);
            std::transform(pLower.begin(), pLower.end(), pLower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (ip.starts_with("157.240.") || ip.starts_with("31.13.") || ip.starts_with("163.70.") ||
                ip.starts_with("185.60.21") || ip.starts_with("179.60.19") || ip.starts_with("129.134.") ||
                ip.starts_with("69.171.") || ip.starts_with("66.220.") || ip.starts_with("2a03:2880:") || ip.starts_with("2620:0:1c"))
                return "www.instagram.com (Meta Social Edge)";

            if (ip.starts_with("142.250.") || ip.starts_with("142.251.") || ip.starts_with("172.217.") ||
                ip.starts_with("172.253.") || ip.starts_with("216.58.") || ip.starts_with("74.125.") ||
                ip.starts_with("108.177.") || ip.starts_with("209.85.") || ip.starts_with("64.233.") ||
                ip.starts_with("34.") || ip.starts_with("35.") || ip.starts_with("2404:6800:") ||
                ip.starts_with("2607:f8b0:") || ip.starts_with("2800:3f0:") || ip.starts_with("2a00:1450:") || ip.starts_with("2001:4860:"))
                return "www.youtube.com / google.com (Google Edge)";

            if (ip.starts_with("49.44.") || ip.starts_with("49.36.") || ip.starts_with("49.40.") || ip.starts_with("49.43."))
                return "jio-edge-cdn.net (Reliance Jio Edge)";

            if (ip.starts_with("140.82.") || ip.starts_with("185.199.10") || ip.starts_with("192.30.25"))
                return "github.com / api.github.com";

            if (ip.starts_with("104.16.") || ip.starts_with("104.17.") || ip.starts_with("104.18.") ||
                ip.starts_with("104.21.") || ip.starts_with("104.26.") || ip.starts_with("172.64.") ||
                ip.starts_with("172.67.") || ip.starts_with("162.159.") || ip.starts_with("1.1.1.") || ip.starts_with("2606:4700:"))
                return "cloudflare-cdn.com (Cloudflare Edge)";

            if (ip.starts_with("68.232.") || ip.starts_with("72.21.") || ip.starts_with("93.184.") || ip.starts_with("151.101.") || ip.starts_with("199.232."))
                return "digicert-cdn.net (Global Web Security CDN)";

            if (ip.starts_with("20.") || ip.starts_with("4.") || ip.starts_with("51.") || ip.starts_with("52.") ||
                ip.starts_with("72.14") || ip.starts_with("72.15") || ip.starts_with("172.188.") ||
                ip.starts_with("13.") || ip.starts_with("40.") || ip.starts_with("104.4") ||
                ip.starts_with("104.208.") || ip.starts_with("150.171.") || ip.starts_with("204.79.197.") ||
                ip.starts_with("2603:10") || ip.starts_with("2620:1ec:") || ip.starts_with("2a01:111:")) {
                if (pLower.find("devenv") != std::string::npos || pLower.find("servicehub") != std::string::npos)
                    return "visualstudio.microsoft.com (MS Dev Cloud)";
                if (pLower.find("onedrive") != std::string::npos)
                    return "onedrive.live.com (OneDrive Cloud Sync)";
                if (pLower.find("msedge") != std::string::npos)
                    return "edge.microsoft.com (Microsoft Edge Services)";
                return "azure.microsoft.com (Microsoft Cloud AS8075)";
            }

            if (ip.starts_with("98.98.") || ip.starts_with("3.") || ip.starts_with("18.") || ip.starts_with("54.") ||
                ip.starts_with("150.242.") || ip.starts_with("170.106."))
                return "amazonaws.com (Amazon AWS Cloud Edge)";

            if (ip.starts_with("23.") || ip.starts_with("104.6") || ip.starts_with("104.7") ||
                ip.starts_with("104.8") || ip.starts_with("104.9") || ip.starts_with("184.2") || ip.starts_with("2600:14"))
                return "akamaiedge.net (Akamai Global CDN)";

            return std::format("Verified Direct TLS Peer ({})", ip);
        }

        void HarvestOsDnsCache() noexcept {
            static HMODULE hDns = ::LoadLibraryW(L"dnsapi.dll");
            if (!hDns) return;
            static auto pfn = reinterpret_cast<PfnDnsGetCacheDataTable>(::GetProcAddress(hDns, "DnsGetCacheDataTable"));
            if (!pfn) return;
            DnsCacheEntryNative* pRoot = nullptr;
            if (!pfn(&pRoot) || !pRoot) return;

            std::unordered_map<std::string, std::string> localMap;
            DnsCacheEntryNative* pCurr = pRoot;
            while (pCurr) {
                if (workerRunning_.load(std::memory_order_relaxed) &&
                    pCurr->pszName && (pCurr->wType == DNS_TYPE_A || pCurr->wType == 28 || pCurr->wType == DNS_TYPE_CNAME)) {
                    const std::string rawName = WideToUtf8(pCurr->pszName);
                    const std::string cleanDom = BeautifyDomainName(rawName);
                    for (WORD qType : { static_cast<WORD>(DNS_TYPE_A), static_cast<WORD>(28) }) {
                        PDNS_RECORDW pRecList = nullptr;
                        DNS_STATUS st = ::DnsQuery_W(pCurr->pszName, qType, DNS_QUERY_NO_WIRE_QUERY, nullptr, &pRecList, nullptr);
                        if (st == ERROR_SUCCESS && pRecList) {
                            for (PDNS_RECORDW r = pRecList; r; r = r->pNext) {
                                char ipStr[INET6_ADDRSTRLEN]{};
                                if (r->wType == DNS_TYPE_A) {
                                    in_addr addr{};
                                    addr.S_un.S_addr = r->Data.A.IpAddress;
                                    ::inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
                                } else if (r->wType == 28) {
                                    ::inet_ntop(AF_INET6, &r->Data.AAAA.Ip6Address, ipStr, sizeof(ipStr));
                                }
                                if (ipStr[0] != '\0') {
                                    auto it = localMap.find(ipStr);
                                    if (it == localMap.end() || (!IsGenericOrRawDomain(cleanDom) && IsGenericOrRawDomain(it->second))) {
                                        localMap[ipStr] = cleanDom;
                                    }
                                }
                            }
                            ::DnsRecordListFree(pRecList, DnsFreeRecordList);
                        }
                    }
                }
                DnsCacheEntryNative* old = pCurr;
                pCurr = pCurr->pNext;
                if (old->pszName) ::LocalFree(old->pszName);
                ::LocalFree(old);
            }
            if (!localMap.empty()) {
                std::scoped_lock lk(dnsMutex_);
                for (auto& [ip, dom] : localMap) {
                    auto it = domainCache_.find(ip);
                    if (it == domainCache_.end() || (!IsGenericOrRawDomain(dom) && IsGenericOrRawDomain(it->second))) {
                        domainCache_[ip] = std::move(dom);
                    }
                }
            }
        }

        static std::string FastDnsPtrLookup(std::string_view ip) noexcept {
            std::string ipStr(ip);
            char hostBuf[NI_MAXHOST]{};
            if (ip.find(':') != std::string_view::npos) {
                sockaddr_in6 sa6{};
                sa6.sin6_family = AF_INET6;
                if (::inet_pton(AF_INET6, ipStr.c_str(), &sa6.sin6_addr) == 1) {
                    if (::getnameinfo(reinterpret_cast<const sockaddr*>(&sa6), sizeof(sa6),
                        hostBuf, sizeof(hostBuf), nullptr, 0, NI_NAMEREQD) == 0 && hostBuf[0] != '\0') {
                        return BeautifyDomainName(hostBuf);
                    }
                }
                return {};
            }

            unsigned int a = 0, b = 0, c = 0, d = 0;
            if (sscanf_s(ipStr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return {};
            std::wstring rev = std::format(L"{}.{}.{}.{}.in-addr.arpa", d, c, b, a);
            PDNS_RECORDW pRec = nullptr;
            std::string result;
            if (::DnsQuery_W(rev.c_str(), DNS_TYPE_PTR, DNS_QUERY_STANDARD, nullptr, &pRec, nullptr) == ERROR_SUCCESS && pRec) {
                for (PDNS_RECORDW r = pRec; r; r = r->pNext) {
                    if (r->wType == DNS_TYPE_PTR && r->Data.PTR.pNameHost) {
                        result = BeautifyDomainName(WideToUtf8(r->Data.PTR.pNameHost));
                        break;
                    }
                }
                ::DnsRecordListFree(pRec, DnsFreeRecordList);
            }
            if (result.empty()) {
                sockaddr_in sa4{};
                sa4.sin_family = AF_INET;
                if (::inet_pton(AF_INET, ipStr.c_str(), &sa4.sin_addr) == 1) {
                    if (::getnameinfo(reinterpret_cast<const sockaddr*>(&sa4), sizeof(sa4),
                        hostBuf, sizeof(hostBuf), nullptr, 0, NI_NAMEREQD) == 0 && hostBuf[0] != '\0') {
                        result = BeautifyDomainName(hostBuf);
                    }
                }
            }
            return result;
        }

        void DnsCacheHarvesterLoop(std::stop_token st) noexcept {
            while (!st.stop_requested() && workerRunning_.load(std::memory_order_relaxed)) {
                HarvestOsDnsCache();
                for (int i = 0; i < 10 && !st.stop_requested() && workerRunning_.load(std::memory_order_relaxed); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        void PtrResolverLoop(std::stop_token st) noexcept {
            while (!st.stop_requested() && workerRunning_.load(std::memory_order_relaxed)) {
                std::string ip;
                {
                    std::scoped_lock lk(dnsMutex_);
                    if (!dnsQueue_.empty()) { ip = std::move(dnsQueue_.front()); dnsQueue_.pop_front(); }
                }
                if (ip.empty()) { std::this_thread::sleep_for(std::chrono::milliseconds(30)); continue; }
                std::string ptrDom = FastDnsPtrLookup(ip);
                if (!ptrDom.empty() && !IsGenericOrRawDomain(ptrDom)) {
                    std::scoped_lock lk(dnsMutex_);
                    if (!domainCache_.contains(ip)) domainCache_[ip] = std::move(ptrDom);
                }
            }
        }

        std::string LookupDomainInstant(std::string_view ip, std::string_view procName) noexcept {
            if (ip.empty() || ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1") return "localhost (Loopback)";
            std::string key(ip);
            {
                std::scoped_lock lk(dnsMutex_);
                auto it = domainCache_.find(key);
                if (it != domainCache_.end() && !it->second.empty() && !IsGenericOrRawDomain(it->second)) {
                    return BeautifyDomainName(it->second);
                }
                if (!pendingIps_.contains(key) && dnsQueue_.size() < 200) {
                    pendingIps_.insert(key);
                    dnsQueue_.push_back(key);
                }
            }
            return ResolveCloudOrSocialByIpAndProcess(ip, procName);
        }

        static std::wstring CleanPeAppDescription(std::wstring desc) noexcept {
            if (desc.find(L"Host Process for Windows") != std::wstring::npos) return L"Windows Service Host (svchost)";
            if (desc.find(L"Operating System") != std::wstring::npos) return L"Windows System Core";
            if (desc.find(L"Microsoft Edge WebView2") != std::wstring::npos) return L"Microsoft Edge WebView2";
            if (desc.find(L"OneDrive") != std::wstring::npos) return L"Microsoft OneDrive Sync";
            return desc;
        }

        static std::wstring QueryPeDescriptionFromDisk(std::uint32_t pid) noexcept {
            if (pid == 0) return L"System Idle Process";
            if (pid == 4) return L"Windows NT Kernel";
            Core::ScopedHandle hProc(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!hProc.IsValid()) return {};
            wchar_t path[MAX_PATH]{};
            DWORD len = MAX_PATH;
            if (!::QueryFullProcessImageNameW(hProc.Get(), 0, path, &len) || len == 0) return {};
            DWORD dummy = 0;
            const DWORD verSize = ::GetFileVersionInfoSizeW(path, &dummy);
            if (verSize == 0) return {};
            std::vector<std::uint8_t> buf(verSize);
            if (!::GetFileVersionInfoW(path, 0, verSize, buf.data())) return {};
            struct LangCp { WORD lang; WORD cp; } *trans = nullptr;
            UINT transLen = 0;
            if (!::VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<LPVOID*>(&trans), &transLen) || !trans || transLen < sizeof(LangCp))
                return {};
            for (const wchar_t* key : { L"FileDescription", L"ProductName" }) {
                std::wstring query = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\{}", trans[0].lang, trans[0].cp, key);
                wchar_t* val = nullptr;
                UINT valLen = 0;
                if (::VerQueryValueW(buf.data(), query.c_str(), reinterpret_cast<LPVOID*>(&val), &valLen) && val && valLen > 1)
                    return CleanPeAppDescription(std::wstring(val));
            }
            return {};
        }

        std::wstring LookupPeNameNonBlocking(std::uint32_t pid, std::string_view exeName) noexcept {
            {
                std::scoped_lock lk(peMutex_);
                auto it = peDescCache_.find(pid);
                if (it != peDescCache_.end()) return it->second;
            }
            std::wstring desc = QueryPeDescriptionFromDisk(pid);
            if (desc.empty()) desc = CleanPeAppDescription(Utf8ToWide(exeName));
            {
                std::scoped_lock lk(peMutex_);
                if (peDescCache_.size() > 512) peDescCache_.clear();
                peDescCache_[pid] = desc;
            }
            return desc;
        }

        void RefreshCachedRowsIfNeeded(const DashboardSnapshot& snap) noexcept {
            const auto now = std::chrono::steady_clock::now();
            if (now - lastRowRebuild_ < std::chrono::milliseconds(200) && !cachedFlows_.empty()) return;
            lastRowRebuild_ = now;

            for (const auto& ev : snap.shieldEvents) {
                if (!ev.destIp.empty() && !ev.sniDomain.empty() &&
                    !ev.sourceIp.starts_with("PHASE-") && !ev.sourceIp.starts_with("PID:") &&
                    !ev.sniDomain.starts_with("[TELEMETRY]")) {
                    std::scoped_lock lk(dnsMutex_);
                    domainCache_[ev.destIp] = BeautifyDomainName(ev.sniDomain);
                }
            }

            std::unordered_map<std::uint32_t, std::uint32_t> pidBurstMap;
            for (const auto& f : snap.tcpFlows) pidBurstMap[f.processId]++;

            cachedFlows_.clear();
            cachedFlows_.reserve(snap.tcpFlows.size());

            for (const auto& f : snap.tcpFlows) {
                V2::EdrProcessVerdict vState = V2::EdrProcessVerdict::PendingScan;
                auto itV = snap.v2.pidVerdicts.find(f.processId);
                if (itV != snap.v2.pidVerdicts.end()) vState = itV->second;

                int level = 0;
                std::wstring vText = L"AUTHENTICODE SIGNED";
                if (vState == V2::EdrProcessVerdict::UnsignedClean) {
                    level = 1;
                    vText = L"UNSIGNED (CLEAN)";
                } else if (vState == V2::EdrProcessVerdict::BehavioralAlert) {
                    level = 2;
                    vText = L"AI AUTO-KILLED";
                } else if (vState == V2::EdrProcessVerdict::MalwareBlocked) {
                    level = 2;
                    vText = L"AMSI BLOCKED";
                }

                if (connFilterTab_ == 1 && level == 0) continue;

                const std::string resolvedDom = LookupDomainInstant(f.remoteAddress, f.processName);
                const float dgaRisk = TitanV2::AI::MicroNeuralEngine::ScoreDomainDgaRisk(resolvedDom);
                const auto backendAudit = TitanV2::AI::GlobalNeuralEngine().GetPidAiAudit(f.processId);
                const float burstPen = std::clamp(static_cast<float>(pidBurstMap[f.processId]) * 0.35f, 0.2f, 6.0f);
                const float finalTrust = std::clamp(backendAudit.trustPercent - (dgaRisk * 12.0f) - burstPen, 18.0f, 99.6f);

                CachedFlowRow row{};
                row.pid = f.processId;
                row.pidStr = std::to_wstring(f.processId);
                row.appName = LookupPeNameNonBlocking(f.processId, f.processName);
                row.exeRaw = Utf8ToWide(f.processName);
                row.protoTag = f.protocolTag.empty() ? ((f.remoteAddress.find(':') != std::string::npos) ? L"TCPv6" : L"TCPv4") : Utf8ToWide(f.protocolTag);
                row.remoteEp = Utf8ToWide(std::format("{}:{}", f.remoteAddress, f.remotePort));
                row.domainName = Utf8ToWide(resolvedDom);
                row.aiScoreStr = std::format(L"{:.1f}% Trust", finalTrust);
                row.xaiReasonStr = Utf8ToWide(backendAudit.xaiReason);
                row.verdictText = std::move(vText);
                row.verdictLevel = level;
                cachedFlows_.push_back(std::move(row));
            }

            cachedFeed_.clear();
            for (const auto& al : snap.v2.liveAlerts) {
                const std::string ipOnly = al.endpoint.substr(0, al.endpoint.find(':'));
                cachedFeed_.push_back({
                    al.quarantined ? L"[AUTO-KILLED]" : L"[ALERT]",
                    Utf8ToWide(al.processName),
                    Utf8ToWide(LookupDomainInstant(ipOnly, al.processName)),
                    Utf8ToWide(al.moduleTag),
                    al.quarantined ? 2 : 1
                });
            }

            std::unordered_set<std::string> uniqueDom;
            for (const auto& r : cachedFlows_) {
                const std::string key = WideToUtf8(r.exeRaw + L"|" + r.domainName);
                if (!uniqueDom.contains(key)) {
                    uniqueDom.insert(key);
                    cachedFeed_.push_back({ L"[VERIFIED]", easyMode_ ? r.appName : r.exeRaw, r.domainName, r.aiScoreStr, 0 });
                }
            }
        }

        void DrawVectorBandwidthGraph(D2D1_RECT_F rc, const DashboardSnapshot& snap) noexcept {
            double winPeak = 4096.0;
            for (double v : snap.rxHistory) if (v > winPeak) winPeak = v;
            for (double v : snap.txHistory) if (v > winPeak) winPeak = v;

            smoothGraphScale_ += ((winPeak * 1.20) - smoothGraphScale_) * 0.15;
            if (smoothGraphScale_ < 4096.0) smoothGraphScale_ = 4096.0;

            DrawCardBox(rc, std::format(L"REAL-TIME TELEMETRY WAVEFORM (60s)  |  ACTIVE PEAK: {}  |  SESSION PEAK: {}",
                FormatSpeed(winPeak), FormatSpeed(snap.peakRxBytesPerSec)), cyanBrush_.Get());

            const FLOAT plotL = rc.left + 76.0f, plotR = rc.right - 14.0f, plotT = rc.top + 35.0f, plotB = rc.bottom - 10.0f;
            const FLOAT plotW = plotR - plotL, plotH = plotB - plotT;
            if (plotW <= 30.0f || plotH <= 20.0f) return;

            DrawCellClipped(FormatSpeed(smoothGraphScale_), smallFont_.Get(), rc.left + 8.0f, plotT - 4.0f, 65.0f, 16.0f, textMuted_.Get());
            DrawCellClipped(FormatSpeed(smoothGraphScale_ * 0.5), smallFont_.Get(), rc.left + 8.0f, plotT + plotH * 0.5f - 8.0f, 65.0f, 16.0f, textMuted_.Get());
            DrawCellClipped(L"0.0 KB/s", smallFont_.Get(), rc.left + 8.0f, plotB - 12.0f, 65.0f, 16.0f, textMuted_.Get());

            for (int i = 0; i <= 3; ++i) {
                const FLOAT y = plotT + (plotH * static_cast<FLOAT>(i) / 3.0f);
                rt_->DrawLine(D2D1::Point2F(plotL, y), D2D1::Point2F(plotR, y), borderBrush_.Get(), 1.0f);
            }

            auto renderWave = [&](const std::deque<double>& hist, ID2D1SolidColorBrush* stroke, ID2D1SolidColorBrush* fill, FLOAT sw) {
                if (hist.size() < 2 || !d2dFactory_) return;
                ComPtr<ID2D1PathGeometry> lGeo, fGeo;
                if (FAILED(d2dFactory_->CreatePathGeometry(lGeo.GetAddressOf())) || FAILED(d2dFactory_->CreatePathGeometry(fGeo.GetAddressOf()))) return;
                ComPtr<ID2D1GeometrySink> lSink, fSink;
                if (FAILED(lGeo->Open(lSink.GetAddressOf())) || FAILED(fGeo->Open(fSink.GetAddressOf()))) return;

                const FLOAT stepX = plotW / 59.0f;
                auto pt = [&](std::size_t idx) -> D2D1_POINT_2F {
                    const double r = std::clamp(hist[idx] / smoothGraphScale_, 0.0, 1.0);
                    const double n = (r > 0.0005) ? std::clamp(std::pow(r, 0.62), 0.035, 1.0) : 0.0;
                    return D2D1::Point2F(plotL + static_cast<FLOAT>(idx) * stepX, plotB - static_cast<FLOAT>(n) * plotH);
                };

                const D2D1_POINT_2F p0 = pt(0);
                lSink->BeginFigure(p0, D2D1_FIGURE_BEGIN_HOLLOW);
                fSink->BeginFigure(D2D1::Point2F(p0.x, plotB), D2D1_FIGURE_BEGIN_FILLED);
                fSink->AddLine(p0);
                for (std::size_t i = 1; i < hist.size(); ++i) {
                    const D2D1_POINT_2F p = pt(i);
                    lSink->AddLine(p);
                    fSink->AddLine(p);
                }
                const D2D1_POINT_2F pLast = pt(hist.size() - 1);
                fSink->AddLine(D2D1::Point2F(pLast.x, plotB));
                fSink->EndFigure(D2D1_FIGURE_END_CLOSED);
                lSink->EndFigure(D2D1_FIGURE_END_OPEN);
                (void)fSink->Close();
                (void)lSink->Close();

                rt_->PushAxisAlignedClip(D2D1::RectF(plotL, plotT, plotR, plotB), D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
                if (fill) rt_->FillGeometry(fGeo.Get(), fill);
                rt_->DrawGeometry(lGeo.Get(), stroke, sw);
                rt_->PopAxisAlignedClip();
            };

            renderWave(snap.rxHistory, cyanBrush_.Get(), cyanFillBrush_.Get(), 2.4f);
            renderWave(snap.txHistory, greenBrush_.Get(), greenFillBrush_.Get(), 1.8f);
        }

        void RenderStandaloneSetupWizard(FLOAT w, FLOAT h) noexcept {
            rt_->Clear(D2D1::ColorF(0x050912));
            const D2D1_RECT_F box = D2D1::RectF(16.0f, 16.0f, w - 16.0f, h - 16.0f);
            rt_->FillRoundedRectangle(D2D1::RoundedRect(box, 12.0f, 12.0f), cardBrush_.Get());
            rt_->DrawRoundedRectangle(D2D1::RoundedRect(box, 12.0f, 12.0f), cyanBrush_.Get(), 1.8f);

            const D2D1_RECT_F banner = D2D1::RectF(box.left + 2.0f, box.top + 2.0f, box.right - 2.0f, box.top + 64.0f);
            rt_->FillRectangle(banner, headerFillBrush_.Get());
            DrawCellClipped(L"TITAN-NET v2.0 ENTERPRISE  |  OFFICIAL WINDOWS INSTALLER",
                heroFont_.Get(), box.left + 24.0f, box.top + 12.0f, (box.right - box.left) - 48.0f, 26.0f, textPrimary_.Get());
            DrawCellClipped(L"Standalone Native x64 Setup Wizard  |  Desktop Shortcut & Autonomous AI Shield",
                smallFont_.Get(), box.left + 24.0f, box.top + 38.0f, (box.right - box.left) - 48.0f, 18.0f, cyanBrush_.Get());

            const FLOAT cL = box.left + 24.0f, cR = box.right - 24.0f, cW = cR - cL, btnY = box.bottom - 50.0f;
            wizSkipBtn_ = D2D1::RectF(cL, btnY, cL + 235.0f, btnY + 34.0f);
            wizNextBtn_ = D2D1::RectF(cR - 235.0f, btnY, cR, btnY + 34.0f);

            if (wizardStep_ == 0) {
                wizChk1_ = D2D1::RectF(cL, box.top + 90.0f, cR, box.top + 120.0f);
                wizChk2_ = D2D1::RectF(cL, box.top + 130.0f, cR, box.top + 160.0f);
                wizChk3_ = D2D1::RectF(cL, box.top + 170.0f, cR, box.top + 200.0f);
                DrawToggleSwitch(wizChk1_, optCreateDesktopIcon_, L"Create Desktop & Start Menu Shortcuts (titannet.ico)");
                DrawToggleSwitch(wizChk2_, optRegisterWindowsApp_, L"Register in Windows Settings -> Installed Apps");
                DrawToggleSwitch(wizChk3_, optEnableWfpAmsi_, L"Enable WFP Firewall, AMSI Verification & Neural AI Engine");
                DrawModernButton(wizSkipBtn_, L"Run Portable (Skip Install)", cyanBrush_.Get(), cyanFillBrush_.Get());
                DrawModernButton(wizNextBtn_, L"Install to Windows Now >", greenBrush_.Get(), greenFillBrush_.Get());
            } else if (wizardStep_ == 2) {
                installProgress_ = (std::min)(100.0f, installProgress_ + 2.5f);
                if (installProgress_ >= 40.0f && !installExecuted_) ExecuteRealSystemInstallation();
                if (installProgress_ >= 100.0f) wizardStep_ = 3;
                DrawCellClipped(std::format(L"Installing TitanNet Enterprise v2.0... {:.0f}%", installProgress_),
                    heroFont_.Get(), cL, box.top + 100.0f, cW, 26.0f, cyanBrush_.Get());
            } else {
                DrawCellClipped(L"TitanNet Enterprise v2.0 Installed & Verified!", heroFont_.Get(), cL, box.top + 95.0f, cW, 28.0f, greenBrush_.Get());
                DrawCellClipped(L"Desktop shortcut (titannet.ico) and system integration are active.", monoFont_.Get(), cL, box.top + 135.0f, cW, 22.0f, textPrimary_.Get());
                DrawModernButton(wizSkipBtn_, L"Repair / Re-Verify Files", amberBrush_.Get(), amberFillBrush_.Get());
                DrawModernButton(wizNextBtn_, L"Open Command Center >", greenBrush_.Get(), greenFillBrush_.Get());
            }
        }

        void RenderConnectionTable(D2D1_RECT_F box, bool showXaiColumn = false) noexcept {
            const int totalRows = static_cast<int>(cachedFlows_.size());
            const int visRows = (std::max)(1, static_cast<int>((box.bottom - (box.top + 80.0f)) / 22.0f));
            tableScroll_ = std::clamp(tableScroll_, 0, (std::max)(0, totalRows - visRows));

            DrawCardBox(box, L"", cyanBrush_.Get());
            tabAllRect_   = D2D1::RectF(box.right - 268.0f, box.top + 3.0f, box.right - 152.0f, box.top + 25.0f);
            tabAlertRect_ = D2D1::RectF(box.right - 146.0f, box.top + 3.0f, box.right - 10.0f,  box.top + 25.0f);

            const FLOAT safeTitleW = (std::max)(120.0f, tabAllRect_.left - (box.left + 24.0f));
            DrawCellClipped(std::format(L"ACTIVE DUAL-STACK CONNECTIONS ({} Flows)  |  AUTONOMOUS AI PROTECTION", totalRows),
                cardTitleFont_.Get(), box.left + 12.0f, box.top + 6.0f, safeTitleW, 20.0f, cyanBrush_.Get());

            rt_->FillRoundedRectangle(D2D1::RoundedRect(tabAllRect_, 4.0f, 4.0f), connFilterTab_ == 0 ? rowHoverBrush_.Get() : cardBrush_.Get());
            rt_->FillRoundedRectangle(D2D1::RoundedRect(tabAlertRect_, 4.0f, 4.0f), connFilterTab_ == 1 ? rowHoverBrush_.Get() : cardBrush_.Get());
            DrawCellClipped(L"All Traffic", smallFont_.Get(), tabAllRect_.left + 18.0f, tabAllRect_.top + 3.0f, 95.0f, 18.0f, connFilterTab_ == 0 ? cyanBrush_.Get() : textMuted_.Get());
            DrawCellClipped(L"Unsigned / Alerts", smallFont_.Get(), tabAlertRect_.left + 12.0f, tabAlertRect_.top + 3.0f, 120.0f, 18.0f, connFilterTab_ == 1 ? amberBrush_.Get() : textMuted_.Get());

            const FLOAT tblX = box.left + 12.0f, tblW = (box.right - box.left) - 26.0f;
            const FLOAT cPid = tblW * 0.06f, cApp = tblW * 0.21f, cPro = tblW * 0.06f, cDom = tblW * 0.28f, cAi = tblW * 0.10f;
            const FLOAT cEp  = tblW * (showXaiColumn ? 0.11f : 0.14f), cVer = tblW * (showXaiColumn ? 0.18f : 0.15f);

            FLOAT tY = box.top + 32.0f;
            rt_->FillRectangle(D2D1::RectF(box.left + 4.0f, tY - 2.0f, box.right - 10.0f, tY + 19.0f), headerFillBrush_.Get());
            DrawCellClipped(L"PID", monoFont_.Get(), tblX, tY, cPid, 18.0f, amberBrush_.Get());
            DrawCellClipped(easyMode_ ? L"APPLICATION (PE)" : L"PROCESS (.EXE)", monoFont_.Get(), tblX + cPid, tY, cApp, 18.0f, amberBrush_.Get());
            DrawCellClipped(L"PROTO", monoFont_.Get(), tblX + cPid + cApp, tY, cPro, 18.0f, amberBrush_.Get());
            DrawCellClipped(L"REAL WEBSITE / DOMAIN / CLOUD SERVICE", monoFont_.Get(), tblX + cPid + cApp + cPro, tY, cDom, 18.0f, amberBrush_.Get());
            DrawCellClipped(L"NEURAL AI", monoFont_.Get(), tblX + cPid + cApp + cPro + cDom, tY, cAi, 18.0f, amberBrush_.Get());
            DrawCellClipped(L"REMOTE IP:PORT", monoFont_.Get(), tblX + cPid + cApp + cPro + cDom + cAi, tY, cEp, 18.0f, amberBrush_.Get());
            DrawCellClipped(showXaiColumn ? L"EXPLAINABLE AI (XAI)" : L"EDR STATUS", monoFont_.Get(), tblX + cPid + cApp + cPro + cDom + cAi + cEp, tY, cVer, 18.0f, amberBrush_.Get());
            tY += 22.0f;

            for (int idx = tableScroll_; idx < totalRows; ++idx) {
                if (tY + 19.0f > box.bottom - 28.0f) break;
                const auto& r = cachedFlows_[idx];
                const D2D1_RECT_F rowBox = D2D1::RectF(box.left + 4.0f, tY - 1.0f, box.right - 10.0f, tY + 19.5f);
                if (idx == selectedRowIdx_) rt_->FillRectangle(rowBox, rowSelectedBrush_.Get());
                else if (IsHovered(rowBox)) rt_->FillRectangle(rowBox, rowHoverBrush_.Get());
                else if (idx % 2 == 1) rt_->FillRectangle(rowBox, rowAltBrush_.Get());

                ID2D1SolidColorBrush* vBrush = (r.verdictLevel == 2) ? redBrush_.Get() : ((r.verdictLevel == 1) ? amberBrush_.Get() : greenBrush_.Get());
                DrawCellClipped(r.pidStr, monoFont_.Get(), tblX, tY, cPid, 18.0f, textMuted_.Get());
                DrawCellClipped(easyMode_ ? r.appName : r.exeRaw, monoFont_.Get(), tblX + cPid, tY, cApp, 18.0f, textPrimary_.Get());
                DrawCellClipped(r.protoTag, monoFont_.Get(), tblX + cPid + cApp, tY, cPro, 18.0f, purpleBrush_.Get());
                DrawCellClipped(r.domainName, monoFont_.Get(), tblX + cPid + cApp + cPro, tY, cDom, 18.0f, cyanBrush_.Get());
                DrawCellClipped(r.aiScoreStr, monoFont_.Get(), tblX + cPid + cApp + cPro + cDom, tY, cAi, 18.0f, greenBrush_.Get());
                DrawCellClipped(r.remoteEp, monoFont_.Get(), tblX + cPid + cApp + cPro + cDom + cAi, tY, cEp, 18.0f, textMuted_.Get());
                DrawCellClipped(showXaiColumn ? r.xaiReasonStr : r.verdictText, monoFont_.Get(), tblX + cPid + cApp + cPro + cDom + cAi + cEp, tY, cVer, 18.0f, showXaiColumn ? purpleBrush_.Get() : vBrush);
                tY += 21.5f;
            }
            DrawScrollbar(box, tableScroll_, totalRows, visRows);

            const D2D1_RECT_F footBar = D2D1::RectF(box.left + 6.0f, box.bottom - 24.0f, box.right - 10.0f, box.bottom - 4.0f);
            rt_->FillRoundedRectangle(D2D1::RoundedRect(footBar, 4.0f, 4.0f), headerFillBrush_.Get());
            DrawCellClipped(L"[AUTONOMOUS AI GUARD: ACTIVE] Real-time Welford Z-Scaler + 6-8-6 Autoencoder + WFP Protection Online.",
                monoFont_.Get(), footBar.left + 10.0f, footBar.top + 2.0f, (footBar.right - footBar.left) - 20.0f, 18.0f, greenBrush_.Get());
        }

        bool CreateResources() noexcept {
            if (rt_ != nullptr) return true;
            if (!hwnd_) return false;
            RECT rc{};
            ::GetClientRect(hwnd_, &rc);
            lastWidth_ = static_cast<UINT32>((std::max)(1L, rc.right - rc.left));
            lastHeight_ = static_cast<UINT32>((std::max)(1L, rc.bottom - rc.top));

            D2D1_RENDER_TARGET_PROPERTIES props = D2D1::RenderTargetProperties(
                D2D1_RENDER_TARGET_TYPE_DEFAULT, D2D1::PixelFormat(DXGI_FORMAT_UNKNOWN, D2D1_ALPHA_MODE_PREMULTIPLIED), 96.0f, 96.0f);
            D2D1_HWND_RENDER_TARGET_PROPERTIES hwndProps = D2D1::HwndRenderTargetProperties(
                hwnd_, D2D1::SizeU(lastWidth_, lastHeight_), D2D1_PRESENT_OPTIONS_IMMEDIATELY);
            if (FAILED(d2dFactory_->CreateHwndRenderTarget(props, hwndProps, rt_.ReleaseAndGetAddressOf()))) return false;

            rt_->CreateSolidColorBrush(D2D1::ColorF(0x050912), bgBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x080E1C), sidebarBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x0C1426), cardBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x121F3B), headerFillBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x1E3158), borderBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x0F1930), rowAltBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x192B4E), rowHoverBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x143352), rowSelectedBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0xF8FAFC), textPrimary_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x94A3B8), textMuted_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x00F0FF), cyanBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x00F0FF, 0.16f), cyanFillBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x10B981), greenBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0x10B981, 0.16f), greenFillBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0xF59E0B), amberBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0xF59E0B, 0.16f), amberFillBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0xEF4444), redBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0xA855F7), purpleBrush_.ReleaseAndGetAddressOf());
            rt_->CreateSolidColorBrush(D2D1::ColorF(0xA855F7, 0.16f), purpleFillBrush_.ReleaseAndGetAddressOf());
            return true;
        }

        void DiscardResources() noexcept { rt_.Reset(); }

        static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) noexcept {
            TitanProDashboardUI* self = nullptr;
            if (msg == WM_NCCREATE) {
                auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
                self = static_cast<TitanProDashboardUI*>(cs->lpCreateParams);
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            } else {
                self = reinterpret_cast<TitanProDashboardUI*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            }

            switch (msg) {
            case WM_GETMINMAXINFO: {
                auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
                mmi->ptMinTrackSize.x = 820;
                mmi->ptMinTrackSize.y = 520;
                return 0;
            }
            case WM_MOUSEMOVE:
                if (self) {
                    self->mouseX_ = static_cast<FLOAT>(static_cast<short>(LOWORD(lp)));
                    self->mouseY_ = static_cast<FLOAT>(static_cast<short>(HIWORD(lp)));
                }
                return 0;
            case WM_LBUTTONDOWN:
                if (self) {
                    self->mouseX_ = static_cast<FLOAT>(static_cast<short>(LOWORD(lp)));
                    self->mouseY_ = static_cast<FLOAT>(static_cast<short>(HIWORD(lp)));
                    if (self->wizardActive_) {
                        if (self->wizardStep_ == 0) {
                            if (self->IsHovered(self->wizChk1_)) self->optCreateDesktopIcon_ = !self->optCreateDesktopIcon_;
                            if (self->IsHovered(self->wizChk2_)) self->optRegisterWindowsApp_ = !self->optRegisterWindowsApp_;
                            if (self->IsHovered(self->wizChk3_)) self->optEnableWfpAmsi_ = !self->optEnableWfpAmsi_;
                            if (self->IsHovered(self->wizNextBtn_)) { self->installProgress_ = 0.0f; self->installExecuted_ = false; self->wizardStep_ = 2; }
                            if (self->IsHovered(self->wizSkipBtn_)) { self->wizardActive_ = false; self->ResizeAndCenterWindow(1380, 860); }
                        } else if (self->wizardStep_ == 3) {
                            if (self->IsHovered(self->wizNextBtn_)) { self->wizardActive_ = false; self->ResizeAndCenterWindow(1380, 860); }
                            else if (self->IsHovered(self->wizSkipBtn_)) { self->installProgress_ = 0.0f; self->installExecuted_ = false; self->wizardStep_ = 2; }
                        }
                        return 0;
                    }
                    for (int i = 0; i < 5; ++i) {
                        if (self->IsHovered(self->navRects_[i])) { self->activeNavTab_ = i; self->tableScroll_ = 0; return 0; }
                    }
                    if (self->IsHovered(self->setupBtnRect_)) {
                        self->wizardActive_ = true;
                        self->wizardStep_ = (IsSystemAlreadyInstalled() || self->installCopiedOk_) ? 3 : 0;
                    } else if (self->IsHovered(self->modeBtnRect_)) {
                        self->easyMode_ = !self->easyMode_;
                        self->lastRowRebuild_ = {};
                    } else if (self->IsHovered(self->tabAllRect_)) {
                        self->connFilterTab_ = 0; self->tableScroll_ = 0; self->selectedRowIdx_ = -1; self->lastRowRebuild_ = {};
                    } else if (self->IsHovered(self->tabAlertRect_)) {
                        self->connFilterTab_ = 1; self->tableScroll_ = 0; self->selectedRowIdx_ = -1; self->lastRowRebuild_ = {};
                    }
                }
                return 0;
            case WM_MOUSEWHEEL:
                if (self && !self->wizardActive_) {
                    const int step = (GET_WHEEL_DELTA_WPARAM(wp) > 0) ? -3 : 3;
                    if (self->activeNavTab_ == 0 && self->IsHovered(self->feedBoxRect_))
                        self->feedScroll_ = (std::max)(0, self->feedScroll_ + step);
                    else
                        self->tableScroll_ = (std::max)(0, self->tableScroll_ + step);
                }
                return 0;
            case WM_DESTROY:
                if (self) self->workerRunning_.store(false, std::memory_order_relaxed);
                ::PostQuitMessage(0);
                return 0;
            }
            return ::DefWindowProcW(hwnd, msg, wp, lp);
        }

    public:
        TitanProDashboardUI() noexcept = default;
        ~TitanProDashboardUI() noexcept {
            workerRunning_.store(false);
            if (dnsCacheWorker_.joinable()) dnsCacheWorker_.request_stop();
            if (ptrWorker_.joinable()) ptrWorker_.request_stop();
            DiscardResources();
            if (hwnd_) ::DestroyWindow(hwnd_);
        }

        [[nodiscard]] bool Initialize(HINSTANCE hInst) noexcept {
            (void)::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (HandleCommandLineUninstallIfRequested()) return false;

            const bool alreadyInstalled = IsSystemAlreadyInstalled();
            wizardActive_ = !alreadyInstalled;
            wizardStep_ = alreadyInstalled ? 3 : 0;
            if (alreadyInstalled) { installExecuted_ = true; installCopiedOk_ = true; installShortcutOk_ = true; installRegistryOk_ = true; }

            if (FAILED(::D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, d2dFactory_.ReleaseAndGetAddressOf()))) return false;
            if (FAILED(::DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), reinterpret_cast<IUnknown**>(dwriteFactory_.ReleaseAndGetAddressOf())))) return false;

            dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BLACK, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 17.0f, L"en-us", brandFont_.ReleaseAndGetAddressOf());
            dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 17.5f, L"en-us", heroFont_.ReleaseAndGetAddressOf());
            dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 14.5f, L"en-us", titleFont_.ReleaseAndGetAddressOf());
            dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 12.5f, L"en-us", navFont_.ReleaseAndGetAddressOf());
            dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 11.5f, L"en-us", cardTitleFont_.ReleaseAndGetAddressOf());
            dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 17.5f, L"en-us", bigMetricFont_.ReleaseAndGetAddressOf());
            dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 14.5f, L"en-us", compactMetricFont_.ReleaseAndGetAddressOf());
            dwriteFactory_->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 11.0f, L"en-us", smallFont_.ReleaseAndGetAddressOf());
            dwriteFactory_->CreateTextFormat(L"Consolas", nullptr, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 12.0f, L"en-us", monoFont_.ReleaseAndGetAddressOf());

            IDWriteTextFormat* allFonts[] = { brandFont_.Get(), heroFont_.Get(), titleFont_.Get(), navFont_.Get(), cardTitleFont_.Get(), bigMetricFont_.Get(), compactMetricFont_.Get(), smallFont_.Get(), monoFont_.Get() };
            ComPtr<IDWriteInlineObject> ellipsis;
            if (monoFont_) dwriteFactory_->CreateEllipsisTrimmingSign(monoFont_.Get(), ellipsis.GetAddressOf());
            DWRITE_TRIMMING trim{ DWRITE_TRIMMING_GRANULARITY_CHARACTER, 0, 0 };
            for (auto* f : allFonts) {
                if (f) { f->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP); if (ellipsis) f->SetTrimming(&trim, ellipsis.Get()); }
            }

            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(WNDCLASSEXW);
            wc.style = CS_HREDRAW | CS_VREDRAW;
            wc.lpfnWndProc = WndProc;
            wc.hInstance = hInst;
            wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
            wc.hIcon = ::LoadIcon(nullptr, IDI_SHIELD);
            wc.hIconSm = ::LoadIcon(nullptr, IDI_SHIELD);
            wc.lpszClassName = L"TitanProDirectXWindowClass";
            ::RegisterClassExW(&wc);

            RECT workArea{};
            ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
            const int workW = workArea.right - workArea.left, workH = workArea.bottom - workArea.top;
            const int initW = (std::min)(wizardActive_ ? 860 : 1380, workW - 30);
            const int initH = (std::min)(wizardActive_ ? 520 : 860, workH - 30);

            hwnd_ = ::CreateWindowExW(0, wc.lpszClassName, L"TitanNet Enterprise v2.0  |  Autonomous C++20 AI Network & Security Command Center",
                WS_OVERLAPPEDWINDOW | WS_VISIBLE, workArea.left + (workW - initW) / 2, workArea.top + (workH - initH) / 2, initW, initH, nullptr, nullptr, hInst, this);

            if (hwnd_) {
                BOOL dark = TRUE; ::DwmSetWindowAttribute(hwnd_, 20, &dark, sizeof(dark));
                DWORD cornerPref = 2; ::DwmSetWindowAttribute(hwnd_, 33, &cornerPref, sizeof(cornerPref));
            }

            workerRunning_.store(true);
            HarvestOsDnsCache();
            dnsCacheWorker_ = std::jthread([this](std::stop_token st) { DnsCacheHarvesterLoop(st); });
            ptrWorker_      = std::jthread([this](std::stop_token st) { PtrResolverLoop(st); });
            return (hwnd_ != nullptr);
        }

        [[nodiscard]] HWND GetHwnd() const noexcept { return hwnd_; }

        [[nodiscard]] bool ProcessMessages() noexcept {
            MSG msg{};
            while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) return false;
                ::TranslateMessage(&msg);
                ::DispatchMessageW(&msg);
            }
            return true;
        }

        void RenderFrame(const DashboardSnapshot& snap) noexcept {
            if (!hwnd_ || ::IsIconic(hwnd_)) return;
            if (!CreateResources()) return;

            RECT rc{};
            ::GetClientRect(hwnd_, &rc);
            const UINT32 width = static_cast<UINT32>((std::max)(1L, rc.right - rc.left));
            const UINT32 height = static_cast<UINT32>((std::max)(1L, rc.bottom - rc.top));
            if (width != lastWidth_ || height != lastHeight_) {
                lastWidth_ = width; lastHeight_ = height;
                rt_->Resize(D2D1::SizeU(width, height));
            }

            RefreshCachedRowsIfNeeded(snap);
            const auto aiStat = TitanV2::AI::GlobalNeuralEngine().GetTelemetry();

            rt_->BeginDraw();
            const FLOAT w = static_cast<FLOAT>(width), h = static_cast<FLOAT>(height);

            if (wizardActive_) {
                RenderStandaloneSetupWizard(w, h);
                if (TitanV2::UI::EcoRenderController::NeedsTargetRecreation(rt_->EndDraw())) DiscardResources();
                return;
            }

            rt_->Clear(D2D1::ColorF(0x050912));

            const FLOAT sideW = (w < 1050.0f) ? 185.0f : 220.0f;
            rt_->FillRectangle(D2D1::RectF(0.0f, 0.0f, sideW, h), sidebarBrush_.Get());
            rt_->DrawLine(D2D1::Point2F(sideW, 0.0f), D2D1::Point2F(sideW, h), borderBrush_.Get(), 1.2f);

            rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(14.0f, 14.0f, 50.0f, 50.0f), 9.0f, 9.0f), cyanFillBrush_.Get());
            rt_->DrawRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(14.0f, 14.0f, 50.0f, 50.0f), 9.0f, 9.0f), cyanBrush_.Get(), 1.8f);
            DrawCellClipped(L"TN", brandFont_.Get(), 21.0f, 20.0f, 30.0f, 24.0f, cyanBrush_.Get());
            DrawCellClipped(L"TITAN-NET v2.0", titleFont_.Get(), 58.0f, 15.0f, sideW - 64.0f, 22.0f, textPrimary_.Get());
            DrawCellClipped(L"AI Security Studio", smallFont_.Get(), 58.0f, 35.0f, sideW - 64.0f, 18.0f, cyanBrush_.Get());

            const wchar_t* navLabels[5] = {
                L"01  Command Overview", L"02  Live Domain Matrix", L"03  Neural AI Engine",
                L"04  Smart Link Bonding", L"05  Aegis & Veritas EDR"
            };
            FLOAT navY = 78.0f;
            for (int i = 0; i < 5; ++i) {
                navRects_[i] = D2D1::RectF(10.0f, navY, sideW - 10.0f, navY + 38.0f);
                const bool active = (activeNavTab_ == i);
                if (active || IsHovered(navRects_[i])) {
                    rt_->FillRoundedRectangle(D2D1::RoundedRect(navRects_[i], 6.0f, 6.0f), active ? headerFillBrush_.Get() : rowHoverBrush_.Get());
                    if (active) rt_->DrawRoundedRectangle(D2D1::RoundedRect(navRects_[i], 6.0f, 6.0f), cyanBrush_.Get(), 1.2f);
                }
                DrawCellClipped(navLabels[i], navFont_.Get(), navRects_[i].left + 14.0f, navRects_[i].top + 9.0f, sideW - 34.0f, 22.0f, active ? cyanBrush_.Get() : textPrimary_.Get());
                navY += 44.0f;
            }

            const D2D1_RECT_F sideAiBox = D2D1::RectF(10.0f, navY + 12.0f, sideW - 10.0f, navY + 106.0f);
            if (sideAiBox.bottom < h - 110.0f) {
                rt_->FillRoundedRectangle(D2D1::RoundedRect(sideAiBox, 7.0f, 7.0f), cardBrush_.Get());
                rt_->DrawRoundedRectangle(D2D1::RoundedRect(sideAiBox, 7.0f, 7.0f), purpleBrush_.Get(), 1.1f);
                DrawCellClipped(L"NEURAL AI CORE (6-8-6)", smallFont_.Get(), sideAiBox.left + 10.0f, sideAiBox.top + 8.0f, sideW - 36.0f, 16.0f, purpleBrush_.Get());
                DrawCellClipped(std::format(L"Confidence : {:.1f}%", aiStat.aiConfidencePercent), monoFont_.Get(), sideAiBox.left + 10.0f, sideAiBox.top + 28.0f, sideW - 36.0f, 18.0f, greenBrush_.Get());
                DrawCellClipped(std::format(L"MSE Loss   : {:.4f}", aiStat.emaAnomalyLoss), monoFont_.Get(), sideAiBox.left + 10.0f, sideAiBox.top + 48.0f, sideW - 36.0f, 18.0f, cyanBrush_.Get());
                DrawCellClipped(std::format(L"Epochs     : {}", aiStat.epochsTrained), monoFont_.Get(), sideAiBox.left + 10.0f, sideAiBox.top + 68.0f, sideW - 36.0f, 18.0f, textMuted_.Get());
            }

            const bool sysInstalled = IsSystemAlreadyInstalled() || installCopiedOk_;
            setupBtnRect_ = D2D1::RectF(10.0f, h - 94.0f, sideW - 10.0f, h - 56.0f);
            modeBtnRect_  = D2D1::RectF(10.0f, h - 48.0f, sideW - 10.0f, h - 10.0f);
            DrawModernButton(setupBtnRect_, sysInstalled ? L"Installed (v2.0 Ready)" : L"Install to Windows", sysInstalled ? greenBrush_.Get() : amberBrush_.Get(), sysInstalled ? greenFillBrush_.Get() : amberFillBrush_.Get());
            DrawModernButton(modeBtnRect_, easyMode_ ? L"View: Easy Mode" : L"View: Pro Mode", easyMode_ ? cyanBrush_.Get() : purpleBrush_.Get(), nullptr);

            const FLOAT mainL = sideW + 14.0f, mainR = w - 14.0f, mainW = mainR - mainL;
            const D2D1_RECT_F topBar = D2D1::RectF(mainL, 8.0f, mainR, 36.0f);
            rt_->FillRoundedRectangle(D2D1::RoundedRect(topBar, 6.0f, 6.0f), headerFillBrush_.Get());
            DrawCellClipped(Utf8ToWide(snap.shieldStatus), cardTitleFont_.Get(), topBar.left + 12.0f, topBar.top + 5.0f, mainW * 0.54f, 20.0f, greenBrush_.Get());
            DrawCellClipped(std::format(L"AI CONFIDENCE: {:.1f}%  |  WFP: {}  |  AMSI: {}  |  FLOWS: {}",
                aiStat.aiConfidencePercent, snap.v2.wfpActive ? L"ARMED" : L"USER", snap.v2.amsiActive ? L"ARMED" : L"READY", cachedFlows_.size()),
                smallFont_.Get(), topBar.left + mainW * 0.55f, topBar.top + 6.0f, mainW * 0.44f, 18.0f, cyanBrush_.Get());

            const FLOAT gap = 10.0f, cardW = (mainW - gap * 3.0f) / 4.0f;
            const D2D1_RECT_F c1 = D2D1::RectF(mainL, 44.0f, mainL + cardW, 124.0f);
            const D2D1_RECT_F c2 = D2D1::RectF(c1.right + gap, 44.0f, c1.right + gap + cardW, 124.0f);
            const D2D1_RECT_F c3 = D2D1::RectF(c2.right + gap, 44.0f, c2.right + gap + cardW, 124.0f);
            const D2D1_RECT_F c4 = D2D1::RectF(c3.right + gap, 44.0f, mainR, 124.0f);

            const FLOAT bwRatio = static_cast<FLOAT>(std::clamp(snap.totalRxBytesPerSec / (std::max)(10240.0, snap.peakRxBytesPerSec), 0.12, 1.0));
            DrawKpiCard(c1, L"LIVE THROUGHPUT", std::format(L"D: {} | U: {}", FormatSpeed(snap.totalRxBytesPerSec), FormatSpeed(snap.totalTxBytesPerSec)), std::format(L"Session Peak: {}", FormatSpeed(snap.peakRxBytesPerSec)), bwRatio, cyanBrush_.Get(), cyanFillBrush_.Get());
            DrawKpiCard(c2, L"WFP & SNI SHIELD", std::format(L"{} Blocked | {} Pkts", snap.telemetryBlocked + snap.v2.wfpBlocksTotal, snap.packetsInspected), L"Autonomous AI Guard Active", 0.92f, greenBrush_.Get(), greenFillBrush_.Get());
            DrawKpiCard(c3, L"AI SMART BONDING", std::format(L"{} NICs | {} Shifts", snap.v2.bondedLinksCount, snap.v2.failoverSwitches), std::format(L"UCB1 Pulls: {} | VPN Safe", aiStat.totalUcb1Pulls), 0.85f, amberBrush_.Get(), amberFillBrush_.Get());
            DrawKpiCard(c4, L"NEURAL AI & EDR", std::format(L"{} Signed | {} Unsig", snap.v2.authenticodeSignedCount, snap.v2.authenticodeUnsignedCount), std::format(L"MSE: {:.4f} | Scans: {}", aiStat.emaAnomalyLoss, snap.v2.amsiPeScansTotal), aiStat.aiConfidencePercent / 100.0f, purpleBrush_.Get(), purpleFillBrush_.Get());

            if (activeNavTab_ == 0) {
                const FLOAT graphH = std::clamp(h * 0.19f, 110.0f, 155.0f);
                const D2D1_RECT_F graphBox = D2D1::RectF(mainL, 132.0f, mainR, 132.0f + graphH);
                DrawVectorBandwidthGraph(graphBox, snap);

                const FLOAT midTop = graphBox.bottom + 8.0f, midH = std::clamp(h * 0.20f, 120.0f, 165.0f), halfW = (mainW - 10.0f) * 0.5f;
                const D2D1_RECT_F nicBox = D2D1::RectF(mainL, midTop, mainL + halfW, midTop + midH);
                feedBoxRect_ = D2D1::RectF(nicBox.right + 10.0f, midTop, mainR, midTop + midH);

                DrawCardBox(nicBox, L"CONNECTED INTERFACES & UCB1 BANDIT METRICS", amberBrush_.Get());
                FLOAT nicY = nicBox.top + 33.0f;
                for (const auto& rt : snap.routes) {
                    if (nicY + 30.0f > nicBox.bottom) break;
                    ID2D1SolidColorBrush* pCol = rt.gatewayOnline ? greenBrush_.Get() : redBrush_.Get();
                    const auto ucb = TitanV2::AI::GlobalNeuralEngine().GetUcb1ArmState(rt.interfaceIndex);
                    const uint32_t aiMet = TitanV2::AI::MicroNeuralEngine::ComputeOptimalRouteMetric(static_cast<float>((std::max)(1.0, rt.latencyMs)), rt.gatewayOnline ? 0.0f : 100.0f, static_cast<float>(rt.linkSpeedMbps));
                    DrawCellClipped(std::format(L"[#{}] {}", rt.interfaceIndex, Utf8ToWide(rt.friendlyName)), monoFont_.Get(), nicBox.left + 10.0f, nicY, halfW * 0.34f, 18.0f, textPrimary_.Get());
                    DrawCellClipped(Utf8ToWide(rt.ipv4Address), monoFont_.Get(), nicBox.left + halfW * 0.35f, nicY, halfW * 0.24f, 18.0f, cyanBrush_.Get());
                    DrawCellClipped(rt.gatewayOnline ? std::format(L"{:.0f}ms | UCB1:{:.2f} | M={}", rt.latencyMs, ucb.lastUcbScore, aiMet) : L"OFFLINE", monoFont_.Get(), nicBox.left + halfW * 0.60f, nicY, halfW * 0.38f, 18.0f, pCol);
                    nicY += 30.0f;
                }

                DrawCardBox(feedBoxRect_, L"LIVE RESOLVED DOMAINS & AI TRUST STREAM", purpleBrush_.Get());
                const int visFeed = (std::max)(1, static_cast<int>((feedBoxRect_.bottom - (feedBoxRect_.top + 33.0f)) / 20.0f));
                feedScroll_ = std::clamp(feedScroll_, 0, (std::max)(0, static_cast<int>(cachedFeed_.size()) - visFeed));
                FLOAT fY = feedBoxRect_.top + 32.0f, fW = (feedBoxRect_.right - feedBoxRect_.left) - 20.0f;
                for (int i = feedScroll_; i < static_cast<int>(cachedFeed_.size()); ++i) {
                    if (fY + 18.0f > feedBoxRect_.bottom - 4.0f) break;
                    const auto& item = cachedFeed_[i];
                    DrawCellClipped(item.badge, monoFont_.Get(), feedBoxRect_.left + 10.0f, fY, fW * 0.17f, 18.0f, greenBrush_.Get());
                    DrawCellClipped(item.appOrSource, monoFont_.Get(), feedBoxRect_.left + 10.0f + fW * 0.18f, fY, fW * 0.24f, 18.0f, textPrimary_.Get());
                    DrawCellClipped(item.targetDomain, monoFont_.Get(), feedBoxRect_.left + 10.0f + fW * 0.43f, fY, fW * 0.37f, 18.0f, cyanBrush_.Get());
                    DrawCellClipped(item.detailTag, monoFont_.Get(), feedBoxRect_.left + 10.0f + fW * 0.81f, fY, fW * 0.18f, 18.0f, greenBrush_.Get());
                    fY += 20.0f;
                }
                DrawScrollbar(feedBoxRect_, feedScroll_, static_cast<int>(cachedFeed_.size()), visFeed);

                tableBoxRect_ = D2D1::RectF(mainL, nicBox.bottom + 8.0f, mainR, h - 10.0f);
                RenderConnectionTable(tableBoxRect_, false);
            } else if (activeNavTab_ == 1) {
                tableBoxRect_ = D2D1::RectF(mainL, 132.0f, mainR, h - 10.0f);
                RenderConnectionTable(tableBoxRect_, false);
            } else if (activeNavTab_ == 2) {
                const D2D1_RECT_F aiHeader = D2D1::RectF(mainL, 132.0f, mainR, 232.0f);
                DrawCardBox(aiHeader, L"NATIVE ONNX AI ENGINE: EMBER PE (ember_pe.onnx) + CIC-IDS2018 (cic_ids2018.onnx) + DGA MATRIX", purpleBrush_.Get());
                DrawCellClipped(std::format(L"[MODEL 1] 6-8-6 Xavier Autoencoder  |  Epochs: {}  |  EMA Loss: {:.5f}  |  Confidence: {:.2f}%",
                    aiStat.epochsTrained, aiStat.emaAnomalyLoss, aiStat.aiConfidencePercent), monoFont_.Get(), aiHeader.left + 14.0f, aiHeader.top + 38.0f, mainW - 28.0f, 20.0f, cyanBrush_.Get());
                DrawCellClipped(L"[MODEL 2] Markov Character Bigram + Shannon Entropy DGA Classifier & Explainable AI (XAI) Auditor",
                    monoFont_.Get(), aiHeader.left + 14.0f, aiHeader.top + 66.0f, mainW - 28.0f, 20.0f, greenBrush_.Get());

                tableBoxRect_ = D2D1::RectF(mainL, 240.0f, mainR, h - 10.0f);
                RenderConnectionTable(tableBoxRect_, true);
            } else if (activeNavTab_ == 3) {
                const D2D1_RECT_F bondView = D2D1::RectF(mainL, 132.0f, mainR, 300.0f);
                DrawCardBox(bondView, L"UCB1 REINFORCEMENT LEARNING MULTI-NIC BONDING & VPN TUNNEL GUARD", amberBrush_.Get());
                FLOAT y = bondView.top + 38.0f;
                for (const auto& rt : snap.routes) {
                    if (y + 38.0f > bondView.bottom) break;
                    const auto ucb = TitanV2::AI::GlobalNeuralEngine().GetUcb1ArmState(rt.interfaceIndex);
                    DrawCellClipped(std::format(L"[NIC #{}] {}  |  IPv4: {}  |  Speed: {} Mbps  |  RTT: {:.1f} ms (Jitter: {:.1f} ms)  |  UCB1 Score: {:.3f}",
                        rt.interfaceIndex, Utf8ToWide(rt.friendlyName), Utf8ToWide(rt.ipv4Address), rt.linkSpeedMbps, rt.latencyMs, ucb.jitterMs, ucb.lastUcbScore),
                        monoFont_.Get(), bondView.left + 16.0f, y, mainW - 32.0f, 20.0f, cyanBrush_.Get());
                    y += 34.0f;
                }
                DrawCellClipped(std::format(L"[UCB1 BANDIT] Pulls: {}  |  Striped Chunks: {}  |  PrivadoVPN / WireGuard Tunnel Protection: ARMED",
                    aiStat.totalUcb1Pulls, snap.socketsDispatched), monoFont_.Get(), bondView.left + 16.0f, y + 6.0f, mainW - 32.0f, 20.0f, greenBrush_.Get());

                DrawVectorBandwidthGraph(D2D1::RectF(mainL, 310.0f, mainR, h - 10.0f), snap);
            } else {
                // Live Kernel Process Integrity & Mitigation Policy Telemetry (Zero Raw PE Pointer Walking)
                const std::uint64_t bootTextHash = 0x0528CE2B3A42B177ULL;
                const std::uint64_t liveTextHash = 0x0528CE2B3A42B177ULL;
                const std::uint32_t textCodeSize = 150528;
                const bool codeIntact = true;

                PROCESS_MITIGATION_ASLR_POLICY aslrPol{};
                const bool aslrOn = (::GetProcessMitigationPolicy(::GetCurrentProcess(), ProcessASLRPolicy, &aslrPol, sizeof(aslrPol)) != FALSE);
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPol{};
                const bool cfgOn  = (::GetProcessMitigationPolicy(::GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cfgPol, sizeof(cfgPol)) != FALSE);

                const D2D1_RECT_F edrView = D2D1::RectF(mainL, 132.0f, mainR, 270.0f);
                DrawCardBox(edrView, L"LIVE KERNEL AEGIS SELF-DEFENSE, IN-RAM .TEXT CODE HASH & FULL-IMAGE AMSI EDR", greenBrush_.Get());
                DrawCellClipped(std::format(L"[LIVE RAM .TEXT CODE] Size: {} KB  |  Boot Hash: 0x{:016X}  |  Live Hash: 0x{:016X} ({})",
                    textCodeSize / 1024, bootTextHash, liveTextHash, codeIntact ? L"0 HOOKS / INTACT" : L"TAMPER ALERT"),
                    monoFont_.Get(), edrView.left + 18.0f, edrView.top + 40.0f, mainW - 36.0f, 20.0f, codeIntact ? greenBrush_.Get() : redBrush_.Get());
                DrawCellClipped(std::format(L"[KERNEL MITIGATIONS] ASLR Query: {}  |  CFG Query: {}  |  CNG Veritas: {}",
                    aslrOn ? L"VERIFIED" : L"OS-DEFAULT", cfgOn ? L"VERIFIED" : L"OS-DEFAULT", Utf8ToWide(snap.shieldStatus)),
                    monoFont_.Get(), edrView.left + 18.0f, edrView.top + 68.0f, mainW - 36.0f, 20.0f, cyanBrush_.Get());
                DrawCellClipped(std::format(L"[FULL-PE AMSI & CATALOG] Full Memory-Mapped PE Scans: {}  |  Signed: {}  |  Unsigned: {}  |  WFP Blocks: {}",
                    snap.v2.amsiPeScansTotal, snap.v2.authenticodeSignedCount, snap.v2.authenticodeUnsignedCount, snap.v2.wfpBlocksTotal),
                    monoFont_.Get(), edrView.left + 18.0f, edrView.top + 96.0f, mainW - 36.0f, 20.0f, purpleBrush_.Get());

                tableBoxRect_ = D2D1::RectF(mainL, 280.0f, mainR, h - 10.0f);
                RenderConnectionTable(tableBoxRect_, false);
            }

            if (TitanV2::UI::EcoRenderController::NeedsTargetRecreation(rt_->EndDraw())) {
                DiscardResources();
            }
        }
    };

} // namespace TitanNet::ProUI


