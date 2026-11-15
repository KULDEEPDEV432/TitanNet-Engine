#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>

namespace TitanV2::Core {
    class SingleInstanceGuard {
        HANDLE hMutex_ = nullptr;
        bool alreadyRunning_ = false;
    public:
        explicit SingleInstanceGuard(const wchar_t* name = L"Local\\TitanNet_v2_UI_Mutex") noexcept {
            hMutex_ = ::CreateMutexW(nullptr, FALSE, name);
            DWORD err = ::GetLastError();
            alreadyRunning_ = (hMutex_ != nullptr && err == ERROR_ALREADY_EXISTS);
        }
        bool IsAlreadyRunning() const noexcept {
            return alreadyRunning_;
        }
        ~SingleInstanceGuard() noexcept {
            if (hMutex_) ::CloseHandle(hMutex_);
        }
    };

    class ScopedIcon {
        HICON hIcon_ = nullptr;
    public:
        explicit ScopedIcon(HICON h = nullptr) noexcept : hIcon_(h) {}
        ~ScopedIcon() noexcept { if (hIcon_) ::DestroyIcon(hIcon_); }
        ScopedIcon(const ScopedIcon&) = delete;
        ScopedIcon& operator=(const ScopedIcon&) = delete;
        HICON get() const noexcept { return hIcon_; }
    };

    template <typename Func>
    inline bool SafeExecuteSEH(Func&& fn, DWORD* outExceptionCode = nullptr) noexcept {
        __try {
            fn();
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (outExceptionCode) *outExceptionCode = GetExceptionCode();
            return false;
        }
    }
}
