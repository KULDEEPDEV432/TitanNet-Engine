#pragma once
#include "TitanSafety.hpp"
#include "TitanLogger.hpp"
#include <shellapi.h>
#include <string>

namespace TitanV2::UI {
    class HardenedInstaller {
    public:
        // Fixes Bug #7: Protected DACL SDDL allowing ONLY LocalSystem (SY) and Built-in Admins (BA)
        static constexpr const wchar_t* GetHardenedTaskSDDL() noexcept {
            return L"D:P(A;;FA;;;BA)(A;;FA;;;SY)";
        }

        // Fixes Bug #24: Atomic Rename & Overwrite so updating a running .exe never fails with Access Denied
        static bool SafeUpdateRunningBinary(const std::wstring& srcExe, const std::wstring& dstExe) noexcept {
            std::wstring oldBackup = dstExe + L".old";
            ::DeleteFileW(oldBackup.c_str());

            if (::GetFileAttributesW(dstExe.c_str()) != INVALID_FILE_ATTRIBUTES) {
                // Rename currently locked/running binary to .old
                if (::MoveFileExW(dstExe.c_str(), oldBackup.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                    ::MoveFileExW(oldBackup.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
                }
            }

            if (::CopyFileW(srcExe.c_str(), dstExe.c_str(), FALSE)) {
                TitanV2::Core::Logger::Write("INSTALLER", "Binary updated safely via atomic MoveFileExW.");
                return true;
            }
            return false;
        }

        // Fixes Bug #25: Detached Self-Cleanup Worker to remove running .exe & folder after --uninstall exits
        static void LaunchDeferredSelfDelete(const std::wstring& exePath, const std::wstring& installFolder) noexcept {
            if (exePath.empty()) return;
            std::wstring cmd = L"cmd.exe /C timeout /t 2 /nobreak > NUL & del /f /q \"" + exePath + L"\"";
            if (!installFolder.empty()) {
                cmd += L" & rmdir /s /q \"" + installFolder + L"\"";
            }

            STARTUPINFOW si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};

            std::wstring mutableCmd = cmd;
            if (::CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                                 CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi)) {
                ::CloseHandle(pi.hThread);
                ::CloseHandle(pi.hProcess);
                TitanV2::Core::Logger::Write("UNINSTALLER", "Deferred self-delete scheduled cleanly.");
            }
        }
    };
}
