#pragma once

// ============================================================================
// TitanBrandAdmin.hpp - Single Desktop Icon + Zero-UAC Admin Task Launcher
// Fixes:
//   1. Removes duplicate Public Desktop shortcut (Leaves only 1 Desktop Icon)
//   2. Links Desktop Shortcut to Windows Task Scheduler (0 UAC Popup on click)
//   3. Applies N:\TitanNet\TitanNet\titannet.ico to Shortcut, Taskbar & App
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <oleauto.h>
#include <taskschd.h>
#include <wrl/client.h>

#include <string>
#include <chrono>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "taskschd.lib")

namespace TitanNet::Brand {

    using Microsoft::WRL::ComPtr;

    inline constexpr const wchar_t* kDevIconPath = L"N:\\TitanNet\\TitanNet\\titannet.ico";
    inline constexpr const wchar_t* kInstallDir = L"C:\\Program Files\\TitanNet Enterprise";
    inline constexpr const wchar_t* kInstalledExe = L"C:\\Program Files\\TitanNet Enterprise\\TitanNet.exe";
    inline constexpr const wchar_t* kInstalledIcon = L"C:\\Program Files\\TitanNet Enterprise\\titannet.ico";
    inline constexpr const wchar_t* kAdminTaskName = L"TitanNetEnterprise_AdminLaunch";
    inline constexpr const wchar_t* kUninstallRegKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TitanNetEnterprise";

    struct ScopedBstr final {
        BSTR ptr{ nullptr };
        explicit ScopedBstr(const wchar_t* str) noexcept : ptr(::SysAllocString(str)) {}
        ~ScopedBstr() noexcept { if (ptr) ::SysFreeString(ptr); }
        ScopedBstr(const ScopedBstr&) = delete;
        ScopedBstr& operator=(const ScopedBstr&) = delete;
        operator BSTR() const noexcept { return ptr; }
    };

    [[nodiscard]] inline bool IsProcessElevated() noexcept {
        HANDLE hToken = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return false;
        }
        TOKEN_ELEVATION elev{};
        DWORD retLen = 0;
        const BOOL ok = ::GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &retLen);
        ::CloseHandle(hToken);
        return (ok && elev.TokenIsElevated != 0);
    }

    [[nodiscard]] inline bool FileExistsOnDisk(const wchar_t* path) noexcept {
        if (!path || path[0] == L'\0') return false;
        const DWORD attr = ::GetFileAttributesW(path);
        return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
    }

    [[nodiscard]] inline const wchar_t* ResolveActiveIconPath() noexcept {
        if (FileExistsOnDisk(kInstalledIcon)) return kInstalledIcon;
        if (FileExistsOnDisk(kDevIconPath))   return kDevIconPath;
        return nullptr;
    }

    // Registers an On-Demand Highest-Privilege Task with Interactive User SDDL permissions
    inline bool RegisterZeroUacAdminTask(const wchar_t* targetExePath) noexcept {
        if (!targetExePath || targetExePath[0] == L'\0') return false;

        ComPtr<ITaskService> service;
        if (FAILED(::CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(service.GetAddressOf()))) || !service) {
            return false;
        }

        VARIANT empty{};
        ::VariantInit(&empty);
        if (FAILED(service->Connect(empty, empty, empty, empty))) {
            return false;
        }

        ComPtr<ITaskFolder> rootFolder;
        if (FAILED(service->GetFolder(ScopedBstr(L"\\"), rootFolder.GetAddressOf())) || !rootFolder) {
            return false;
        }

        ComPtr<ITaskDefinition> taskDef;
        if (FAILED(service->NewTask(0, taskDef.GetAddressOf())) || !taskDef) {
            return false;
        }

        ComPtr<IPrincipal> principal;
        if (SUCCEEDED(taskDef->get_Principal(principal.GetAddressOf())) && principal) {
            principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST); // Full Administrator
            principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        }

        ComPtr<ITaskSettings> settings;
        if (SUCCEEDED(taskDef->get_Settings(settings.GetAddressOf())) && settings) {
            settings->put_AllowDemandStart(VARIANT_TRUE);
            settings->put_StartWhenAvailable(VARIANT_TRUE);
            settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
            settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
            settings->put_ExecutionTimeLimit(ScopedBstr(L"PT0S"));
            settings->put_MultipleInstances(TASK_INSTANCES_PARALLEL);
        }

        ComPtr<IActionCollection> actions;
        if (FAILED(taskDef->get_Actions(actions.GetAddressOf())) || !actions) {
            return false;
        }

        ComPtr<IAction> action;
        if (FAILED(actions->Create(TASK_ACTION_EXEC, action.GetAddressOf())) || !action) {
            return false;
        }

        ComPtr<IExecAction> execAction;
        if (FAILED(action.As(&execAction)) || !execAction) {
            return false;
        }

        execAction->put_Path(ScopedBstr(targetExePath));

        std::wstring workDir(targetExePath);
        const auto slashPos = workDir.find_last_of(L"\\/");
        if (slashPos != std::wstring::npos) {
            workDir = workDir.substr(0, slashPos);
            execAction->put_WorkingDirectory(ScopedBstr(workDir.c_str()));
        }

        // Grant Interactive Users (IU) & Authenticated Users (AU) permission to trigger task without UAC
        VARIANT sddlVar{};
        sddlVar.vt = VT_BSTR;
        sddlVar.bstrVal = ::SysAllocString(L"D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;IU)(A;;FA;;;AU)");

        ComPtr<IRegisteredTask> regTask;
        HRESULT hr = rootFolder->RegisterTaskDefinition(
            ScopedBstr(kAdminTaskName),
            taskDef.Get(),
            TASK_CREATE_OR_UPDATE,
            empty,
            empty,
            TASK_LOGON_INTERACTIVE_TOKEN,
            sddlVar,
            regTask.GetAddressOf()
        );
        ::SysFreeString(sddlVar.bstrVal);

        if (FAILED(hr)) {
            hr = rootFolder->RegisterTaskDefinition(
                ScopedBstr(kAdminTaskName),
                taskDef.Get(),
                TASK_CREATE_OR_UPDATE,
                empty,
                empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                empty,
                regTask.GetAddressOf()
            );
        }
        return SUCCEEDED(hr);
    }

    [[nodiscard]] inline bool DoesZeroUacAdminTaskExist() noexcept {
        ComPtr<ITaskService> service;
        if (FAILED(::CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(service.GetAddressOf()))) || !service) {
            return false;
        }
        VARIANT empty{};
        ::VariantInit(&empty);
        if (FAILED(service->Connect(empty, empty, empty, empty))) return false;

        ComPtr<ITaskFolder> rootFolder;
        if (FAILED(service->GetFolder(ScopedBstr(L"\\"), rootFolder.GetAddressOf())) || !rootFolder) return false;

        ComPtr<IRegisteredTask> regTask;
        return SUCCEEDED(rootFolder->GetTask(ScopedBstr(kAdminTaskName), regTask.GetAddressOf()));
    }

    [[nodiscard]] inline bool TriggerZeroUacAdminTask() noexcept {
        ComPtr<ITaskService> service;
        if (FAILED(::CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(service.GetAddressOf()))) || !service) {
            return false;
        }

        VARIANT empty{};
        ::VariantInit(&empty);
        if (FAILED(service->Connect(empty, empty, empty, empty))) return false;

        ComPtr<ITaskFolder> rootFolder;
        if (FAILED(service->GetFolder(ScopedBstr(L"\\"), rootFolder.GetAddressOf())) || !rootFolder) return false;

        ComPtr<IRegisteredTask> regTask;
        if (FAILED(rootFolder->GetTask(ScopedBstr(kAdminTaskName), regTask.GetAddressOf())) || !regTask) return false;

        ComPtr<IRunningTask> runningTask;
        return SUCCEEDED(regTask->Run(empty, runningTask.GetAddressOf()));
    }

    inline void RemoveZeroUacAdminTask() noexcept {
        ComPtr<ITaskService> service;
        if (SUCCEEDED(::CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(service.GetAddressOf()))) && service) {
            VARIANT empty{};
            ::VariantInit(&empty);
            if (SUCCEEDED(service->Connect(empty, empty, empty, empty))) {
                ComPtr<ITaskFolder> rootFolder;
                if (SUCCEEDED(service->GetFolder(ScopedBstr(L"\\"), rootFolder.GetAddressOf())) && rootFolder) {
                    (void)rootFolder->DeleteTask(ScopedBstr(kAdminTaskName), 0);
                }
            }
        }
    }

    // Removes the duplicate Public Desktop shortcut so only 1 icon stays on the Desktop
    inline bool RemoveDuplicatePublicDesktopShortcut() noexcept {
        wchar_t pubDesktop[MAX_PATH]{};
        if (SUCCEEDED(::SHGetFolderPathW(nullptr, CSIDL_COMMON_DESKTOPDIRECTORY, nullptr, 0, pubDesktop))) {
            const std::wstring pubLnk = std::wstring(pubDesktop) + L"\\TitanNet Enterprise.lnk";
            if (FileExistsOnDisk(pubLnk.c_str())) {
                ::DeleteFileW(pubLnk.c_str());
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] inline bool EnsureSilentAdministratorLaunch() noexcept {
        (void)::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        const std::wstring cmdLine = ::GetCommandLineW();
        if (cmdLine.find(L"--uninstall") != std::wstring::npos) {
            RemoveZeroUacAdminTask();
            RemoveDuplicatePublicDesktopShortcut();
            ::DeleteFileW(kInstalledIcon);
            return false;
        }

        wchar_t selfExe[MAX_PATH]{};
        ::GetModuleFileNameW(nullptr, selfExe, MAX_PATH);
        const wchar_t* targetExe = FileExistsOnDisk(kInstalledExe) ? kInstalledExe : selfExe;

        if (IsProcessElevated()) {
            (void)RegisterZeroUacAdminTask(targetExe);
            return false;
        }

        if (TriggerZeroUacAdminTask()) {
            return true;
        }

        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(SHELLEXECUTEINFOW);
        sei.lpVerb = L"runas";
        sei.lpFile = selfExe;
        sei.nShow = SW_SHOWNORMAL;
        if (::ShellExecuteExW(&sei)) {
            return true;
        }
        return false;
    }

    inline void ApplyWindowAndTaskbarIcon() noexcept {
        HWND hwnd = ::FindWindowW(L"TitanProDirectXWindowClass", nullptr);
        if (!hwnd) return;

        // Ensure window is visible and brought to front when started via Task Scheduler
        ::ShowWindow(hwnd, SW_SHOWNORMAL);
        ::SetForegroundWindow(hwnd);

        const wchar_t* iconFile = ResolveActiveIconPath();
        if (!iconFile) return;

        auto hBigIcon = static_cast<HICON>(::LoadImageW(
            nullptr, iconFile, IMAGE_ICON, 32, 32, LR_LOADFROMFILE
        ));
        auto hSmallIcon = static_cast<HICON>(::LoadImageW(
            nullptr, iconFile, IMAGE_ICON, 16, 16, LR_LOADFROMFILE
        ));

        if (hBigIcon) {
            ::SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hBigIcon));
            ::SetClassLongPtrW(hwnd, GCLP_HICON, reinterpret_cast<LONG_PTR>(hBigIcon));
        }
        if (hSmallIcon) {
            ::SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hSmallIcon));
            ::SetClassLongPtrW(hwnd, GCLP_HICONSM, reinterpret_cast<LONG_PTR>(hSmallIcon));
        }
    }

    // Creates a Zero-UAC Shortcut using schtasks.exe (bypasses Explorer's requireAdministrator check)
    inline bool CreateZeroUacAdminShortcut(
        const wchar_t* lnkPath,
        const wchar_t* iconPath,
        bool useZeroUacTask) noexcept {

        ComPtr<IShellLinkW> shellLink;
        if (FAILED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(shellLink.GetAddressOf()))) || !shellLink) {
            return false;
        }

        if (useZeroUacTask) {
            // Point shortcut to Windows schtasks.exe (asInvoker -> 0 UAC popup!)
            shellLink->SetPath(L"C:\\Windows\\System32\\schtasks.exe");
            shellLink->SetArguments(L"/run /tn \"TitanNetEnterprise_AdminLaunch\"");
            shellLink->SetShowCmd(SW_SHOWMINNOACTIVE); // Hides brief schtasks console window
        }
        else {
            shellLink->SetPath(kInstalledExe);
            shellLink->SetShowCmd(SW_SHOWNORMAL);
        }

        shellLink->SetWorkingDirectory(kInstallDir);
        shellLink->SetDescription(L"TitanNet Enterprise v1.0 - Direct Administrator Launch");
        if (iconPath && iconPath[0] != L'\0') {
            shellLink->SetIconLocation(iconPath, 0);
        }

        ComPtr<IPersistFile> persistFile;
        if (FAILED(shellLink.As(&persistFile)) || !persistFile) {
            return false;
        }
        return SUCCEEDED(persistFile->Save(lnkPath, TRUE));
    }

    inline void SyncInstallerBrandingAndAdminTask() noexcept {
        static auto lastCheck = std::chrono::steady_clock::now() - std::chrono::seconds(10);
        static bool syncedThisSession = false;

        const auto now = std::chrono::steady_clock::now();
        if (now - lastCheck < std::chrono::milliseconds(800)) {
            return;
        }
        lastCheck = now;

        if (!FileExistsOnDisk(kInstalledExe)) {
            return;
        }

        // 1. Always delete the duplicate Public Desktop shortcut if TitanProUI.hpp created it
        const bool hadDuplicateIcon = RemoveDuplicatePublicDesktopShortcut();

        if (syncedThisSession && !hadDuplicateIcon && FileExistsOnDisk(kInstalledIcon)) {
            return;
        }

        // 2. Copy N:\TitanNet\TitanNet\titannet.ico to C:\Program Files\TitanNet Enterprise\titannet.ico
        if (FileExistsOnDisk(kDevIconPath)) {
            ::CopyFileW(kDevIconPath, kInstalledIcon, FALSE);
        }

        const wchar_t* finalIcon = ResolveActiveIconPath();

        // 3. Register the Zero-UAC Scheduled Task pointing to C:\Program Files\TitanNet Enterprise\TitanNet.exe
        const bool taskReady = RegisterZeroUacAdminTask(kInstalledExe) || DoesZeroUacAdminTaskExist();

        // 4. Update ONLY the single User Desktop shortcut & Start Menu shortcut to use Zero-UAC Task
        wchar_t folderBuf[MAX_PATH]{};
        if (SUCCEEDED(::SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, 0, folderBuf))) {
            const std::wstring userLnk = std::wstring(folderBuf) + L"\\TitanNet Enterprise.lnk";
            CreateZeroUacAdminShortcut(userLnk.c_str(), finalIcon, taskReady);
        }
        if (SUCCEEDED(::SHGetFolderPathW(nullptr, CSIDL_COMMON_PROGRAMS, nullptr, 0, folderBuf))) {
            const std::wstring startLnk = std::wstring(folderBuf) + L"\\TitanNet Enterprise.lnk";
            CreateZeroUacAdminShortcut(startLnk.c_str(), finalIcon, taskReady);
        }

        // 5. Update Windows Installed Apps Registry Icon to titannet.ico
        if (finalIcon) {
            HKEY hKey = nullptr;
            if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, kUninstallRegKey, 0,
                KEY_WRITE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                const std::wstring regIcon(finalIcon);
                ::RegSetValueExW(hKey, L"DisplayIcon", 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(regIcon.c_str()),
                    static_cast<DWORD>((regIcon.size() + 1) * sizeof(wchar_t)));
                ::RegCloseKey(hKey);
            }
        }

        ApplyWindowAndTaskbarIcon();
        ::SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
        syncedThisSession = true;
    }

} // namespace TitanNet::Brand