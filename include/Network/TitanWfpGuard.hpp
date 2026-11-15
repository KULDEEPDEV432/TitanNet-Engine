#pragma once
#include "TitanSafety.hpp"
#include "TitanLogger.hpp"
#include <fwpmu.h>
#include <mutex>

namespace TitanV2::Network {
    // Fixes Bug #3 & #16: RAII Dynamic WFP Session (Auto-cleans kernel filters even on Task Manager Force-Close)
    class ScopedDynamicWfpEngine {
        HANDLE hEngine_ = nullptr;
        std::mutex mtx_;
    public:
        ScopedDynamicWfpEngine() noexcept { OpenDynamicSession(); }
        ~ScopedDynamicWfpEngine() noexcept { CloseSession(); }

        ScopedDynamicWfpEngine(const ScopedDynamicWfpEngine&) = delete;
        ScopedDynamicWfpEngine& operator=(const ScopedDynamicWfpEngine&) = delete;

        bool OpenDynamicSession() noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            if (hEngine_) return true;

            FWPM_SESSION0 session{};
            session.flags = FWPM_SESSION_FLAG_DYNAMIC; // Kernel auto-purges filters if process dies
            DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &hEngine_);
            if (status == ERROR_SUCCESS) {
                TitanV2::Core::Logger::Write("WFP_GUARD", "Dynamic WFP session opened safely (Auto-cleanup armed).");
                return true;
            }
            hEngine_ = nullptr;
            return false;
        }

        void CloseSession() noexcept {
            std::lock_guard<std::mutex> lock(mtx_);
            if (hEngine_) {
                FwpmEngineClose0(hEngine_);
                hEngine_ = nullptr;
            }
        }

        // Fixes Bug #15: Re-initializes WFP handle cleanly after Windows Sleep/Hibernation
        void ResetAfterPowerResume() noexcept {
            CloseSession();
            OpenDynamicSession();
        }
    };
}
