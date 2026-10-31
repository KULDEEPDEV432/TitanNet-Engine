#pragma once
#pragma once

#include "TitanTypes.hpp"

#include <string>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace TitanNet::Aegis {

    struct AegisSecurityState {
        bool          layer1DaclLocked{ false };
        bool          layer2ExploitGuardActive{ false };
        bool          layer3CodeRamIntact{ true };
        bool          layer4ZeroDebuggerAttach{ true };
        bool          layer5PriorityBoosted{ false };
        std::uint32_t activeDefenseLayers{ 0 };     // Out of 5 AI Layers
        std::uint64_t codeSectionHash{ 0 };
        std::uint64_t tamperAttemptsBlocked{ 0 };
        std::string   aegisStatusText;
    };

    class TitanAegisDefense final {
    private:
        mutable std::mutex         aegisMutex_{};
        std::uint64_t              baselineCodeHash_{ 0 };
        bool                       daclHardened_{ false };
        bool                       mitigationLocked_{ false };
        bool                       priorityElevated_{ false };
        std::atomic<std::uint64_t> tamperBlocks_{ 0 };

        // Layer 1: Hardens Process Kernel Security Descriptor against external tampering
        [[nodiscard]] static bool EnableKernelDaclProtection() noexcept;

        // Layer 2: Applies Windows Exploit Guard Anti-DLL-Injection Policies
        [[nodiscard]] static bool EnableExploitMitigationPolicies() noexcept;

        // Layer 3: Computes 64-Bit FNV-1a Hash of Executable's in-RAM .text machine code
        [[nodiscard]] static std::uint64_t ComputeExecutableCodeSectionHash() noexcept;

        // Layer 4: Detects external malware debuggers or remote thread hooks
        [[nodiscard]] static bool VerifyZeroExternalDebugger() noexcept;

        // Layer 5: Boosts Process & Thread Scheduling Priority against CPU starvation
        [[nodiscard]] static bool ElevateEngineSchedulingPriority() noexcept;

    public:
        TitanAegisDefense() noexcept = default;
        ~TitanAegisDefense() noexcept = default;

        TitanAegisDefense(const TitanAegisDefense&) = delete;
        TitanAegisDefense& operator=(const TitanAegisDefense&) = delete;

        // Initializes all 5 Self-Defense Layers at Engine Startup
        void InitializeArmor() noexcept;

        // Runs every 1 second to verify RAM code integrity & block tampering
        [[nodiscard]] AegisSecurityState AuditSelfDefense() noexcept;
    };

} // namespace TitanNet::Aegis