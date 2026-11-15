#pragma once
#include "TitanSafety.hpp"
#include "TitanMicroML.hpp"
#include <iphlpapi.h>
#include <string>
#include <vector>

namespace TitanV2::Network {
    class SmartBondController {
    public:
        // Fixes Bug #26: Detects VPNs, WireGuard, Cloudflare WARP, TAP & WSL2 Virtual Adapters
        static bool IsVpnOrVirtualAdapter(ULONG ifType, const std::wstring& description) noexcept {
            if (ifType == IF_TYPE_PROP_VIRTUAL || ifType == IF_TYPE_TUNNEL || ifType == 53 || ifType == 131) {
                return true;
            }
            const wchar_t* vpnKeywords[] = {
                L"VPN", L"WireGuard", L"WARP", L"TAP-", L"TUN", L"Wintun",
                L"WSL", L"Hyper-V", L"Virtual", L"ZeroTier", L"Tailscale", L"Cisco"
            };
            for (const wchar_t* kw : vpnKeywords) {
                if (description.find(kw) != std::wstring::npos) return true;
            }
            return false;
        }

        // Fixes Bug #14: Uses MicroNeuralEngine to compute live route metric instead of static hardcoded values
        static uint32_t CalculateSafeDynamicMetric(ULONG ifType, const std::wstring& desc,
                                                   float rttMs, float lossPct, float bwMbps) noexcept {
            if (IsVpnOrVirtualAdapter(ifType, desc)) {
                return 0; // 0 = Do NOT touch active VPN/Virtual adapter metrics
            }
            return TitanV2::AI::MicroNeuralEngine::ComputeOptimalRouteMetric(rttMs, lossPct, bwMbps);
        }
    };
}
