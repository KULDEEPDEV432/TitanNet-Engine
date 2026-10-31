#pragma once

#include "TitanTypes.hpp"
#include "TitanShield.hpp"

#include <vector>
#include <string>
#include <string_view>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_map>

namespace TitanNet::Fusion {

    // Har Hardware NIC ki Live Routing, Ping aur Load-Balance State
    struct FusionRouteNode {
        std::uint32_t interfaceIndex{ 0 };
        std::string   friendlyName;
        std::string   ipv4Address;
        std::uint64_t linkSpeedMbps{ 0 };
        double        latencyMs{ -1.0 };      // -1.0 = No Internet Gateway
        bool          gatewayOnline{ false }; // True agar is NIC se internet chal raha hai
        std::uint32_t weightPercent{ 0 };     // Traffic Split % (e.g., 60% Wi-Fi / 40% USB)
        std::uint64_t dispatchedSockets{ 0 }; // Is NIC par kitne sockets route huye
    };

    class TitanFusionEngine final {
    private:
        Shield::WsaSession                              wsaSession_{};
        std::jthread                                    probeThread_{};
        mutable std::mutex                              fusionMutex_{};
        std::vector<Core::AdapterRecord>                latestAdapters_{};
        std::unordered_map<std::uint32_t, FusionRouteNode> routeNodes_{};
        std::atomic<std::uint64_t>                      rrCounter_{ 0 };
        std::atomic<std::uint64_t>                      totalDispatched_{ 0 };

        void ProbeWorker(std::stop_token stopToken) noexcept;

        // Specific NIC IPv4 par socket bind karke non-blocking TCP RTT ping naapta hai
        [[nodiscard]] static double MeasureAdapterRttMs(std::string_view sourceIpv4) noexcept;

        // Ping aur Link Speed ke hisab se har NIC ka Weight (%) calculate karta hai
        void RecalculateWeightsLocked() noexcept;

    public:
        TitanFusionEngine() noexcept = default;
        ~TitanFusionEngine() noexcept;

        TitanFusionEngine(const TitanFusionEngine&) = delete;
        TitanFusionEngine& operator=(const TitanFusionEngine&) = delete;

        void Start() noexcept;
        void Stop() noexcept;

        // Main loop se latest active NICs feed karta hai
        void SyncAdapters(const std::vector<Core::AdapterRecord>& adapters) noexcept;

        // Weighted Load-Balancer: Agle connection ke liye best NIC select karke Bound Socket deta hai
        [[nodiscard]] Shield::ScopedSocket CreateLoadBalancedSocket(std::string& outBoundIp) noexcept;

        [[nodiscard]] std::vector<FusionRouteNode> GetRouteTable() const noexcept;
        [[nodiscard]] std::uint64_t GetTotalDispatched() const noexcept { return totalDispatched_.load(); }
        [[nodiscard]] std::size_t GetOnlineGatewayCount() const noexcept;
    };

} // namespace TitanNet::Fusion