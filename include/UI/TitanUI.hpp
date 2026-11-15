#pragma once
#include "TitanSafety.hpp"
#include "TitanTypes.hpp"
#include "TitanShield.hpp"
#include "TitanFusion.hpp"
#include "TitanV2Engine.hpp"
#include <vector>
#include <deque>
#include <string>

namespace TitanNet::UI {
    struct DashboardSnapshot {
        double                                  totalRxBytesPerSec{ 0.0 };
        double                                  totalTxBytesPerSec{ 0.0 };
        double                                  peakRxBytesPerSec{ 10240.0 };
        std::deque<double>                      rxHistory{};
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
        V2::V2EnterpriseReport                  v2{};
    };
}
