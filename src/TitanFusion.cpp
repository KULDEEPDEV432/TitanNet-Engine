#include "TitanFusion.hpp"

#include <chrono>
#include <algorithm>
#include <cmath>

namespace TitanNet::Fusion {

    TitanFusionEngine::~TitanFusionEngine() noexcept {
        Stop();
    }

    void TitanFusionEngine::Start() noexcept {
        if (probeThread_.joinable()) {
            return;
        }
        probeThread_ = std::jthread([this](std::stop_token st) {
            ProbeWorker(st);
            });
    }

    void TitanFusionEngine::Stop() noexcept {
        if (probeThread_.joinable()) {
            probeThread_.request_stop();
            probeThread_.join();
        }
    }

    void TitanFusionEngine::SyncAdapters(const std::vector<Core::AdapterRecord>& adapters) noexcept {
        std::scoped_lock lock(fusionMutex_);
        latestAdapters_ = adapters;

        for (const auto& nic : adapters) {
            auto& node = routeNodes_[nic.interfaceIndex];
            node.interfaceIndex = nic.interfaceIndex;
            node.friendlyName = nic.friendlyName;
            node.ipv4Address = nic.ipv4Address;
            node.linkSpeedMbps = nic.rxLinkSpeedMbps;
        }
    }

    // ========================================================================
    // MULTI-HOMED SOCKET BINDING & NON-BLOCKING GATEWAY LATENCY PROBE
    // ========================================================================
    double TitanFusionEngine::MeasureAdapterRttMs(std::string_view sourceIpv4) noexcept {
        if (sourceIpv4.empty() || sourceIpv4 == "0.0.0.0") {
            return -1.0;
        }

        Shield::ScopedSocket sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!sock.IsValid()) {
            return -1.0;
        }

        // 1. Socket ko strictly is NIC ke Local IPv4 par bind karo
        sockaddr_in localAddr{};
        localAddr.sin_family = AF_INET;
        localAddr.sin_port = 0; // Ephemeral kernel port
        std::string ipStr(sourceIpv4);
        if (::inet_pton(AF_INET, ipStr.c_str(), &localAddr.sin_addr) != 1) {
            return -1.0;
        }

        if (::bind(sock.Get(), reinterpret_cast<const sockaddr*>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR) {
            return -1.0;
        }

        // 2. Non-Blocking Mode (FIONBIO) lagao taaki offline adapter par thread hang na ho
        u_long nonBlocking = 1;
        if (::ioctlsocket(sock.Get(), FIONBIO, &nonBlocking) == SOCKET_ERROR) {
            return -1.0;
        }

        // 3. Target Anycast DNS Gateway (1.1.1.1:53)
        sockaddr_in targetAddr{};
        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = ::htons(53);
        ::inet_pton(AF_INET, "1.1.1.1", &targetAddr.sin_addr);

        const auto startTick = std::chrono::steady_clock::now();
        const int connRes = ::connect(sock.Get(), reinterpret_cast<const sockaddr*>(&targetAddr), sizeof(targetAddr));

        if (connRes == SOCKET_ERROR && ::WSAGetLastError() != WSAEWOULDBLOCK) {
            return -1.0;
        }

        fd_set writeSet{};
        FD_ZERO(&writeSet);
        FD_SET(sock.Get(), &writeSet);

        // Maximum 350ms wait timeout
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = 350'000;

        const int selRes = ::select(0, nullptr, &writeSet, nullptr, &timeout);
        if (selRes <= 0) {
            return -1.0;
        }

        int soError = -1;
        int optLen = sizeof(soError);
        if (::getsockopt(sock.Get(), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &optLen) != 0 || soError != 0) {
            return -1.0;
        }

        const auto endTick = std::chrono::steady_clock::now();
        return std::chrono::duration<double, std::milli>(endTick - startTick).count();
    }

    void TitanFusionEngine::RecalculateWeightsLocked() noexcept {
        double totalScore = 0.0;
        std::unordered_map<std::uint32_t, double> scores;

        for (auto& [ifIdx, node] : routeNodes_) {
            if (node.gatewayOnline && node.latencyMs > 0.1) {
                // Score Formula: Higher Link Speed + Lower Latency = Higher Traffic Share
                const double speedFactor = static_cast<double>((std::max)(node.linkSpeedMbps, 10ULL));
                const double score = speedFactor / (node.latencyMs + 5.0);
                scores[ifIdx] = score;
                totalScore += score;
            }
            else {
                node.weightPercent = 0;
            }
        }

        if (totalScore <= 0.0) {
            return;
        }

        for (auto& [ifIdx, node] : routeNodes_) {
            if (scores.contains(ifIdx)) {
                node.weightPercent = static_cast<std::uint32_t>(
                    std::round((scores[ifIdx] / totalScore) * 100.0)
                    );
            }
        }
    }

    void TitanFusionEngine::ProbeWorker(std::stop_token stopToken) noexcept {
        while (!stopToken.stop_requested()) {
            std::vector<Core::AdapterRecord> snapshot;
            {
                std::scoped_lock lock(fusionMutex_);
                snapshot = latestAdapters_;
            }

            for (const auto& nic : snapshot) {
                if (stopToken.stop_requested()) break;

                const double rtt = MeasureAdapterRttMs(nic.ipv4Address);

                std::scoped_lock lock(fusionMutex_);
                auto it = routeNodes_.find(nic.interfaceIndex);
                if (it != routeNodes_.end()) {
                    it->second.latencyMs = rtt;
                    it->second.gatewayOnline = (rtt > 0.0);
                }
            }

            {
                std::scoped_lock lock(fusionMutex_);
                RecalculateWeightsLocked();
            }

            // Har cycle mein ek Load-Balanced Multi-Homed Socket dispatch verify karo
            std::string boundIp;
            auto testSock = CreateLoadBalancedSocket(boundIp);

            for (int i = 0; i < 20 && !stopToken.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    // ========================================================================
    // WEIGHTED MULTI-HOMED SOCKET DISPATCHER
    // ========================================================================
    Shield::ScopedSocket TitanFusionEngine::CreateLoadBalancedSocket(std::string& outBoundIp) noexcept {
        outBoundIp.clear();
        std::scoped_lock lock(fusionMutex_);

        std::vector<FusionRouteNode*> onlineNodes;
        for (auto& [ifIdx, node] : routeNodes_) {
            if (node.gatewayOnline && node.weightPercent > 0) {
                onlineNodes.push_back(&node);
            }
        }

        if (onlineNodes.empty()) {
            return {};
        }

        // Weighted Round-Robin (WRR) Bucket Selection across all active NICs
        const std::uint64_t ticket = (rrCounter_.fetch_add(17, std::memory_order_relaxed)) % 100;
        std::uint32_t cumulative = 0;
        FusionRouteNode* selected = onlineNodes.front();

        for (auto* node : onlineNodes) {
            cumulative += node->weightPercent;
            if (ticket < cumulative) {
                selected = node;
                break;
            }
        }

        Shield::ScopedSocket sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!sock.IsValid()) {
            return {};
        }

        sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_port = 0;
        if (::inet_pton(AF_INET, selected->ipv4Address.c_str(), &bindAddr.sin_addr) != 1) {
            return {};
        }

        if (::bind(sock.Get(), reinterpret_cast<const sockaddr*>(&bindAddr), sizeof(bindAddr)) == SOCKET_ERROR) {
            return {};
        }

        selected->dispatchedSockets++;
        totalDispatched_.fetch_add(1, std::memory_order_relaxed);
        outBoundIp = selected->ipv4Address;

        return sock;
    }

    std::vector<FusionRouteNode> TitanFusionEngine::GetRouteTable() const noexcept {
        std::scoped_lock lock(fusionMutex_);
        std::vector<FusionRouteNode> table;
        table.reserve(routeNodes_.size());
        for (const auto& [ifIdx, node] : routeNodes_) {
            table.push_back(node);
        }
        return table;
    }

    std::size_t TitanFusionEngine::GetOnlineGatewayCount() const noexcept {
        std::scoped_lock lock(fusionMutex_);
        std::size_t count = 0;
        for (const auto& [ifIdx, node] : routeNodes_) {
            if (node.gatewayOnline) {
                ++count;
            }
        }
        return count;
    }

} // namespace TitanNet::Fusion