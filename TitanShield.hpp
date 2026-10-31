#pragma once

#include "TitanTypes.hpp"
#include <mstcpip.h>

#include <span>
#include <vector>
#include <deque>
#include <string>
#include <string_view>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_set>

namespace TitanNet::Shield {

    // ========================================================================
    // RAII Guard for Winsock2 Subsystem (Auto WSAStartup / WSACleanup)
    // ========================================================================
    class WsaSession final {
    private:
        bool initialized_{ false };

    public:
        WsaSession() noexcept {
            WSADATA wsaData{};
            initialized_ = (::WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
        }

        ~WsaSession() noexcept {
            if (initialized_) {
                ::WSACleanup();
            }
        }

        WsaSession(const WsaSession&) = delete;
        WsaSession& operator=(const WsaSession&) = delete;

        [[nodiscard]] bool IsValid() const noexcept { return initialized_; }
    };

    // ========================================================================
    // RAII Guard for Windows Kernel Sockets (Zero Socket Leak + Move Safe)
    // ========================================================================
    class ScopedSocket final {
    private:
        SOCKET sock_{ INVALID_SOCKET };

    public:
        ScopedSocket() noexcept = default;
        explicit ScopedSocket(SOCKET s) noexcept : sock_(s) {}

        ~ScopedSocket() noexcept {
            Close();
        }

        // Copy strictly banned (Double-Close exploit roknay ke liye)
        ScopedSocket(const ScopedSocket&) = delete;
        ScopedSocket& operator=(const ScopedSocket&) = delete;

        // Move Constructor & Move Assignment (Function se safely socket return karne ke liye)
        ScopedSocket(ScopedSocket&& other) noexcept : sock_(other.sock_) {
            other.sock_ = INVALID_SOCKET;
        }

        ScopedSocket& operator=(ScopedSocket&& other) noexcept {
            if (this != &other) {
                Close();
                sock_ = other.sock_;
                other.sock_ = INVALID_SOCKET;
            }
            return *this;
        }

        [[nodiscard]] bool IsValid() const noexcept { return sock_ != INVALID_SOCKET; }
        [[nodiscard]] SOCKET Get() const noexcept { return sock_; }

        void Close() noexcept {
            if (sock_ != INVALID_SOCKET) {
                ::closesocket(sock_);
                sock_ = INVALID_SOCKET;
            }
        }
    };

    struct ShieldEvent {
        std::string   sourceIp;
        std::string   destIp;
        std::uint16_t destPort{ 0 };
        std::string   sniDomain;
        bool          wasBlocked{ false };
    };

    class TitanShieldEngine final {
    private:
        WsaSession                        wsaSession_{};
        std::jthread                      snifferThread_{};
        mutable std::mutex                eventMutex_{};
        std::deque<ShieldEvent>           recentEvents_{};
        std::unordered_set<std::string>   blockedProcesses_{};
        std::atomic<std::uint64_t>        packetsInspected_{ 0 };
        std::atomic<std::uint64_t>        connectionsBlocked_{ 0 };
        std::atomic<bool>                 rawSnifferActive_{ false };
        std::string                       statusMessage_{ "Initializing..." };

        void SnifferWorker(std::stop_token stopToken, std::string bindIpv4) noexcept;

        [[nodiscard]] static std::string ExtractTlsSniBounded(std::span<const std::uint8_t> tcpPayload) noexcept;

    public:
        TitanShieldEngine() noexcept;
        ~TitanShieldEngine() noexcept;

        TitanShieldEngine(const TitanShieldEngine&) = delete;
        TitanShieldEngine& operator=(const TitanShieldEngine&) = delete;

        void Start(std::string_view bindIpv4) noexcept;
        void Stop() noexcept;

        [[nodiscard]] std::size_t EnforceTelemetryPolicy(const std::vector<Core::TcpFlowRecord>& activeFlows) noexcept;

        [[nodiscard]] static bool TerminateKernelTcpConnection(
            std::string_view localIp, std::uint16_t localPort,
            std::string_view remoteIp, std::uint16_t remotePort) noexcept;

        [[nodiscard]] std::vector<ShieldEvent> GetRecentEvents() const noexcept;
        [[nodiscard]] std::uint64_t GetPacketsInspected() const noexcept { return packetsInspected_.load(); }
        [[nodiscard]] std::uint64_t GetConnectionsBlocked() const noexcept { return connectionsBlocked_.load(); }
        [[nodiscard]] bool IsRawSnifferActive() const noexcept { return rawSnifferActive_.load(); }
        [[nodiscard]] std::string GetStatusMessage() const noexcept;
    };

} // namespace TitanNet::Shield