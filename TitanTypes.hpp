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
#include <iphlpapi.h>

#include <string>
#include <cstdint>

namespace TitanNet::Core {

    class ScopedHandle final {
    private:
        HANDLE handle_{ nullptr };

    public:
        ScopedHandle() noexcept = default;
        explicit ScopedHandle(HANDLE h) noexcept : handle_(h) {}

        ~ScopedHandle() noexcept {
            Close();
        }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        ScopedHandle(ScopedHandle&& other) noexcept : handle_(other.handle_) {
            other.handle_ = nullptr;
        }

        ScopedHandle& operator=(ScopedHandle&& other) noexcept {
            if (this != &other) {
                Close();
                handle_ = other.handle_;
                other.handle_ = nullptr;
            }
            return *this;
        }

        [[nodiscard]] bool IsValid() const noexcept {
            return (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE);
        }

        [[nodiscard]] HANDLE Get() const noexcept {
            return handle_;
        }

        void Close() noexcept {
            if (IsValid()) {
                ::CloseHandle(handle_);
                handle_ = nullptr;
            }
        }
    };

    struct AdapterRecord {
        std::uint32_t interfaceIndex{ 0 };
        std::string   friendlyName;
        std::string   hardwareDescription;
        std::string   ipv4Address;
        std::uint64_t txLinkSpeedMbps{ 0 };
        std::uint64_t rxLinkSpeedMbps{ 0 };
        std::uint64_t rxBytesTotal{ 0 };
        std::uint64_t txBytesTotal{ 0 };
    };

    struct TcpFlowRecord {
        std::uint32_t processId{ 0 };
        std::string   processName;
        std::string   localAddress;
        std::uint16_t localPort{ 0 };
        std::string   remoteAddress;
        std::uint16_t remotePort{ 0 };
    };

} // namespace TitanNet::Core