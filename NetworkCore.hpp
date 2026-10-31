#pragma once

#include "TitanTypes.hpp"
#include <vector>
#include <string_view>

namespace TitanNet::Core {

    class NetworkCore final {
    public:
        NetworkCore() = delete;

        [[nodiscard]] static std::string WideToUtf8(std::wstring_view wideStr) noexcept;
        [[nodiscard]] static std::string IpToString(std::uint32_t netByteOrderIp) noexcept;
        [[nodiscard]] static std::string ResolveProcessName(std::uint32_t pid) noexcept;
        [[nodiscard]] static std::vector<AdapterRecord> EnumerateActiveAdapters() noexcept;
        [[nodiscard]] static std::vector<TcpFlowRecord> CaptureActiveTcpFlows() noexcept;
    };

} // namespace TitanNet::Core