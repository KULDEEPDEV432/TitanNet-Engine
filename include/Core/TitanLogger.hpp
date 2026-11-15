#pragma once
#include "TitanSafety.hpp"
#include <fstream>
#include <mutex>
#include <string>
#include <chrono>

namespace TitanV2::Core {
    class Logger {
        inline static std::mutex logMutex_;
    public:
        static void Write(const std::string& level, const std::string& msg) noexcept {
            std::lock_guard<std::mutex> lock(logMutex_);
            std::ofstream file("TitanNet_v2.log", std::ios::app);
            if (!file.is_open()) return;
            SYSTEMTIME st{};
            ::GetLocalTime(&st);
            char buf[64]{};
            sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            file << "[" << buf << "] [" << level << "] " << msg << "\n";
        }
    };
}
