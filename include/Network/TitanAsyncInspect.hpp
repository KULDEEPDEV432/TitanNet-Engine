#pragma once
#include "TitanSafety.hpp"
#include "TitanLogger.hpp"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <span>
#include <atomic>
#include <cstdint>

namespace TitanV2::Network {
    struct PacketSample {
        uint32_t pid = 0;
        uint16_t dstPort = 0;
        bool isUdp = false;
        std::vector<uint8_t> payload;
    };

    // Fixes Bug #5, #8, #10, #21: Non-Blocking std::jthread Worker Pool + QUIC UDP 443 Detection
    class AsyncPacketInspector {
        std::mutex queueMtx_;
        std::condition_variable_any cv_;
        std::queue<PacketSample> queue_;
        std::atomic<uint64_t> quicPacketsDetected_{ 0 };
        std::atomic<uint64_t> inspectedCount_{ 0 };
        std::jthread worker_;

        void WorkerLoop(std::stop_token st) noexcept {
            while (!st.stop_requested()) {
                PacketSample sample{};
                {
                    std::unique_lock<std::mutex> lock(queueMtx_);
                    cv_.wait(lock, st, [this] { return !queue_.empty(); });
                    if (st.stop_requested() || queue_.empty()) break;
                    sample = std::move(queue_.front());
                    queue_.pop();
                }
                InspectSpanSafe(std::span<const uint8_t>(sample.payload), sample.dstPort, sample.isUdp);
            }
        }

    public:
        AsyncPacketInspector() noexcept
            : worker_([this](std::stop_token st) { WorkerLoop(st); }) {}

        ~AsyncPacketInspector() noexcept {
            if (worker_.joinable()) {
                worker_.request_stop();
                cv_.notify_all();
            }
        }

        // Non-blocking enqueue so UI and network sockets never lag
        void EnqueueSample(PacketSample&& s) noexcept {
            std::lock_guard<std::mutex> lock(queueMtx_);
            if (queue_.size() < 256) {
                queue_.push(std::move(s));
                cv_.notify_one();
            }
        }

        // Fixes Bug #10 & #21: Safe std::span bounds check + QUIC (HTTP/3 UDP 443) Long Header detection
        void InspectSpanSafe(std::span<const uint8_t> data, uint16_t dstPort, bool isUdp) noexcept {
            inspectedCount_.fetch_add(1, std::memory_order_relaxed);
            if (isUdp && dstPort == 443 && data.size() >= 6) {
                // QUIC Long Header packet starts with 11xxxxxx (0xC0 mask) and 4-byte version
                if ((data[0] & 0x80) != 0) {
                    quicPacketsDetected_.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }

        uint64_t GetQuicCount() const noexcept { return quicPacketsDetected_.load(std::memory_order_relaxed); }
        uint64_t GetInspectedCount() const noexcept { return inspectedCount_.load(std::memory_order_relaxed); }
    };
}
