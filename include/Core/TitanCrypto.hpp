#pragma once
#include "TitanSafety.hpp"
#include <bcrypt.h>
#include <vector>
#include <string>
#include <span>
#pragma comment(lib, "bcrypt.lib")

namespace TitanV2::Core {
    inline std::string ComputeSHA256(std::span<const uint8_t> data) noexcept {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        uint8_t hash[32]{};
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
            BCryptHashData(hHash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
            BCryptFinishHash(hHash, hash, sizeof(hash), 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
        static const char hex[] = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (uint8_t b : hash) {
            out.push_back(hex[b >> 4]);
            out.push_back(hex[b & 0x0F]);
        }
        return out;
    }
}
