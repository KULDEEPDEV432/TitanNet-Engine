#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <array>
#include <string>
#include <filesystem>
#include <fstream>
#include <cmath>
#include <cstdint>
#include <algorithm>
#include "TitanPeExtractor.hpp"
#include "TitanModelProvisioner.hpp"

namespace TitanV2::AI::Models {

    inline std::wstring ResolveModelFilePath(const wchar_t* fileName) noexcept {
        static const std::filesystem::path provisionedDir = EnsureLocalModelsProvisioned();
        std::error_code ec;
        auto target = provisionedDir / fileName;
        if (std::filesystem::exists(target, ec)) {
            return target.wstring();
        }
        return (std::filesystem::path(L"assets\\models") / fileName).wstring();
    }

    struct OnnxTensorGraph8x16x8x1 {
        std::array<std::array<float, 8>, 16> W1{};
        std::array<float, 16>                B1{};
        std::array<std::array<float, 16>, 8> W2{};
        std::array<float, 8>                 B2{};
        std::array<float, 8>                 W3{};
        float                                B3{ 0.0f };
        bool                                 loadedFromDisk{ false };

        float Forward(const std::array<float, 8>& x) const noexcept {
            std::array<float, 16> h1{};
            for (size_t i = 0; i < 16; ++i) {
                float s = B1[i];
                for (size_t j = 0; j < 8; ++j) s += W1[i][j] * x[j];
                h1[i] = (s > 0.0f) ? s : (0.08f * s);
            }
            std::array<float, 8> h2{};
            for (size_t i = 0; i < 8; ++i) {
                float s = B2[i];
                for (size_t j = 0; j < 16; ++j) s += W2[i][j] * h1[j];
                h2[i] = (s > 0.0f) ? s : (0.08f * s);
            }
            float logit = B3;
            for (size_t i = 0; i < 8; ++i) logit += W3[i] * h2[i];
            return 1.0f / (1.0f + std::exp(-std::clamp(logit, -10.0f, 10.0f)));
        }
    };

    class TitanNativeOnnxEngine {
        OnnxTensorGraph8x16x8x1 emberPeModel_{};
        OnnxTensorGraph8x16x8x1 cicIdsFlowModel_{};

        static bool LoadOnnxFileFromDisk(const std::wstring& path, OnnxTensorGraph8x16x8x1& outGraph) noexcept {
            std::ifstream file(path, std::ios::binary);
            if (!file.is_open()) return false;

            std::array<uint8_t, 1200> buf{};
            file.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
            if (file.gcount() < 1184) return false;
            if (buf[16] != 'O' || buf[17] != 'R' || buf[18] != 'T' || buf[19] != 'N') return false;

            const float* fPtr = reinterpret_cast<const float*>(buf.data() + 32);
            for (size_t i = 0; i < 16; ++i)
                for (size_t j = 0; j < 8; ++j) outGraph.W1[i][j] = *fPtr++;
            for (size_t i = 0; i < 16; ++i) outGraph.B1[i] = *fPtr++;
            for (size_t i = 0; i < 8; ++i)
                for (size_t j = 0; j < 16; ++j) outGraph.W2[i][j] = *fPtr++;
            for (size_t i = 0; i < 8; ++i) outGraph.B2[i] = *fPtr++;
            for (size_t i = 0; i < 8; ++i) outGraph.W3[i] = *fPtr++;
            outGraph.B3 = *fPtr;
            outGraph.loadedFromDisk = true;
            return true;
        }

    public:
        TitanNativeOnnxEngine() noexcept {
            (void)EnsureLocalModelsProvisioned();
            LoadOnnxFileFromDisk(ResolveModelFilePath(L"ember_pe.onnx"), emberPeModel_);
            LoadOnnxFileFromDisk(ResolveModelFilePath(L"cic_ids2018.onnx"), cicIdsFlowModel_);
        }

        float ScoreEmberPeTensor(const std::array<float, 8>& peFeatures) const noexcept {
            if (!emberPeModel_.loadedFromDisk) return 0.04f;
            return std::clamp(emberPeModel_.Forward(peFeatures), 0.002f, 0.990f);
        }

        float ScoreCicIdsFlowTensor(const std::array<float, 8>& flowFeatures) const noexcept {
            if (!cicIdsFlowModel_.loadedFromDisk) return 0.03f;
            return std::clamp(cicIdsFlowModel_.Forward(flowFeatures), 0.002f, 0.990f);
        }

        bool IsReady() const noexcept {
            return emberPeModel_.loadedFromDisk && cicIdsFlowModel_.loadedFromDisk;
        }
    };

    inline TitanNativeOnnxEngine& GlobalOnnxRuntime() noexcept {
        static TitanNativeOnnxEngine instance{};
        return instance;
    }

} // namespace TitanV2::AI::Models