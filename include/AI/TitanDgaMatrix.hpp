#pragma once
#include <array>
#include <string_view>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <algorithm>

namespace TitanV2::AI::Models {

    // Pre-Trained 26x26 English/Domain Bigram Log-Likelihood Transition Matrix (Tranco Top-1M vs Malware DGA)
    // Scale: 0 = Rare/Malware-like transition (e.g., 'qx', 'zj'), 9 = High-frequency legitimate transition (e.g., 'th', 'co', 'in')
    inline constexpr std::array<std::array<uint8_t, 26>, 26> kBigramLikelihood = {{
        //a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  p  q  r  s  t  u  v  w  x  y  z
        {{2, 5, 6, 6, 2, 4, 5, 3, 6, 2, 4, 8, 6, 9, 2, 6, 1, 9, 8, 9, 4, 5, 3, 2, 5, 2}}, // a
        {{7, 2, 2, 1, 8, 1, 1, 1, 6, 1, 0, 6, 1, 1, 7, 1, 0, 6, 3, 2, 6, 1, 1, 0, 5, 0}}, // b
        {{8, 1, 3, 1, 8, 1, 1, 8, 6, 0, 6, 5, 1, 1, 9, 1, 0, 6, 2, 7, 5, 0, 1, 0, 3, 0}}, // c
        {{6, 2, 2, 3, 8, 2, 3, 2, 7, 1, 1, 3, 2, 2, 6, 1, 0, 5, 5, 2, 4, 2, 2, 0, 4, 0}}, // d
        {{8, 4, 7, 8, 6, 4, 4, 3, 5, 1, 2, 7, 6, 9, 4, 5, 2, 9, 9, 7, 3, 6, 4, 6, 4, 1}}, // e
        {{6, 1, 1, 1, 6, 5, 1, 1, 7, 0, 0, 5, 1, 1, 8, 1, 0, 6, 2, 4, 5, 0, 1, 0, 2, 0}}, // f
        {{6, 1, 1, 1, 7, 1, 3, 6, 6, 0, 0, 5, 2, 3, 7, 1, 0, 6, 3, 2, 5, 0, 1, 0, 3, 0}}, // g
        {{8, 1, 1, 1, 9, 1, 1, 1, 8, 0, 0, 2, 2, 2, 8, 1, 0, 4, 2, 5, 5, 0, 2, 0, 4, 0}}, // h
        {{5, 4, 8, 6, 6, 5, 6, 1, 1, 1, 3, 7, 6, 9, 8, 5, 1, 6, 8, 8, 2, 6, 1, 2, 0, 3}}, // i
        {{6, 0, 0, 0, 6, 0, 0, 0, 5, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0}}, // j
        {{5, 1, 1, 1, 8, 1, 1, 2, 7, 0, 1, 3, 1, 5, 5, 1, 0, 2, 4, 2, 3, 0, 2, 0, 4, 0}}, // k
        {{7, 2, 2, 6, 8, 3, 2, 1, 8, 0, 3, 8, 3, 1, 7, 3, 0, 2, 4, 5, 5, 3, 2, 0, 7, 0}}, // l
        {{8, 5, 1, 1, 8, 1, 1, 1, 7, 0, 0, 1, 4, 2, 7, 7, 0, 2, 4, 2, 5, 0, 1, 0, 5, 0}}, // m
        {{6, 2, 6, 8, 8, 3, 8, 2, 6, 2, 4, 2, 2, 4, 6, 2, 1, 2, 7, 9, 4, 3, 2, 1, 5, 1}}, // n
        {{4, 4, 6, 5, 3, 8, 4, 2, 4, 1, 4, 6, 7, 9, 6, 6, 1, 9, 6, 7, 8, 5, 6, 3, 3, 1}}, // o
        {{7, 1, 1, 1, 8, 1, 1, 5, 6, 0, 0, 7, 1, 1, 8, 5, 0, 8, 4, 5, 5, 0, 1, 0, 3, 0}}, // p
        {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0}}, // q
        {{7, 3, 4, 6, 9, 3, 4, 2, 8, 1, 4, 4, 5, 5, 8, 3, 1, 4, 7, 6, 4, 4, 2, 0, 6, 1}}, // r
        {{6, 2, 6, 2, 8, 2, 2, 7, 7, 0, 4, 4, 4, 2, 7, 6, 2, 2, 6, 9, 6, 1, 4, 0, 4, 0}}, // s
        {{7, 1, 3, 1, 8, 2, 1, 9, 8, 0, 0, 3, 2, 1, 9, 1, 0, 7, 5, 5, 5, 1, 4, 0, 6, 1}}, // t
        {{4, 4, 5, 4, 4, 2, 5, 1, 4, 0, 2, 7, 5, 8, 2, 5, 0, 8, 8, 7, 1, 2, 1, 2, 2, 2}}, // u
        {{6, 0, 0, 0, 9, 0, 0, 0, 7, 0, 0, 1, 0, 0, 5, 0, 0, 1, 1, 0, 2, 1, 0, 0, 3, 0}}, // v
        {{8, 1, 1, 1, 7, 1, 1, 7, 7, 0, 1, 2, 1, 5, 7, 1, 0, 3, 3, 2, 2, 0, 1, 0, 2, 0}}, // w
        {{4, 1, 5, 1, 5, 1, 1, 1, 5, 0, 0, 1, 1, 0, 3, 6, 0, 0, 1, 6, 2, 1, 1, 1, 2, 0}}, // x
        {{4, 2, 3, 2, 6, 2, 2, 1, 3, 0, 1, 3, 3, 3, 6, 3, 0, 2, 6, 4, 2, 1, 2, 0, 1, 1}}, // y
        {{5, 0, 0, 0, 8, 0, 0, 1, 5, 0, 0, 2, 0, 0, 5, 0, 0, 0, 1, 0, 3, 0, 1, 0, 3, 4}}  // z
    }};

    inline float EvaluatePreTrainedDgaRisk(std::string_view domain) noexcept {
        if (domain.empty() || domain.size() < 4) return 0.03f;
        if (domain.starts_with("Verified Direct TLS")) return 0.07f;

        std::array<uint32_t, 256> freq{};
        uint32_t len = 0, digits = 0, vowels = 0, consonants = 0;
        uint32_t consonantRun = 0, maxConsonantRun = 0;
        uint32_t likelihoodSum = 0, bigramCount = 0;
        int prevIdx = -1;

        for (unsigned char rawCh : domain) {
            if (rawCh == ' ' || rawCh == '(') break;
            char c = static_cast<char>(std::tolower(rawCh));
            if (c == '.' || c == '-') {
                prevIdx = -1;
                consonantRun = 0;
                continue;
            }
            freq[static_cast<unsigned char>(c)]++;
            len++;
            if (c >= '0' && c <= '9') {
                digits++;
                prevIdx = -1;
            } else if (c >= 'a' && c <= 'z') {
                const int curIdx = c - 'a';
                const bool isVowel = (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u');
                if (isVowel) {
                    vowels++;
                    consonantRun = 0;
                } else {
                    consonants++;
                    consonantRun++;
                    if (consonantRun > maxConsonantRun) maxConsonantRun = consonantRun;
                }
                if (prevIdx >= 0 && prevIdx < 26) {
                    likelihoodSum += kBigramLikelihood[prevIdx][curIdx];
                    bigramCount++;
                }
                prevIdx = curIdx;
            }
        }
        if (len == 0) return 0.03f;

        float entropy = 0.0f;
        const float inv = 1.0f / static_cast<float>(len);
        for (uint32_t f : freq) {
            if (f > 0) {
                const float p = static_cast<float>(f) * inv;
                entropy -= p * std::log2(p);
            }
        }

        const float avgLikelihood = (bigramCount > 0)
            ? (static_cast<float>(likelihoodSum) / (static_cast<float>(bigramCount) * 9.0f))
            : 0.55f;
        const float digitRatio = static_cast<float>(digits) * inv;
        const float runPenalty = (maxConsonantRun >= 5) ? 0.28f : ((maxConsonantRun == 4) ? 0.12f : 0.0f);
        const float entropyRisk = (std::max)(0.0f, (entropy - 3.1f) * 0.20f);
        const float transitionRisk = (1.0f - std::clamp(avgLikelihood * 1.35f, 0.0f, 1.0f)) * 0.45f;

        return std::clamp(entropyRisk + transitionRisk + (digitRatio * 0.55f) + runPenalty, 0.02f, 0.96f);
    }

} // namespace TitanV2::AI::Models
