#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

#include <Hooking.Patterns.h>

// Try each candidate signature in turn, return the first that matches the expected
// number of times. Lets a single call site carry per-build variants (1.0.7.0,
// 1.0.8.0, Complete Edition, ...) instead of being pinned to one game version:
//
//     find_pattern("<1.0.8.0 sig>", "<CE sig>")
//
// When a build's signature differs, ADD it as another argument - don't replace the
// existing one. Ported from FusionFix (source/common.ixx).
template<size_t count = 1, typename... Args>
hook::pattern find_pattern(Args... args)
{
    hook::pattern pattern{};
    ((pattern = hook::pattern(args), !pattern.count_hint(count).empty()) || ...);
    return pattern;
}

// Raw object representation - used to build a byte pattern that finds every
// instruction referencing a given address.
template<typename T>
std::array<uint8_t, sizeof(T)> to_bytes(const T &object)
{
    std::array<uint8_t, sizeof(T)> bytes{};
    const uint8_t *begin = reinterpret_cast<const uint8_t *>(std::addressof(object));
    std::copy(begin, begin + sizeof(T), std::begin(bytes));
    return bytes;
}

template<size_t n>
std::string pattern_str(const std::array<uint8_t, n> &bytes)
{
    char buf[4];
    std::string result;
    result.reserve(n * 3);
    for (size_t i = 0; i < n; i++)
    {
        snprintf(buf, sizeof(buf), "%02X ", bytes[i]);
        result += buf;
    }
    return result;
}
