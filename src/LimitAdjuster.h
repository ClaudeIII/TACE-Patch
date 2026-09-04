#pragma once

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <vector>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Log.h"
#include "Patterns.h"

// Grows one of the game's fixed-size static arrays and repoints every instruction
// that referenced the old storage at the new, larger buffer.
//
// This is what raising a limit actually requires. Writing a bigger count over an
// immediate does NOT work for these tables - the backing store is a fixed-size
// buffer in .data, so the game walks straight off the end of it. Ported from
// FusionFix (source/limits.ixx), reduced from C++20 concepts/templated lambdas to
// the C++17 this project builds with.
//
// Difference from upstream: FusionFix guards the xref count with assert(), which
// is compiled out in Release. A signature that finds the wrong number of
// references then patches SOME of them, leaving the rest pointing at the old
// array - which corrupts memory and crashes later, far from the cause. Here the
// references are counted first and nothing is written unless the count is exactly
// what the caller expected.
class LimitAdjuster
{
public:
    LimitAdjuster(uintptr_t startAddress, size_t elementSize, size_t elementsCount, size_t xrefCount)
        : m_startAddress(startAddress), m_elementSize(elementSize),
          m_elementsCount(elementsCount), m_xrefCount(xrefCount)
    {
    }

    LimitAdjuster &Named(const char *name)
    {
        m_name = name;
        return *this;
    }

    // Per-offset xref counts. Noisy, but they are what pinpoint a build
    // difference, so they are on by default (Debug/VerboseXrefs in the ini).
    LimitAdjuster &Verbose(bool on)
    {
        m_verbose = on;
        return *this;
    }

    LimitAdjuster &IncreaseBy(size_t num)
    {
        if (num > 1)
            m_increaseby = num;
        return *this;
    }

    LimitAdjuster &InsertNewArrayPointer(uint8_t *ptr)
    {
        m_array = ptr;
        return *this;
    }

    bool Succeeded() const { return m_patchedXrefs; }

    template<typename... Offsets>
    LimitAdjuster &ReplaceXrefs(Offsets... offsets)
    {
        if (m_patchedXrefs || m_failed)
            return *this;

        if (m_startAddress == 0)
        {
            TaceLog("[limits] %s: SKIPPED - array address is null (signature did not match)", m_name);
            m_failed = true;
            return *this;
        }

        const std::initializer_list<ptrdiff_t> list = { static_cast<ptrdiff_t>(offsets)... };
        const ptrdiff_t maxArrayOffset = static_cast<ptrdiff_t>(m_elementSize * m_elementsCount);
        const ptrdiff_t maxNeededOffset = *std::max_element(list.begin(), list.end());

        // Pass 1 - count the real references without touching anything.
        size_t found = 0;
        for (ptrdiff_t v : list)
        {
            size_t perOffset = 0;
            ForEachXref(v, [&](uint32_t *) { perOffset++; });
            found += perOffset;
            // Per-offset counts are what pinpoint a build difference: an offset
            // yielding 0 here is the one whose signature moved in this build.
            if (m_verbose)
                TaceLog("[limits] %s:   +0x%zX -> %zu xref(s) @ %p",
                        m_name, size_t(v), perOffset, (void *)(m_startAddress + v));
        }

        if (found != m_xrefCount)
        {
            TaceLog("[limits] %s: ABORTED - found %zu xrefs, expected %zu. Nothing patched.",
                    m_name, found, m_xrefCount);
            m_failed = true;
            return *this;
        }

        if (m_array == nullptr)
        {
            const size_t tail = (maxNeededOffset > maxArrayOffset) ? size_t(maxNeededOffset - maxArrayOffset) : 0;
            m_storage = new std::vector<uint8_t>(m_increaseby * size_t(maxArrayOffset) + tail, 0);
            m_array = m_storage->data();
        }

        // Pass 2 - the count checked out, so commit.
        for (ptrdiff_t v : list)
        {
            const uintptr_t oldPtr = m_startAddress + v;
            ForEachXref(v, [&](uint32_t *xref)
            {
                if (v < maxArrayOffset)
                    injector::AdjustPointer(xref, m_array, m_startAddress, oldPtr);
                else
                    injector::WriteMemory(xref,
                                          m_array + (m_elementSize * m_elementsCount * m_increaseby) + (v - maxArrayOffset),
                                          true);
            });
        }

        TaceLog("[limits] %s: OK - %zu xrefs repointed, %zu -> %zu elements",
                m_name, found, m_elementsCount, m_elementsCount * m_increaseby);
        m_patchedXrefs = true;
        return *this;
    }

    // Rewrites the hardcoded element counts the game compares against. Only runs
    // once the array itself has actually been moved.
    template<typename... Pointers>
    LimitAdjuster &ReplaceNumericRefs(Pointers... pointers)
    {
        if (m_patchedNumRefs || !m_patchedXrefs)
            return *this;

        const std::initializer_list<intptr_t> list = { static_cast<intptr_t>(pointers)... };
        for (intptr_t v : list)
        {
            if (v == 0)
                continue;
            if (TryPatchCount<uint64_t>(v) || TryPatchCount<uint32_t>(v) ||
                TryPatchCount<uint16_t>(v) || TryPatchCount<uint8_t>(v))
                continue;
            TaceLog("[limits] %s: numeric ref at %p did not hold the expected count", m_name, (void *)v);
        }

        m_patchedNumRefs = true;
        return *this;
    }

private:
    template<typename Fn>
    void ForEachXref(ptrdiff_t offset, Fn &&fn)
    {
        const uintptr_t oldPtr = m_startAddress + offset;
        auto pattern = hook::pattern(pattern_str(to_bytes(oldPtr)));
        pattern.for_each_result([&](hook::pattern_match match)
        {
            uint32_t *xref = match.get<uint32_t>();
            if (*xref == oldPtr)
                fn(xref);
        });
    }

    template<typename T>
    bool TryPatchCount(intptr_t ptr)
    {
        const T val = injector::ReadMemory<T>(ptr, true);
        if (val == T(m_elementsCount))
        {
            injector::WriteMemory<T>(ptr, T(m_elementsCount * m_increaseby), true);
            return true;
        }
        if (val == T(m_elementsCount + 1))
        {
            injector::WriteMemory<T>(ptr, T(m_elementsCount * m_increaseby + 1), true);
            return true;
        }
        if (val == T(m_elementsCount - 1))
        {
            injector::WriteMemory<T>(ptr, T(m_elementsCount * m_increaseby - 1), true);
            return true;
        }
        return false;
    }

    const char           *m_name          = "<unnamed>";
    bool                  m_verbose       = true;
    size_t                m_increaseby    = 2;
    bool                  m_patchedXrefs  = false;
    bool                  m_patchedNumRefs = false;
    bool                  m_failed        = false;
    uintptr_t             m_startAddress  = 0;
    size_t                m_elementSize   = 0;
    size_t                m_elementsCount = 0;
    size_t                m_xrefCount     = 0;
    uint8_t              *m_array         = nullptr;
    std::vector<uint8_t> *m_storage       = nullptr;
};
