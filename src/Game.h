#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>

// Small helpers for reading game memory and finding code in GTAIV.exe, shared
// by the feature files.

template<typename T>
T Field(const void *base, size_t offset)
{
    return *reinterpret_cast<const T *>(static_cast<const uint8_t *>(base) + offset);
}

// The destination of a `call rel32` / `jmp rel32` at p.
inline uint8_t *CallTarget(uint8_t *p)
{
    return p + 5 + *reinterpret_cast<int32_t *>(p + 1);
}

// visit(section header, its first byte) for every section of GTAIV.exe.
template<typename F>
void ForEachSection(F visit)
{
    auto *mod = reinterpret_cast<uint8_t *>(GetModuleHandleA(nullptr));
    auto *nt  = reinterpret_cast<IMAGE_NT_HEADERS *>(mod + reinterpret_cast<IMAGE_DOS_HEADER *>(mod)->e_lfanew);
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        visit(*sec, mod + sec->VirtualAddress);
}

// The pointer to fn stored outside the code - its vtable slot. Null unless
// there is exactly one; `found` says how many there were.
inline uint32_t *FindDataSlot(const void *fn, int &found)
{
    const uint32_t value = uint32_t(uintptr_t(fn));
    uint32_t *slot = nullptr;
    found = 0;
    ForEachSection([&](const IMAGE_SECTION_HEADER &sec, uint8_t *begin) {
        if (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            return;
        auto *p   = reinterpret_cast<uint32_t *>(begin);
        auto *end = reinterpret_cast<uint32_t *>(begin + (sec.Misc.VirtualSize & ~3u));
        for (; p < end; p++)
            if (*p == value && found++ == 0)
                slot = p;
    });
    return found == 1 ? slot : nullptr;
}

// Every `call rel32` to target in the game's code: returns how many, and keeps
// the first `max` in sites.
inline int CallersOf(const uint8_t *target, uint8_t **sites, int max)
{
    int count = 0;
    ForEachSection([&](const IMAGE_SECTION_HEADER &sec, uint8_t *begin) {
        if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) || sec.Misc.VirtualSize < 5)
            return;
        for (uint8_t *p = begin, *end = begin + sec.Misc.VirtualSize - 5; p <= end; p++)
            if (*p == 0xE8 && CallTarget(p) == target)
            {
                if (count < max)
                    sites[count] = p;
                count++;
            }
    });
    return count;
}

// ---- peds -------------------------------------------------------------------

constexpr size_t kEntityModel  = 0x2E;   // int16 model index
constexpr size_t kPedAnimBlender = 0x78;

// CTask::getType - vtable +0x0C
inline int TaskType(const void *task)
{
    using GetTypeFn = int(__thiscall *)(const void *);
    return (*reinterpret_cast<GetTypeFn *const *>(task))[3](task);
}

// fn(anim) for every live animation on the ped, until fn returns true. The
// blender (ped +0x78) keeps a list from +0x1A28: node +0x8C next, +0x48 == 1
// live, +4 the animation (+0x04 flags, +0x08 blend group, +0x0C id, +0x34
// weight, +0x40 non-null when playing, +0x4C phase).
template<typename F>
void ForEachLiveAnim(const uint8_t *ped, F fn, int limit = 64)
{
    const uint8_t *blender = Field<uint8_t *>(ped, kPedAnimBlender);
    uint8_t *node = blender != nullptr ? Field<uint8_t *>(blender, 0x1A28) : nullptr;
    for (int n = 0; node != nullptr && n < limit; node = Field<uint8_t *>(node, 0x8C), n++)
    {
        uint8_t *anim = node + 4;
        if (Field<uint16_t>(node, 0x48) == 1 && Field<void *>(anim, 0x40) != nullptr && fn(anim))
            return;
    }
}
