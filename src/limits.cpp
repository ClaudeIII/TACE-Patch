#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Config.h"
#include "LimitAdjuster.h"
#include "Log.h"
#include "Patterns.h"

// ============================================================================
// Limit adjusters, ported from FusionFix (ThirteenAG/GTAIV.EFLC.FusionFix,
// source/limits.ixx).
//
// Every signature below goes through find_pattern(), which takes one variant per
// game build and uses whichever matches. That is how the Complete Edition is
// handled: when CE differs, ADD its signature as another argument rather than
// replacing the existing one.
//
// Nothing here writes to an instruction's address operand. The previous version
// of this file did - it took `get_first<void>(n)`, which is a POINTER TO the
// operand bytes, and wrote the new limit over it, turning e.g.
// `MOV ECX,[0x00C0FFEE]` into `MOV ECX,[0x000001C2]`. That is what crashed. To
// read the array's address you must dereference: `*get_first<uintptr_t>(n)`.
// ============================================================================

namespace
{
    // ------------------------------------------------------------------------
    // Configuration - TacePatch.ini, next to the .asi.
    //
    // The DEFAULTS ARE THE VALUES TACE NEEDS: the .wad limits are already raised
    // to what a full-DLC build requires, so the mod works correctly with no ini
    // present at all. The file only exists so those values can be pushed further
    // (or backed off) without a rebuild.
    //
    // The uncalibrated sections default to OFF. Their signatures are FusionFix's
    // and do not resolve correctly on this build yet - they abort safely rather
    // than half-patching, but there is no reason to run them until they're fixed.
    // ------------------------------------------------------------------------
    struct Config
    {
        int  animWadBlocks   = 4096;   // stock 1500 - REQUIRED by TACE (all DLC animations)
        int  carGenerators   = 4096;   // stock 1100, map and script together
        int  scriptCarGenerators = 128; // stock 25 - the first N of carGenerators
        std::vector<std::string> blipSprites;   // [BLIPSPRITES], ids 129 onwards
        bool enableHandling  = false;  // uncalibrated: 25 of 26 xrefs resolve
        int  handlingScale   = 2;
        bool enableCarcols   = false;  // uncalibrated: wrong operand offset for this build
        bool enableVehOffs   = false;  // uncalibrated: signature matches the wrong site
        bool enableWeaponInfo = false; // verified to resolve on this build; off until tested in game
        bool verboseXrefs    = true;   // per-offset xref counts in the log
    };

    Config gConfig;

    // TacePatch.ini beside the .asi. Deliberately uses the Win32 profile API
    // rather than deps/IniReader - that header needs std::string::starts_with,
    // which is C++20, and this project builds as C++17.
    std::string IniPath()
    {
        char buf[MAX_PATH]{};
        HMODULE hm = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(&IniPath), &hm);
        GetModuleFileNameA(hm, buf, MAX_PATH);
        std::string p = buf;
        const size_t dot = p.find_last_of('.');
        if (dot != std::string::npos)
            p = p.substr(0, dot);
        return p + ".ini";
    }

    void LoadConfig()
    {
        const std::string ini = IniPath();

        // Reads the value itself rather than using GetPrivateProfileInt, so the
        // trailing "// ..." comments in the ini (FusionFix's layout) are safely
        // ignored: strtol stops at the first character that isn't part of the
        // number, and anything unparseable falls back to the default.
        auto readInt = [&](const char *sec, const char *key, int def)
        {
            char buf[64]{};
            if (GetPrivateProfileStringA(sec, key, "", buf, sizeof(buf), ini.c_str()) == 0)
                return def;
            char *end = nullptr;
            const long v = strtol(buf, &end, 10);
            return (end == buf) ? def : static_cast<int>(v);
        };
        auto readBool = [&](const char *sec, const char *key, bool def)
        {
            return readInt(sec, key, def ? 1 : 0) != 0;
        };

        gConfig.animWadBlocks  = readInt("LIMITS", "AnimWadBlocks", gConfig.animWadBlocks);
        gConfig.carGenerators  = readInt("LIMITS", "CarGenerators", gConfig.carGenerators);
        gConfig.scriptCarGenerators = readInt("LIMITS", "ScriptCarGenerators", gConfig.scriptCarGenerators);
        gConfig.scriptCarGenerators = (std::max)(25, (std::min)(gConfig.scriptCarGenerators, 65535));
        gConfig.enableHandling = readBool("LIMITS", "Handling", gConfig.enableHandling);
        gConfig.handlingScale  = readInt("LIMITS", "HandlingScale", gConfig.handlingScale);
        gConfig.enableCarcols  = readBool("LIMITS", "Carcols", gConfig.enableCarcols);
        gConfig.enableVehOffs  = readBool("LIMITS", "VehicleOffsets", gConfig.enableVehOffs);
        gConfig.enableWeaponInfo = readBool("LIMITS", "WeaponInfo", gConfig.enableWeaponInfo);
        gConfig.verboseXrefs   = TaceTraceEnabled("limits") || readBool("DEBUG", "VerboseXrefs", gConfig.verboseXrefs);

        // Refuse nonsense rather than letting it reach a memory write.
        if (gConfig.animWadBlocks < 1500)
        {
            TaceLog("[limits] config: AnimWadBlocks=%d is below the stock 1500 - clamping. "
                    "TACE needs it RAISED, not lowered.", gConfig.animWadBlocks);
            gConfig.animWadBlocks = 1500;
        }
        if (gConfig.animWadBlocks > 65535)
            gConfig.animWadBlocks = 65535;
        if (gConfig.handlingScale < 2)
            gConfig.handlingScale = 2;
        if (gConfig.carGenerators < 1100)
        {
            TaceLog("[limits] config: CarGenerators=%d is below the stock 1100 - clamping", gConfig.carGenerators);
            gConfig.carGenerators = 1100;
        }
        if (gConfig.carGenerators > 65535)
            gConfig.carGenerators = 65535;   // the script natives take a 16-bit index

        // [BLIPSPRITES] <id> = <texture>, counting up from 129. The first missing
        // id ends the list - the game loads sprites in order, so there are no gaps.
        gConfig.blipSprites.clear();
        for (int id = 129; id < 129 + 256; id++)
        {
            const std::string name = TaceIniString("BLIPSPRITES", std::to_string(id).c_str());
            if (name.empty())
                break;
            gConfig.blipSprites.push_back(name);
        }

        TaceLog("[limits] config: AnimWadBlocks=%d CarGenerators=%d BlipSprites=+%zu Handling=%d(x%d) "
                "Carcols=%d VehOffs=%d WeaponInfo=%d",
                gConfig.animWadBlocks, gConfig.carGenerators, gConfig.blipSprites.size(),
                gConfig.enableHandling, gConfig.handlingScale,
                gConfig.enableCarcols, gConfig.enableVehOffs, gConfig.enableWeaponInfo);
    }

    // Guarded lookup - hook::pattern's internal count check is an assert(), which
    // is compiled out in Release, so calling get_first() on a pattern that found
    // nothing reads past the end of an empty vector. Always test first.
    bool Found(hook::pattern &pattern, const char *what)
    {
        if (pattern.empty())
        {
            TaceLog("[limits] %s: no signature matched, section skipped", what);
            return false;
        }
        return true;
    }

    // Overwrites a 32-bit immediate, but only if it currently holds exactly the
    // value we expect. A signature can go stale or match the wrong site on a
    // different build; checking the operand's current value first turns that into
    // a logged skip instead of a corrupted instruction.
    void PokeImmediate(const char *what, hook::pattern &pattern, ptrdiff_t offset,
                       uint32_t expected, uint32_t newValue)
    {
        if (!Found(pattern, what))
            return;

        uint32_t *imm = pattern.get_first<uint32_t>(offset);
        const uint32_t current = *imm;
        if (current != expected)
        {
            TaceLog("[limits] %s: ABORTED - operand reads %u, expected %u. Wrong site; not patched.",
                    what, current, expected);
            return;
        }

        injector::WriteMemory<uint32_t>(imm, newValue, true);
        TaceLog("[limits] %s: OK - %u -> %u", what, current, newValue);
    }

    // Animation .wad limit - the one TBoGT dies on with full DLC content.
    //
    // The engine registers an asset store named "AnimManager" for the "wad"
    // extension, sized 1500, and a matching "Anim Manager" pool also sized 1500:
    //
    //     push "Anim Manager" ; push 1500 ; call <pool init>
    //     ...
    //     push 1500 ; push "wad" ; push "AnimManager" ; call <register store>
    //     mov [0x00F49830], eax        <- the store
    //
    // Both counts are raised together; raising one without the other just moves
    // the overflow. Each signature is unique in the binary and value-checked
    // against 1500 before anything is written.
    //
    // NOTE: every absolute address here (the string pointers) is WILDCARDED on
    // purpose. GTAIV.exe is ASLR-relocated, so the loader rewrites baked-in
    // addresses at load time - a signature containing one matches the file on
    // disk but NEVER the loaded module. Only opcodes and immediates are safe.
    void AdjustAnimWadBlocks()
    {
        constexpr uint32_t kStock = 1500;
        const uint32_t kNew = uint32_t(gConfig.animWadBlocks);

        if (kNew == kStock)
        {
            TaceLog("[limits] animwad: left at stock 1500 by config");
            return;
        }

        // push <"Anim Manager"> ; push 1500 ; call ; add esp,8
        auto pool = find_pattern("68 ? ? ? ? 68 DC 05 00 00 E8 ? ? ? ? 83 C4 08");
        PokeImmediate("animwad.pool", pool, 6, kStock, kNew);

        // push 1500 ; push <"wad"> ; push <"AnimManager"> ; call ; mov ecx,eax
        auto store = find_pattern("68 DC 05 00 00 68 ? ? ? ? 68 ? ? ? ? E8 ? ? ? ? 8B C8");
        PokeImmediate("animwad.store", store, 1, kStock, kNew);
    }

    void AdjustHandling()
    {
        const size_t increaseby = size_t(gConfig.handlingScale);
        constexpr size_t ms_iStandardLines = 160;
        constexpr size_t ms_iBikeLines = 40;
        constexpr size_t ms_iFlyingLines = 40;
        constexpr size_t ms_iBoatLines = 40;

        const size_t ms_iStandardLinesLimit = ms_iStandardLines * increaseby;
        const size_t ms_iBikeLinesLimit = ms_iBikeLines * increaseby;
        const size_t ms_iFlyingLinesLimit = ms_iFlyingLines * increaseby;
        const size_t ms_iBoatLinesLimit = ms_iBoatLines * increaseby;

        auto basePattern = find_pattern("8D B0 ? ? ? ? 57 8B CE E8 ? ? ? ? 8B CE E8",
                                        "8D B0 ? ? ? ? 53 8B CE E8 ? ? ? ? 8B CE E8 ? ? ? ? 6A 01 55");
        if (!Found(basePattern, "handling"))
            return;

        static std::vector<uint8_t> handling(
            (0x110 * ms_iStandardLinesLimit) + (0x40 * ms_iBikeLinesLimit) +
                (0x60 * ms_iFlyingLinesLimit) + (0xE0 * ms_iBoatLinesLimit),
            0);   // sized from the configured scale

        const uintptr_t aHandlingLines = *basePattern.get_first<uintptr_t>(2);
        const uintptr_t aFlyingHandlingLines = aHandlingLines + (0x110 * ms_iStandardLines) + (0x40 * ms_iBikeLines);
        const uintptr_t aBoatHandlingLines = aFlyingHandlingLines + (0x60 * ms_iFlyingLines);

        // The four handling tables are CONTIGUOUS inside one region based at
        // aHandlingLines - bike/flying/boat sit inside it, which is why upstream
        // needs no separate bike adjuster (xref offsets 0xAA00/0xAAFC already
        // reach into the bike area). So if the standard move fails, the region
        // has NOT grown and raising any of the parser's counts below would make
        // it write past the end of a 160-entry array. All of it hangs together.
        auto standard = LimitAdjuster(aHandlingLines, 0x110, ms_iStandardLines, 26)
            .Named("handling.standard")
            .Verbose(gConfig.verboseXrefs)
            .IncreaseBy(increaseby)
            .InsertNewArrayPointer(handling.data())
            .ReplaceXrefs(0x0, 0xF8, 0xFC, 0x100, 0x5F60, 0xAA00, 0xAAFC);

        if (!standard.Succeeded())
        {
            TaceLog("[limits] handling: standard table did not move - skipping ALL handling "
                    "count/bound patches (raising them now would overflow the original array)");
            return;
        }

        // Bike lines are deliberately left alone - upstream has this commented out.

        LimitAdjuster(aFlyingHandlingLines, 0x40, ms_iFlyingLines, 5)
            .Named("handling.flying")
            .Verbose(gConfig.verboseXrefs)
            .IncreaseBy(increaseby)
            .InsertNewArrayPointer(handling.data() + (0x110 * ms_iStandardLinesLimit) + (0x40 * ms_iBikeLinesLimit))
            .ReplaceXrefs(0);

        LimitAdjuster(aBoatHandlingLines, 0x40, ms_iBoatLines, 5)
            .Named("handling.boat")
            .Verbose(gConfig.verboseXrefs)
            .IncreaseBy(increaseby)
            .InsertNewArrayPointer(handling.data() + (0x110 * ms_iStandardLinesLimit) +
                                   (0x40 * ms_iBikeLinesLimit) + (0x60 * ms_iFlyingLinesLimit))
            .ReplaceXrefs(0);

        // The loop bounds the parser compares against.
        auto p = find_pattern("BF 9F 00 00 00 8D 64 24 ? 8B CE E8 ? ? ? ? 81 C6 ? ? ? ? 4F 79 ? 5F 5E C3",
                              "BE 9F ? ? ? EB 03 8D 49 00 8B CA E8 ? ? ? ? 81 C2 ? ? ? ? 83 EE 01 79 EE 5E C3");
        if (Found(p, "handling.standardCount"))
            injector::WriteMemory(p.get_first(1), int(ms_iStandardLinesLimit - 1), true);

        p = find_pattern("BF ? ? ? ? 8D 64 24 00 8B CE E8 ? ? ? ? 83 C6 40 4F 79 F3 5F 5E C3 56 57 BE ? ? ? ? BF ? ? ? ? 8D 64 24 00 8B CE E8 ? ? ? ? 81 C6 ? ? ? ? 4F 79 F0 5F",
                         "BA ? ? ? ? 8D 9B ? ? ? ? E8 ? ? ? ? 83 C1 40 83 EA 01 79 F3 C3");
        if (Found(p, "handling.bikeCount"))
            injector::WriteMemory(p.get_first(1), int(ms_iBikeLinesLimit - 1), true);

        p = find_pattern("BF ? ? ? ? 8D 64 24 00 8B CE E8 ? ? ? ? 83 C6 60 4F 79 F3 5F 5E C3 56",
                         "BA ? ? ? ? 8D 9B ? ? ? ? E8 ? ? ? ? 83 C1 60 83 EA 01 79 F3 C3");
        if (Found(p, "handling.flyingCount"))
            injector::WriteMemory(p.get_first(1), int(ms_iFlyingLinesLimit - 1), true);

        p = find_pattern("BF 27 00 00 00 8D 64 24 ? 8B CE E8 ? ? ? ? 81 C6 ? ? ? ? 4F 79 ? 5F 5E C3",
                         "BA 27 ? ? ? 8D 9B ? ? ? ? E8 ? ? ? ? 81 C1 ? ? ? ? 83 EA 01 79 F0 C3");
        if (Found(p, "handling.boatCount"))
            injector::WriteMemory(p.get_first(1), int(ms_iBoatLinesLimit - 1), true);

        // Bounds checks that would otherwise reject the raised counts.
        p = find_pattern("7D 1B 8B C2", "7D 19 56 8B F2");
        if (Found(p, "handling.bikeBound"))
            injector::MakeNOP(p.get_first(), 2);

        p = find_pattern("7D 1C 8D 04 52", "7D 1A 56 8D 34 49");
        if (Found(p, "handling.flyingBound"))
            injector::MakeNOP(p.get_first(), 2);

        p = find_pattern("7D 1E 8B C2", "7D 1C 56 8B F2");
        if (Found(p, "handling.boatBound"))
            injector::MakeNOP(p.get_first(), 2);
    }

    void AdjustCarcols()
    {
        auto p = find_pattern("8B 87 ? ? ? ? 25 ? ? ? ? 0B C8 89 8F",
                              "8B 94 36 ? ? ? ? 03 F6 33 C0 8A A4 24 ? ? ? ? 81 E2 ? ? ? ? C1 E1 10 0B CA");
        auto r1 = find_pattern("81 3D ? ? ? ? ? ? ? ? 0F 8D ? ? ? ? 8D 84 24",
                               "81 3D ? ? ? ? ? ? ? ? 0F 8D ? ? ? ? 8D 8C 24 ? ? ? ? 51 8D 94 24 ? ? ? ? 52 8D 84 24 ? ? ? ? 50");
        auto r2 = find_pattern("81 FA ? ? ? ? 0F 8D ? ? ? ? 42",
                               "81 3D ? ? ? ? ? ? ? ? 0F 8D ? ? ? ? 83 05 ? ? ? ? ? E9 ? ? ? ? 83 FD 02");

        if (!Found(p, "carcols.colors") || !Found(r1, "carcols.ref1") || !Found(r2, "carcols.ref2"))
            return;

        // The scanner tables below are indexed by colour id, so growing them is
        // pointless - and needless risk - unless the main colour array grew too.
        if (!LimitAdjuster(*p.get_first<uintptr_t>(2), 4, 196, 23)
                 .Named("carcols.colors")
            .Verbose(gConfig.verboseXrefs)
                 .ReplaceXrefs(0)
                 .ReplaceNumericRefs((intptr_t)r1.get_first(6), (intptr_t)r2.get_first(2))
                 .Succeeded())
        {
            TaceLog("[limits] carcols: colour array did not move - skipping scanner tables");
            return;
        }

        p = find_pattern("8B 04 8D ? ? ? ? 89 06", "8B 0C 85 ? ? ? ? 89 0E");
        if (Found(p, "carcols.scannerPrefixes"))
        {
            LimitAdjuster(*p.get_first<uintptr_t>(3), 4, 197, 3)
                .Named("carcols.scannerPrefixes")
            .Verbose(gConfig.verboseXrefs)
                .ReplaceXrefs(0);
        }

        p = find_pattern("8B 04 8D ? ? ? ? 89 46 04", "8B 14 85 ? ? ? ? 89 56 04");
        if (Found(p, "carcols.scannerColors"))
        {
            LimitAdjuster(*p.get_first<uintptr_t>(3), 4, 196, 3)
                .Named("carcols.scannerColors")
            .Verbose(gConfig.verboseXrefs)
                .ReplaceXrefs(0);
        }
    }

    // WeaponInfo table: 60 entries -> 120.
    //
    // Verified against this build before shipping: all four signatures match
    // exactly once, the array resolves to 0x0124A600 in .data, and the twelve
    // xref offsets total exactly the 16 references upstream expects. That is why
    // this one is portable while handling/carcols/vehoff are not.
    //
    // NOT ported from upstream: FusionFix also installs a safetyhook inline hook
    // on GetWeaponInfoIdByHash to register *custom* (mod-added) weapons into the
    // enlarged table. This project has no safetyhook dependency. Episodic weapons
    // are already known to the game, so the raise alone should serve TACE - but
    // weapons added by other mods will not claim the new slots.
    void AdjustWeaponInfo()
    {
        auto base = find_pattern("81 C3 ? ? ? ? 89 03", "81 C7 ? ? ? ? 89 07");
        auto r1 = find_pattern("BF ? ? ? ? 8D 64 24 00 8B CE E8 ? ? ? ? 81 C6 ? ? ? ? 4F 79 F0 68 ? ? ? ? E8 ? ? ? ? 83 C4 04 5F 5E C3 56",
                               "BE ? ? ? ? EB 03 8D 49 00 E8 ? ? ? ? 81 C1 ? ? ? ? 83 EE 01 79 F0 68 ? ? ? ? E8 ? ? ? ? 83 C4 04 5E C3");
        auto r2 = find_pattern("83 F8 3C 7C F1", "83 F8 3C 7C EF");

        if (!Found(base, "weaponinfo") || !Found(r1, "weaponinfo.ref1") || !Found(r2, "weaponinfo.ref2"))
            return;

        auto info = LimitAdjuster(*base.get_first<uintptr_t>(2), 0x110, 60, 16)
                        .Named("weaponinfo")
                        .Verbose(gConfig.verboseXrefs)
                        .ReplaceXrefs(0, 0x24, 0x1A98, 0x1A9C, 0x1AB4, 0x1B30,
                                      0x3430, 0x3540, 0x363C, 0x3870, 0x3980, 0x3DC0)
                        .ReplaceNumericRefs((intptr_t)r1.get_first(1), (intptr_t)r2.get_first(2));

        // Only lift the bounds check once the table has actually grown - NOPing
        // it against a still-60-entry array is how you get a silent overflow.
        if (!info.Succeeded())
        {
            TaceLog("[limits] weaponinfo: table did not move - leaving the bounds check intact");
            return;
        }

        auto bound = find_pattern("7D 0C 69 C0");
        if (Found(bound, "weaponinfo.bound"))
        {
            injector::MakeNOP(bound.get_first(), 2);
            TaceLog("[limits] weaponinfo.bound: OK - bounds check lifted");
        }
    }

    void AdjustVehicleOffsets()
    {
        auto p = find_pattern("81 C7 ? ? ? ? 83 BB", "81 C7 ? ? ? ? 83 BE");
        if (!Found(p, "vehoff"))
            return;

        LimitAdjuster(*p.get_first<uintptr_t>(2), 640, 205, 6)
            .Named("vehoff")
            .Verbose(gConfig.verboseXrefs)
            .ReplaceXrefs(0, 0x1C0, 0x1E0);
    }

    // ------------------------------------------------------------------------
    // Moving a table that code reaches by absolute address.
    //
    // LimitAdjuster finds references by searching for an address's bytes. The
    // two tables below also need to know HOW each reference uses the address -
    // a loop's end test has to follow the table, while a variable that happens
    // to sit just past it must stay put - so they scan once and classify.
    // ------------------------------------------------------------------------

    struct CodeRef
    {
        uint8_t  *at;      // the 4-byte operand
        uint32_t  value;   // what it holds, already relocated by the loader
    };

    bool Readable(const void *p, size_t len)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
            return false;
        return uintptr_t(p) + len <= uintptr_t(mbi.BaseAddress) + mbi.RegionSize;
    }

    // Every absolute address in GTAIV.exe's code that points into [lo, hi).
    //
    // Read off the image's base relocation table - the list the loader walked to
    // apply ASLR - so each hit really is an address operand. A raw byte scan
    // also meets constants that only look like one, and once ASLR has moved the
    // image, some of those (colours such as 0x00FF8xxx) land inside a table's
    // new range: that is what failed the first in-game run. An exe without
    // relocations has not moved, so the byte scan is still right for it.
    std::vector<CodeRef> CodeRefsInRange(uint32_t lo, uint32_t hi)
    {
        std::vector<CodeRef> out;
        auto *mod = reinterpret_cast<uint8_t *>(GetModuleHandleA(nullptr));
        auto *nt  = reinterpret_cast<IMAGE_NT_HEADERS *>(mod + reinterpret_cast<IMAGE_DOS_HEADER *>(mod)->e_lfanew);

        // 8 bytes of slack at each end of a section, so the encoding checks can
        // look around an operand without leaving it.
        auto inCode = [&](uint32_t rva)
        {
            const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
                if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                    rva >= sec->VirtualAddress + 8 && rva + 12 <= sec->VirtualAddress + sec->Misc.VirtualSize)
                    return true;
            return false;
        };

        const IMAGE_DATA_DIRECTORY &relocs = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocs.VirtualAddress != 0 && relocs.Size != 0 && Readable(mod + relocs.VirtualAddress, relocs.Size))
        {
            const uint8_t *at  = mod + relocs.VirtualAddress;
            const uint8_t *end = at + relocs.Size;
            while (at + sizeof(IMAGE_BASE_RELOCATION) <= end)
            {
                const auto *block = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(at);
                if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || at + block->SizeOfBlock > end)
                    break;
                const auto *entry = reinterpret_cast<const WORD *>(block + 1);
                const size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (size_t i = 0; i < count; i++)
                {
                    if ((entry[i] >> 12) != IMAGE_REL_BASED_HIGHLOW)
                        continue;
                    const uint32_t rva = block->VirtualAddress + (entry[i] & 0xFFF);
                    if (!inCode(rva))
                        continue;
                    uint8_t *p = mod + rva;
                    const uint32_t v = *reinterpret_cast<const uint32_t *>(p);
                    if (v - lo < hi - lo)
                        out.push_back({ p, v });
                }
                at += block->SizeOfBlock;
            }
            return out;
        }

        const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) || sec->Misc.VirtualSize < 16)
                continue;
            uint8_t *p   = mod + sec->VirtualAddress + 8;
            uint8_t *end = mod + sec->VirtualAddress + sec->Misc.VirtualSize - 8;
            for (; p < end; p++)
            {
                const uint32_t v = *reinterpret_cast<const uint32_t *>(p);
                if (v - lo < hi - lo)
                    out.push_back({ p, v });
            }
        }
        return out;
    }

    // True if [addr, addr + len) lies inside one writable section of GTAIV.exe -
    // it really is a static table, not somewhere a stale signature led.
    bool InWritableImage(uintptr_t addr, size_t len)
    {
        auto *mod = reinterpret_cast<uint8_t *>(GetModuleHandleA(nullptr));
        auto *nt  = reinterpret_cast<IMAGE_NT_HEADERS *>(mod + reinterpret_cast<IMAGE_DOS_HEADER *>(mod)->e_lfanew);
        auto *sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            const uintptr_t lo = uintptr_t(mod) + sec->VirtualAddress;
            const uintptr_t hi = lo + sec->Misc.VirtualSize;
            if ((sec->Characteristics & IMAGE_SCN_MEM_WRITE) && addr >= lo && addr + len <= hi)
                return true;
        }
        return false;
    }

    // Zeroed memory for a moved table, never freed - the game uses it until the
    // process is gone. Every loop over these tables ends on a SIGNED pointer
    // compare (jl), so a block straddling 2 GB would end them after one entry:
    // refuse one rather than find out in game.
    void *AllocTable(size_t bytes)
    {
        void *p = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (p != nullptr && int32_t(uintptr_t(p)) > int32_t(uintptr_t(p) + bytes + 0x40))
        {
            VirtualFree(p, 0, MEM_RELEASE);
            p = nullptr;
        }
        return p;
    }

    struct RefCheck
    {
        const char *role;
        size_t      found;
        size_t      expected;
    };

    // Each role's count against what the known builds hold. Nothing is written
    // unless all of them agree.
    bool AllMatch(const char *what, std::initializer_list<RefCheck> checks)
    {
        bool ok = true;
        for (const RefCheck &c : checks)
        {
            if (gConfig.verboseXrefs || c.found != c.expected)
                TaceLog("[limits] %s:   %-20s %zu (expected %zu)%s", what, c.role, c.found, c.expected,
                        c.found != c.expected ? "  <-- differs" : "");
            ok &= (c.found == c.expected);
        }
        if (!ok)
            TaceLog("[limits] %s: ABORTED - references do not match the known layout. Nothing patched.", what);
        return ok;
    }

    // `add <reg>, 2Ch ; cmp <reg>, <operand> ; jl` - the end test of a loop that
    // steps through 44-byte car generator entries.
    bool IsCarGenLoopEnd(const uint8_t *op)
    {
        const bool cmpEax = op[-4] == 0x83 && op[-3] == 0xC0 && op[-2] == 0x2C && op[-1] == 0x3D;
        const bool cmpReg = op[-5] == 0x83 && op[-4] == (0xC0 | (op[-1] & 7)) && op[-3] == 0x2C &&
                            op[-2] == 0x81 && (op[-1] & 0xF8) == 0xF8;
        const bool jl     = op[4] == 0x7C || (op[4] == 0x0F && op[5] == 0x8C);
        return (cmpEax || cmpReg) && jl;
    }

    // Car generators: 1100 slots -> CarGenerators.
    //
    // One static array of 44-byte entries. __createCarGenerator gives slots 0-24
    // to script generators and 25-1099 to the ones each map IPL adds as it
    // streams in; with no free slot the generator is silently dropped. Only slots
    // 0-24 go into the savegame, so a longer table leaves the save format alone.
    //
    // References, the same on EFLC 1.1.2.0 (IDA) and 1.0.8.0 (whole-.text scan):
    //   array+0x00  11   index -> entry (imul 2Ch ; add <array>), save/load loops
    //   array+0x08   2   loop starts over the +8 field
    //   array+0x29   4   loop starts over the flags byte
    //   end          2   loop ends - plus 5 uses of the generator COUNT stored there
    //   end+0x08     2   loop ends - plus 3 uses of the next table (15 x 16 B, saved)
    //   end+0x29     3   loop ends
    //   1100         3   the free-slot search bound and the per-frame update window
    // The count and the next table stay where they are; only the loop ends move.
    void AdjustCarGenerators()
    {
        constexpr uint32_t kStock = 1100;
        constexpr uint32_t kEntry = 44;
        constexpr uint32_t kFields[3] = { 0, 8, 0x29 };
        const uint32_t slots = uint32_t(gConfig.carGenerators);

        if (slots == kStock)
        {
            TaceLog("[limits] cargens: left at stock 1100 by config");
            return;
        }

        // mov eax,25 ; mov ecx,1100 ; jz ; xor eax,eax ; mov ecx,25 ; cmp eax,ecx ;
        // push esi ; mov esi,eax ; jge ; imul eax,2Ch ; add eax,<array+29h>
        auto create = find_pattern("B8 19 00 00 00 B9 4C 04 00 00 74 07 33 C0 B9 19 00 00 00 3B C1 56 8B F0 7D 18 6B C0 2C 05 ? ? ? ?");
        // imul esi,1100 ; lea ecx,[esi+1100] ; mov eax,2AAAAAABh - a sixth of the table per frame
        auto update = find_pattern("69 F6 4C 04 00 00 8D 8E 4C 04 00 00 B8 AB AA AA 2A");
        if (!Found(create, "cargens.create") || !Found(update, "cargens.update"))
            return;

        const uintptr_t array = *create.get_first<uint32_t>(30) - 0x29;
        const uintptr_t end   = array + kEntry * kStock;
        if (!InWritableImage(array, kEntry * kStock + 0x30))
        {
            TaceLog("[limits] cargens: ABORTED - table address %p is not in GTAIV.exe's data. Nothing patched.",
                    (void *)array);
            return;
        }

        std::vector<uint8_t *> starts[3], ends[3];
        size_t neighbours[3] = {};
        for (const CodeRef &r : CodeRefsInRange(uint32_t(array), uint32_t(end + 0x2A)))
        {
            for (int k = 0; k < 3; k++)
            {
                if (r.value == array + kFields[k])
                    starts[k].push_back(r.at);
                else if (r.value == end + kFields[k])
                    IsCarGenLoopEnd(r.at) ? ends[k].push_back(r.at) : void(neighbours[k]++);
            }
        }

        if (!AllMatch("cargens", {
                { "array refs",          starts[0].size(), 11 },
                { "array+8 refs",        starts[1].size(),  2 },
                { "flags refs",          starts[2].size(),  4 },
                { "end loop tests",      ends[0].size(),    2 },
                { "count (stays)",       neighbours[0],     5 },
                { "end+8 loop tests",    ends[1].size(),    2 },
                { "next table (stays)",  neighbours[1],     3 },
                { "flags loop tests",    ends[2].size(),    3 },
                { "other past flags",    neighbours[2],     0 } }))
            return;

        auto *table = static_cast<uint8_t *>(AllocTable(size_t(kEntry) * slots));
        if (table == nullptr)
        {
            TaceLog("[limits] cargens: ABORTED - could not allocate %u slots. Nothing patched.", slots);
            return;
        }
        memcpy(table, reinterpret_cast<const void *>(array), kEntry * kStock);
        const uintptr_t newEnd = uintptr_t(table) + kEntry * slots;

        size_t moved = 0;
        for (int k = 0; k < 3; k++)
        {
            for (uint8_t *at : starts[k])
                injector::WriteMemory<uint32_t>(at, uint32_t(uintptr_t(table) + kFields[k]), true), moved++;
            for (uint8_t *at : ends[k])
                injector::WriteMemory<uint32_t>(at, uint32_t(newEnd + kFields[k]), true), moved++;
        }
        injector::WriteMemory<uint32_t>(create.get_first(6), slots, true);
        injector::WriteMemory<uint32_t>(update.get_first(2), slots, true);
        injector::WriteMemory<uint32_t>(update.get_first(8), slots, true);

        TaceLog("[limits] cargens: OK - %zu refs moved, 1100 -> %u slots (%u for map generators)",
                moved, slots, slots - 25);
    }

    // ------------------------------------------------------------------------
    // Script car generators: slots 0-24 -> 0 to ScriptCarGenerators-1.
    //
    // CREATE_CAR_GENERATOR only ever gets slots 0-24; the map's IPL generators
    // start at 25. Two immediates in __createCarGenerator set that split. The
    // hard part is the savegame.
    //
    // The "CarGenerators" save block is slots 0-24 plus two small tables, 1344
    // bytes, and GTA IV cannot take a block of another size: before loading it
    // dry-runs every handler to measure the blocks, allocates the load buffer
    // from that, and then rejects any block whose stored size differs. So the
    // block stays byte-for-byte vanilla, and script slots from 25 up are kept in
    // a small side file per save, in the Saves folder beside the .asi.
    //
    // The side file is named after a hash of everything the save holds before
    // this block - scripts, player, clock and the rest - which is the same bytes
    // in memory while saving as in the file when it is loaded back. So it needs
    // no save slot number and follows the save wherever the pair is copied. A
    // save without one loads as before, with script slots 25 and up empty.
    // ------------------------------------------------------------------------

    constexpr uint32_t kCgEntry       = 44;
    constexpr uint32_t kCgStockScript = 25;
    constexpr uint32_t kSaveHeader    = 272;          // version, size, globals size, "SAVE", 256-byte name
    constexpr uint32_t kSideMagic     = 0x31474354;   // "TCG1"

    struct SideFileHeader
    {
        uint32_t magic;       // kSideMagic
        uint32_t firstSlot;   // 25
        uint32_t count;       // slots stored from firstSlot
        uint32_t entrySize;   // 44
        // then slots 0-24 exactly as saved, to recognise the save, then `count` slots
    };

    struct
    {
        char (__cdecl *origSave)() = nullptr;
        char (__cdecl *origLoad)() = nullptr;
        const uintptr_t *desc   = nullptr;   // -> the save descriptor, whose first field is the buffer
        const uint32_t  *cursor = nullptr;   // bytes the save buffer has been read or written up to
        const uint8_t   *dryRun = nullptr;   // set while the game only measures block sizes
        const uint8_t   *error  = nullptr;   // set once a read or write has failed
        uint8_t         *table  = nullptr;   // slot 0
        uint32_t         slots  = kCgStockScript;
        std::string      dir;
    } gScriptCg;

    // Does the code at p match sig ("A1 ? ? ? ? 56 ...")?
    bool MatchAt(const uint8_t *p, const char *sig)
    {
        for (const char *s = sig; *s != '\0';)
        {
            if (*s == ' ')
            {
                s++;
                continue;
            }
            if (*s == '?')
            {
                while (*s == '?')
                    s++;
                p++;
                continue;
            }
            char *next = nullptr;
            const unsigned long v = strtoul(s, &next, 16);
            if (next == s || *p++ != uint8_t(v))
                return false;
            s = next;
        }
        return true;
    }

    uint64_t Fnv1a64(const uint8_t *p, size_t n)
    {
        uint64_t h = 0xCBF29CE484222325ull;
        for (size_t i = 0; i < n; i++)
            h = (h ^ p[i]) * 0x100000001B3ull;
        return h;
    }

    // The side file for the save being written or read, given where the
    // CarGenerators block starts in its buffer. Empty if the buffer is not there.
    std::string SideFilePath(uint32_t blockStart)
    {
        const uintptr_t desc = *gScriptCg.desc;
        const uint8_t *buffer = desc ? *reinterpret_cast<const uint8_t *const *>(desc) : nullptr;
        if (buffer == nullptr || blockStart <= kSaveHeader)
            return {};

        char name[48];
        snprintf(name, sizeof(name), "cargens_%016llx.bin",
                 static_cast<unsigned long long>(Fnv1a64(buffer + kSaveHeader, blockStart - kSaveHeader)));
        return gScriptCg.dir + name;
    }

    void StoreScriptCarGens(uint32_t blockStart)
    {
        uint32_t used = 0;   // one past the highest occupied script slot
        for (uint32_t i = kCgStockScript; i < gScriptCg.slots; i++)
            if (gScriptCg.table[i * kCgEntry + 0x29] & 0x10)
                used = i + 1;
        if (used == 0)
            return;   // nothing past 24 - the save alone restores everything

        const std::string path = SideFilePath(blockStart);
        if (path.empty())
            return;

        CreateDirectoryA(gScriptCg.dir.c_str(), nullptr);
        HANDLE f = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE)
        {
            TaceLog("[limits] scriptcargens: could not write %s (error %lu) - script slots past 24 are not saved",
                    path.c_str(), GetLastError());
            return;
        }

        const SideFileHeader header{ kSideMagic, kCgStockScript, used - kCgStockScript, kCgEntry };
        DWORD written = 0;
        bool ok = WriteFile(f, &header, sizeof(header), &written, nullptr) && written == sizeof(header);
        ok = ok && WriteFile(f, gScriptCg.table, kCgStockScript * kCgEntry, &written, nullptr);
        ok = ok && WriteFile(f, gScriptCg.table + kCgStockScript * kCgEntry, header.count * kCgEntry, &written, nullptr);
        CloseHandle(f);

        if (ok)
            TaceLog("[limits] scriptcargens: saved slots 25-%u -> %s", used - 1, path.c_str());
        else
            TaceLog("[limits] scriptcargens: writing %s failed - script slots past 24 are not saved", path.c_str());
    }

    void RestoreScriptCarGens(uint32_t blockStart)
    {
        // Loading replaces every script slot in vanilla, so the extra ones start
        // empty whether or not this save has a side file.
        uint8_t *extra = gScriptCg.table + kCgStockScript * kCgEntry;
        memset(extra, 0, (gScriptCg.slots - kCgStockScript) * kCgEntry);

        const std::string path = SideFilePath(blockStart);
        if (path.empty())
            return;
        HANDLE f = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE)
            return;   // saved with nothing past 24, or before this existed

        SideFileHeader header{};
        std::vector<uint8_t> stock(kCgStockScript * kCgEntry);
        DWORD got = 0;
        bool ok = ReadFile(f, &header, sizeof(header), &got, nullptr) && got == sizeof(header) &&
                  header.magic == kSideMagic && header.firstSlot == kCgStockScript && header.entrySize == kCgEntry &&
                  ReadFile(f, stock.data(), DWORD(stock.size()), &got, nullptr) && got == stock.size();

        // The slots 0-24 it was written with must be the ones this save just
        // restored - anything else is a hash collision or a hand-copied file.
        if (ok && memcmp(stock.data(), gScriptCg.table, stock.size()) != 0)
        {
            TaceLog("[limits] scriptcargens: %s does not belong to this save - ignored", path.c_str());
            CloseHandle(f);
            return;
        }

        const uint32_t keep = (std::min)(header.count, gScriptCg.slots - kCgStockScript);
        ok = ok && ReadFile(f, extra, keep * kCgEntry, &got, nullptr) && got == keep * kCgEntry;
        CloseHandle(f);

        if (!ok)
        {
            memset(extra, 0, (gScriptCg.slots - kCgStockScript) * kCgEntry);
            TaceLog("[limits] scriptcargens: %s is damaged - script slots past 24 left empty", path.c_str());
            return;
        }
        TaceLog("[limits] scriptcargens: restored slots 25-%u from %s", kCgStockScript + keep - 1, path.c_str());
        if (header.count > keep)
            TaceLog("[limits] scriptcargens: %u slot(s) dropped - ScriptCarGenerators is lower than when saved",
                    header.count - keep);
    }

    // The game's CarGenerators handlers, wrapped. Both also run in the measuring
    // pass, where nothing is really read or written - the side file is left alone.
    char __cdecl CarGenSaveHook()
    {
        const bool real = *gScriptCg.dryRun == 0;
        const uint32_t start = *gScriptCg.cursor;
        const char ok = gScriptCg.origSave();
        if (ok && real && *gScriptCg.error == 0)
            StoreScriptCarGens(start);
        return ok;
    }

    char __cdecl CarGenLoadHook()
    {
        const bool real = *gScriptCg.dryRun == 0;
        const uint32_t start = *gScriptCg.cursor;
        const char ok = gScriptCg.origLoad();
        if (ok && real && *gScriptCg.error == 0)
            RestoreScriptCarGens(start);
        return ok;
    }

    // The save/load primitive a handler calls: handler+13h is `call <thunk>`, the
    // thunk a `jmp`. Null unless both look like that.
    const uint8_t *SavePrimitive(const uint8_t *handler)
    {
        const uint8_t *call = handler + 0x13;
        if (call[0] != 0xE8)
            return nullptr;
        const uint8_t *thunk = call + 5 + *reinterpret_cast<const int32_t *>(call + 1);
        if (thunk[0] != 0xE9)
            return nullptr;
        return thunk + 5 + *reinterpret_cast<const int32_t *>(thunk + 1);
    }

    void AdjustScriptCarGenerators()
    {
        const uint32_t script = uint32_t(gConfig.scriptCarGenerators);
        if (script == kCgStockScript)
        {
            TaceLog("[limits] scriptcargens: left at stock 25 by config");
            return;
        }

        // AdjustCarGenerators' site with the table size wildcarded - it may have been raised already.
        auto create = find_pattern("B8 19 00 00 00 B9 ? ? ? ? 74 07 33 C0 B9 19 00 00 00 3B C1 56 8B F0 7D 18 6B C0 2C 05");
        // The save and load handlers: push esi ; push edi ; mov esi,<table> ; mov edi,25 ; ... call <write/read>
        auto handlers = find_pattern<2>("56 57 BE ? ? ? ? BF 19 00 00 00 8D 64 24 00 6A 2C 56 E8");
        if (!Found(create, "scriptcargens.create") || !Found(handlers, "scriptcargens.handlers"))
            return;

        const uint32_t total = *create.get_first<uint32_t>(6);
        if (handlers.size() != 2 || total < script + 1075)
        {
            TaceLog("[limits] scriptcargens: ABORTED - %s. Nothing patched.",
                    handlers.size() != 2 ? "expected exactly two save handlers"
                                         : "the map would get fewer than its stock 1075 slots - raise CarGenerators");
            return;
        }

        // Registered as push <save> ; push <load> ; push "CarGenerators" ; mov ecx,<list> ; call - the
        // save is the last argument, so it is pushed first.
        const auto h0 = uint32_t(uintptr_t(handlers.get(0).get<void>(0)));
        const auto h1 = uint32_t(uintptr_t(handlers.get(1).get<void>(0)));
        std::vector<uint8_t *> sites;
        for (const CodeRef &r : CodeRefsInRange((std::min)(h0, h1), (std::max)(h0, h1) + 1))
        {
            const uint32_t other = (r.value == h0) ? h1 : h0;
            if ((r.value == h0 || r.value == h1) && r.at[-1] == 0x68 && r.at[4] == 0x68 &&
                *reinterpret_cast<const uint32_t *>(r.at + 5) == other)
                sites.push_back(r.at);
        }

        const uint8_t *save = sites.size() == 1 ? reinterpret_cast<const uint8_t *>(uintptr_t(*reinterpret_cast<uint32_t *>(sites[0]))) : nullptr;
        const uint8_t *load = sites.size() == 1 ? reinterpret_cast<const uint8_t *>(uintptr_t(*reinterpret_cast<uint32_t *>(sites[0] + 5))) : nullptr;
        const uint8_t *write = save ? SavePrimitive(save) : nullptr;
        const uint8_t *read  = load ? SavePrimitive(load) : nullptr;

        // Both primitives share one body up to the memcpy; only its argument
        // order tells writing from reading - which also proves the push order.
        constexpr const char *kPrimitive =
            "A1 ? ? ? ? 56 8B 74 24 0C 01 35 ? ? ? ? 85 C0 75 0B C6 05 ? ? ? ? 01 32 C0 5E C3 01 70 04 "
            "80 3D ? ? ? ? 00 75 39 80 3D ? ? ? ? 00 75 E7 85 F6 7E 2C A1 ? ? ? ? 8B 0D ? ? ? ? 8D 14 30 3B 51 0C 77 C9";
        auto field = [](const uint8_t *p, size_t off) { return *reinterpret_cast<const uint32_t *>(p + off); };
        const bool ok = write && read &&
                        MatchAt(write, kPrimitive) && MatchAt(write + 0x4B, "8B 54 24 08 8B 09") &&
                        MatchAt(read, kPrimitive)  && MatchAt(read + 0x4B, "8B 09 8B 54 24 08") &&
                        field(write, 0x01) == field(read, 0x01) && field(write, 0x16) == field(read, 0x16) &&
                        field(write, 0x24) == field(read, 0x24) && field(write, 0x39) == field(read, 0x39) &&
                        field(save, 3) == field(load, 3);
        if (!ok)
        {
            TaceLog("[limits] scriptcargens: ABORTED - the CarGenerators save handlers are not laid out as expected "
                    "(%zu registration site(s)). Nothing patched.", sites.size());
            return;
        }

        gScriptCg.origSave = reinterpret_cast<char (__cdecl *)()>(const_cast<uint8_t *>(save));
        gScriptCg.origLoad = reinterpret_cast<char (__cdecl *)()>(const_cast<uint8_t *>(load));
        gScriptCg.desc     = reinterpret_cast<const uintptr_t *>(uintptr_t(field(read, 0x01)));
        gScriptCg.error    = reinterpret_cast<const uint8_t *>(uintptr_t(field(read, 0x16)));
        gScriptCg.dryRun   = reinterpret_cast<const uint8_t *>(uintptr_t(field(read, 0x24)));
        gScriptCg.cursor   = reinterpret_cast<const uint32_t *>(uintptr_t(field(read, 0x39)));
        gScriptCg.table    = reinterpret_cast<uint8_t *>(uintptr_t(field(save, 3)));
        gScriptCg.slots    = script;
        gScriptCg.dir = TaceFolder("Saves");

        injector::WriteMemory<uint32_t>(create.get_first(1), script, true);    // map generators start here
        injector::WriteMemory<uint32_t>(create.get_first(15), script, true);   // script generators end here
        injector::WriteMemory<uint32_t>(sites[0], uint32_t(uintptr_t(&CarGenSaveHook)), true);
        injector::WriteMemory<uint32_t>(sites[0] + 5, uint32_t(uintptr_t(&CarGenLoadHook)), true);

        TaceLog("[limits] scriptcargens: OK - 25 -> %u script slots, %u left for the map; slots past 24 saved to %s",
                script, total - script, gScriptCg.dir.c_str());
    }

    // Radar blip sprites: ids 0-128, plus whatever [BLIPSPRITES] adds.
    //
    // A sprite id indexes two parallel tables: texture NAMES, which the game walks
    // at startup (and on every episode switch) to load each sprite from
    // blips.wtd, and the SPRITES it creates from them, in order. Both hold the
    // 129 ids the exe knows. CHANGE_BLIP_SPRITE does no range check, so id 129
    // today reads whatever global follows the table. Growing both gives new
    // textures real ids - the load loop appends them after the stock ones.
    //
    // References, the same on EFLC 1.1.2.0 (IDA) and 1.0.8.0 (whole-.text scan):
    //   names     start 1 (mov esi) and end 1 (cmp esi), both in the load loop
    //   sprites   [reg*4+table] 13, [reg*4+table+4] 1 and [reg*4+table-4] 1 - the
    //             objective arrows read the neighbours of ids 1 and 4 - and
    //             table+0x130 x3, sprite 76 read directly
    // The dword just below the table is an unrelated float that 4 other
    // instructions use, so below the table only the scaled-index form moves.
    void AdjustBlipSprites()
    {
        constexpr size_t kStock = 129;
        const std::vector<std::string> &extra = gConfig.blipSprites;

        if (extra.empty())
        {
            TaceLog("[limits] blipsprites: none configured, stock 129");
            return;
        }

        // mov esi,<names> ; jmp ; lea ecx,[ecx] ; mov ecx,[esi] ; push ecx ; call <add sprite> ;
        // add esi,4 ; add esp,4 ; cmp esi,<names end> ; jl
        auto load = find_pattern("BE ? ? ? ? EB 03 8D 49 00 8B 0E 51 E8 ? ? ? ? 83 C6 04 83 C4 04 81 FE ? ? ? ? 7C EA");
        // xor eax,eax ; mov ecx,[count] ; mov [ecx*4+<sprites>],eax ; add ecx,1 ; mov [count],ecx ;
        // lea eax,[ecx-1] ; ret
        auto add = find_pattern("33 C0 8B 0D ? ? ? ? 89 04 8D ? ? ? ? 83 C1 01 89 0D ? ? ? ? 8D 41 FF C3");
        if (!Found(load, "blipsprites.load") || !Found(add, "blipsprites.add"))
            return;

        const uintptr_t names    = *load.get_first<uint32_t>(1);
        const uintptr_t namesEnd = *load.get_first<uint32_t>(26);
        const uintptr_t sprites  = *add.get_first<uint32_t>(11);
        const auto *stockNames = reinterpret_cast<const char *const *>(names);

        if (namesEnd - names != kStock * 4 || strcmp(stockNames[0], "radar_higher") != 0 ||
            *add.get_first<uint32_t>(4) != *add.get_first<uint32_t>(20) ||
            !InWritableImage(sprites, kStock * 4))
        {
            TaceLog("[limits] blipsprites: ABORTED - the sprite tables are not laid out as expected. Nothing patched.");
            return;
        }

        std::vector<uint8_t *>  spriteRefs;
        std::vector<intptr_t>   spriteOffsets;   // parallel: where in the table each points
        size_t at0 = 0, atPlus4 = 0, atMinus4 = 0, direct = 0, strays = 0;
        for (const CodeRef &r : CodeRefsInRange(uint32_t(sprites - 4), uint32_t(sprites + kStock * 4)))
        {
            const intptr_t off = intptr_t(r.value) - intptr_t(sprites);
            if (off % 4 != 0)
                continue;   // unaligned: the bytes of some other instruction

            const bool scaled = (r.at[-2] & 0xC7) == 0x04 && (r.at[-1] & 0xC7) == 0x85;
            if (scaled && (off == 0 || off == 4 || off == -4))
                (off == 0 ? at0 : off == 4 ? atPlus4 : atMinus4)++;
            else if (off == 0x130)
                direct++;
            else
            {
                if (off != -4)
                    strays++;
                continue;
            }
            spriteRefs.push_back(r.at);
            spriteOffsets.push_back(off);
        }

        std::vector<uint8_t *> nameStart, nameEnd;
        size_t nameStrays = 0;
        for (const CodeRef &r : CodeRefsInRange(uint32_t(names), uint32_t(namesEnd + 1)))
        {
            if (r.value == names)
                nameStart.push_back(r.at);
            else if (r.value == namesEnd)
                nameEnd.push_back(r.at);
            else if ((r.value - names) % 4 == 0)
                nameStrays++;
        }

        if (!AllMatch("blipsprites", {
                { "table refs",        at0,              13 },
                { "table+4 refs",      atPlus4,           1 },
                { "table-4 refs",      atMinus4,          1 },
                { "sprite 76 reads",   direct,            3 },
                { "other table refs",  strays,            0 },
                { "name table start",  nameStart.size(),  1 },
                { "name table end",    nameEnd.size(),    1 },
                { "other name refs",   nameStrays,        0 } }))
            return;

        const size_t total = kStock + extra.size();
        auto **newNames  = static_cast<const char **>(AllocTable(total * sizeof(const char *)));
        auto  *newSprites = static_cast<uint32_t *>(AllocTable(total * sizeof(uint32_t)));
        if (newNames == nullptr || newSprites == nullptr)
        {
            TaceLog("[limits] blipsprites: ABORTED - could not allocate %zu sprites. Nothing patched.", total);
            return;
        }

        memcpy(newNames, stockNames, kStock * sizeof(const char *));
        for (size_t i = 0; i < extra.size(); i++)
        {
            char *copy = new char[extra[i].size() + 1];   // never freed, like the tables
            memcpy(copy, extra[i].c_str(), extra[i].size() + 1);
            newNames[kStock + i] = copy;
        }
        memcpy(newSprites, reinterpret_cast<const void *>(sprites), kStock * sizeof(uint32_t));

        for (size_t i = 0; i < spriteRefs.size(); i++)
            injector::WriteMemory<uint32_t>(spriteRefs[i], uint32_t(intptr_t(newSprites) + spriteOffsets[i]), true);
        for (uint8_t *at : nameStart)
            injector::WriteMemory<uint32_t>(at, uint32_t(uintptr_t(newNames)), true);
        for (uint8_t *at : nameEnd)
            injector::WriteMemory<uint32_t>(at, uint32_t(uintptr_t(newNames + total)), true);

        TaceLog("[limits] blipsprites: OK - %zu refs moved, 129 -> %zu sprites",
                spriteRefs.size() + nameStart.size() + nameEnd.size(), total);
        for (size_t i = 0; i < extra.size(); i++)
            TaceLog("[limits] blipsprites:   %zu = %s", kStock + i, extra[i].c_str());
    }
}

// ============================================================================
// Entry point. Call once, early (DLL_PROCESS_ATTACH), before the game reads any
// of these tables.
// ============================================================================
void InitializeAllLimitAdjusters()
{
    TaceLog("[limits] ---- init ----");

    LoadConfig();

    AdjustAnimWadBlocks();
    AdjustCarGenerators();
    AdjustScriptCarGenerators();   // after AdjustCarGenerators: needs the moved table
    AdjustBlipSprites();

    if (gConfig.enableHandling) AdjustHandling();
    else                        TaceLog("[limits] handling: disabled in ini");

    if (gConfig.enableCarcols)  AdjustCarcols();
    else                        TaceLog("[limits] carcols: disabled in ini");

    if (gConfig.enableVehOffs)  AdjustVehicleOffsets();
    else                        TaceLog("[limits] vehoff: disabled in ini");

    if (gConfig.enableWeaponInfo) AdjustWeaponInfo();
    else                          TaceLog("[limits] weaponinfo: disabled in ini");

    // WeaponInfo is NOT ported yet. Upstream raises it to 120 entries but also
    // installs a safetyhook inline hook on GetWeaponInfoIdByHash to register
    // custom weapons into the enlarged table. This project has no safetyhook
    // dependency, and moving the array without that hook leaves lookups pointing
    // into the old table. Needs the hook first.

    TaceLog("[limits] ---- done ----");
}
