#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

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
        gConfig.enableHandling = readBool("LIMITS", "Handling", gConfig.enableHandling);
        gConfig.handlingScale  = readInt("LIMITS", "HandlingScale", gConfig.handlingScale);
        gConfig.enableCarcols  = readBool("LIMITS", "Carcols", gConfig.enableCarcols);
        gConfig.enableVehOffs  = readBool("LIMITS", "VehicleOffsets", gConfig.enableVehOffs);
        gConfig.enableWeaponInfo = readBool("LIMITS", "WeaponInfo", gConfig.enableWeaponInfo);
        gConfig.verboseXrefs   = readBool("DEBUG", "VerboseXrefs", gConfig.verboseXrefs);

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

        TaceLog("[limits] config: AnimWadBlocks=%d Handling=%d(x%d) Carcols=%d VehOffs=%d WeaponInfo=%d",
                gConfig.animWadBlocks, gConfig.enableHandling, gConfig.handlingScale,
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
