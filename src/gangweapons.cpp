#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Config.h"
#include "Log.h"
#include "Patterns.h"
#include "Weapons.h"

// ============================================================================
// Gang weapon loadouts.
//
// CGangs::initialize makes twelve CGangs::setGang calls, each writing a 20-byte
// entry: three weapon ids as dwords at +4/+8/+12 and three chances as bytes at
// +16/+17/+18. Every argument is a `push imm8`, so a loadout can be edited in
// place before the game ever runs initialize - no hooking, no relocation.
//
// Picking is done by the equivalent of:
//
//     roll = (uint8)(rand01 * 300);
//     for (slot = 0; slot < 3; slot++) {
//         running += chance[slot];
//         if (roll < running && slot <= cap) return weapon[slot];
//     }
//     return 0;   // unarmed
//
// so the chances are cumulative out of 256, NOT out of 100. Vanilla's 20/40/20
// totals 80, which is why roughly two thirds of gang peds spawn empty-handed.
// Raise the numbers, not just the weapon ids, if you want them actually armed.
//
// PED TYPE NUMBERING - the thing that makes this look broken
// The index is `pedType - 3`, read from modelInfo+0x12C. That field does NOT
// use the same numbering as the 71-entry name table the relationship data is
// parsed against: it has no PLAYER entry, so every value sits one lower. COP is
// 2, GANG_ALBANIAN 3, GANG_BIKER_1 4, up to GANG_PUERTO_RICAN 14 - which makes
// the eligibility test `>= 3 && <= 14` exactly the twelve gangs, cops excluded
// and Puerto Ricans included. Vanilla is correct here; there is no off-by-one
// to fix. Using the other numbering writes each loadout to the entry next door,
// which presents as "the patch does nothing" because the gang really is still
// reading its neighbour's weapons.
// ============================================================================

namespace
{
    constexpr int kGangCount = 12;

    const NamedId kPedTypes[] = {
        { "GANG_ALBANIAN", 3 }, { "GANG_BIKER_1", 4 }, { "GANG_BIKER_2", 5 },
        { "GANG_ITALIAN", 6 }, { "GANG_RUSSIAN", 7 }, { "GANG_RUSSIAN_2", 8 },
        { "GANG_IRISH", 9 }, { "GANG_JAMAICAN", 10 }, { "GANG_AFRICAN_AMERICAN", 11 },
        { "GANG_KOREAN", 12 }, { "GANG_CHINESE_JAPANESE", 13 }, { "GANG_PUERTO_RICAN", 14 },
    };

    uint8_t *gCallSite[kGangCount] = {};   // the `call setGang` for each entry

    // The configured loadouts, kept so they can be re-applied to the live table.
    // Patching the `push` immediates only decides what CGangs::initialize writes
    // at startup - but the table is ALSO a save/load field ("Gangs" handler), so
    // loading a savegame restores whatever was in the save and silently undoes
    // it. Enforcing the values on the table itself is what actually sticks.
    struct Override { bool set; uint32_t w[3]; uint8_t c[3]; };
    Override gOverride[kGangCount] = {};

    // Diagnostics. The picker is the only consumer of the table, so wrapping it
    // answers the question the loadout log cannot: whether a given ped ever
    // reaches the gang path at all, and which entry it lands on.
    int      (__fastcall *OrigPickWeapon)(uint8_t *entry, void *, int flag) = nullptr;
    uint8_t  *gTableBase = nullptr;
    bool      gTrace     = false;
    int       gTraceLeft = 0;
    int       gFirstPedType = 3;

    // "<weapon>,<chance>, <weapon>,<chance>, <weapon>,<chance>"
    bool ParseLoadout(const std::string &value, int weapon[3], int chance[3])
    {
        std::vector<std::string> parts;
        size_t start = 0;
        for (;;)
        {
            const size_t comma = value.find(',', start);
            parts.push_back(TrimToken(value.substr(start, comma - start)));
            if (comma == std::string::npos)
                break;
            start = comma + 1;
        }
        if (parts.size() != 6)
            return false;

        for (int i = 0; i < 3; i++)
        {
            if (!LookUpWeapon(parts[i * 2], weapon[i]))
                return false;
            chance[i] = atoi(parts[i * 2 + 1].c_str());

            // `push imm8` sign-extends into the dword the weapon id is stored
            // in, so an id above 127 would land as a negative. Every real id is
            // far below that. The chance only ever survives as its low byte, so
            // 0..255 is the honest range there.
            if (chance[i] < 0 || chance[i] > 255)
                return false;
        }
        return true;
    }
}

// Replaces the eligibility test, which is the one place the raw ped type is
// visible. Logging each distinct value once is what confirms the numbering -
// bikers must show as 4, not 5.
bool __cdecl GangWeapons_Eligible(int pedType)
{
    const bool eligible = pedType >= 3 && pedType <= 14;

    // Log the CALLER, not just the ped type. This test has three callers and only
    // two of them are the weapon path - the third is
    // CPedIntelligence::setCombatDecisionMaker, which uses the ped type for
    // combat AI. Ped types alone cannot tell those apart, and "eligible ped type
    // seen, no weapon rolled" means completely different things depending on
    // which one asked.
    if (gTrace)
    {
        const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
        const uintptr_t rva = ret - reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));

        static uintptr_t seenCaller[8] = {};
        static int       callerCount   = 0;
        bool known = false;
        for (int i = 0; i < callerCount; i++)
            known = known || (seenCaller[i] == rva);

        if (!known && callerCount < 8)
        {
            seenCaller[callerCount++] = rva;
            TaceLog("[gangs] eligibility called from GTAIV.exe+0x%zX (ped type %d)",
                    static_cast<size_t>(rva), pedType);
        }

        static uint32_t seen = 0;
        if (pedType >= 0 && pedType < 32 && (seen & (1u << pedType)) == 0)
        {
            seen |= (1u << pedType);
            const char *name = "?";
            for (const NamedId &pt : kPedTypes)
                if (pt.id == pedType)
                    name = pt.name;
            TaceLog("[gangs] ped type %d seen (%s) -> %s", pedType, name,
                    eligible ? "eligible" : "not a gang");
        }
    }
    return eligible;
}

// Wraps the gang weapon picker at both of its call sites. This is where the
// configured loadout is enforced: the picker is the only reader of the table, so
// correcting the entry here covers every way it can be clobbered - a savegame
// load above all - without needing to know when that happened.
int __fastcall GangWeapons_Pick(uint8_t *entry, void *, int flag)
{
    if (gTableBase != nullptr)
    {
        const ptrdiff_t slot = (entry - gTableBase) / 20;
        if (slot >= 0 && slot < kGangCount && gOverride[slot].set)
        {
            const Override &o = gOverride[slot];
            bool differs = false;
            for (int i = 0; i < 3; i++)
                differs = differs || *reinterpret_cast<uint32_t *>(entry + 4 + 4 * i) != o.w[i]
                                  || entry[16 + i] != o.c[i];

            if (differs)
            {
                for (int i = 0; i < 3; i++)
                {
                    *reinterpret_cast<uint32_t *>(entry + 4 + 4 * i) = o.w[i];
                    entry[16 + i] = o.c[i];
                }
                static uint32_t logged = 0;
                if ((logged & (1u << slot)) == 0)
                {
                    logged |= (1u << slot);
                    TaceLog("[gangs] entry %d did not hold the configured loadout - re-applied"
                            " (a savegame load restores this table)", static_cast<int>(slot));
                }
            }
        }
    }

    const int weapon = OrigPickWeapon(entry, nullptr, flag);

    // Dump the live table once. Patching the `push` immediates only matters if
    // CGangs::initialize runs AFTER we patch them; reading what actually landed
    // in the table is the only way to tell that apart from a picker that ignores
    // our values.
    if (gTrace && gTableBase != nullptr)
    {
        static bool dumped = false;
        if (!dumped)
        {
            dumped = true;
            for (int i = 0; i < kGangCount; i++)
            {
                const uint8_t *e = gTableBase + 20 * i;
                TaceLog("[gangs] live table entry %2d: %s,%u  %s,%u  %s,%u",
                        i,
                        WeaponName(*reinterpret_cast<const uint32_t *>(e + 4)),  e[16],
                        WeaponName(*reinterpret_cast<const uint32_t *>(e + 8)),  e[17],
                        WeaponName(*reinterpret_cast<const uint32_t *>(e + 12)), e[18]);
            }
        }
    }

    if (gTrace && gTraceLeft > 0 && gTableBase != nullptr)
    {
        gTraceLeft--;
        const ptrdiff_t slot = (entry - gTableBase) / 20;
        TaceLog("[gangs] pick: entry %d (pedType %d) -> %s%s",
                static_cast<int>(slot), static_cast<int>(slot) + gFirstPedType,
                weapon ? WeaponName(weapon) : "nothing (roll missed, ped spawns unarmed)",
                flag ? "  [forced-pistol flag set]" : "");
    }
    return weapon;
}

void GangWeapons_Init()
{
    if (!TaceIniBool("GANGWEAPONS", "Enabled", false))
    {
        TaceLog("[gangs] disabled in ini");
        return;
    }

    // CGangs::initialize: the save-handler registration followed by entry 0's
    // seven pushes and its call.
    auto init = find_pattern("68 ? ? ? ? 68 ? ? ? ? 68 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? "
                             "6A 14 6A 0C 6A 28 6A 07 6A 14 6A 03 6A 00 E8 ? ? ? ?");
    if (init.empty())
    {
        TaceLog("[gangs] CGangs::initialize signature not found - feature disabled");
        return;
    }

    // Each entry is seven `push imm8` then `call`, so the call is preceded by
    // the arguments at a fixed stride. Walk them rather than pattern-matching
    // each one: several gangs share identical loadouts in stock data.
    uint8_t *base = init.get_first<uint8_t>(0);
    int found = 0;
    for (ptrdiff_t off = 0; off < 0x140 && found < kGangCount; off++)
    {
        uint8_t *p = base + off;
        if (p[0] != 0x6A || p[2] != 0xE8 || off < 13)
            continue;
        if (p[1] != found)          // entries appear in index order
            continue;
        gCallSite[found] = p + 2;   // the call opcode
        found++;
    }

    if (found != kGangCount)
    {
        TaceLog("[gangs] found %d of %d loadout entries - feature disabled", found, kGangCount);
        return;
    }

    // Vanilla indexes the table `pedType - 3`, which with the real ped type
    // numbering is exactly right: entry 0 is GANG_ALBANIAN (3) and entry 11 is
    // GANG_PUERTO_RICAN (14). Nothing to correct.
    const int firstPedType = 3;
    gFirstPedType = firstPedType;

    // --- diagnostics ---
    gTrace     = TaceIniBool("GANGWEAPONS", "Debug", false);
    gTraceLeft = gTrace ? 120 : 0;
    {
        auto setGang = find_pattern("8B 44 24 04 8B 4C 24 08 8A 54 24 0C 8D 04 80 8D 04 85 ? ? ? ? "
                                    "89 48 04 8B 4C 24 10 88 50 10");
        auto idxA    = find_pattern("8B 86 6C 02 00 00 C1 E8 02 25 01 FF FF FF 8D 4C BF ? 50 "
                                    "8D 0C 8D ? ? ? ? E8 ? ? ? ?");
        auto idxB    = find_pattern("8D 4C BF ? 6A 00 8D 0C 8D ? ? ? ? E8 ? ? ? ?");

        if (setGang.empty() || idxA.empty() || idxB.empty())
        {
            TaceLog("[gangs] picker signature(s) not found - loadouts cannot be enforced"
                    " against a savegame load");
            gTrace = false;
        }
        else
        {
            gTableBase = *setGang.get_first<uint8_t *>(18);

            auto eligible = find_pattern("8B 44 24 04 83 F8 03 7C 08 83 F8 0E 7F 03 B0 01 C3 32 C0 C3");
            if (!eligible.empty())
                injector::MakeJMP(eligible.get_first(0), GangWeapons_Eligible, true);
            OrigPickWeapon = injector::MakeCALL(idxA.get_first(26), GangWeapons_Pick, true).get();
            injector::MakeCALL(idxB.get_first(13), GangWeapons_Pick, true);
            TaceLog("[gangs] picker wrapped, table at %p", (void *)gTableBase);
        }
    }

    // --- per-gang loadouts ---
    int applied = 0;
    for (const NamedId &pt : kPedTypes)
    {
        const std::string value = TaceIniString("GANGWEAPONS", pt.name);
        if (value.empty())
            continue;

        const int slot = pt.id - firstPedType;
        if (slot < 0 || slot >= kGangCount)
        {
            TaceLog("[gangs] %s has no loadout entry (slot %d out of range) - skipped",
                    pt.name, slot);
            continue;
        }

        int weapon[3], chance[3];
        if (!ParseLoadout(value, weapon, chance))
        {
            TaceLog("[gangs] %s: expected \"<weapon>,<chance>\" three times, got \"%s\" - skipped",
                    pt.name, value.c_str());
            continue;
        }

        // Arguments are pushed right to left, so relative to the call opcode:
        // -1 index, -3/-5 weapon+chance 1, -7/-9 two, -11/-13 three.
        uint8_t *call = gCallSite[slot];
        TaceLog("[gangs] %s (entry %d): %s,%d %s,%d %s,%d  <- was %s,%d %s,%d %s,%d",
                pt.name, slot,
                WeaponName(weapon[0]), chance[0], WeaponName(weapon[1]), chance[1],
                WeaponName(weapon[2]), chance[2],
                WeaponName(call[-3]), call[-5], WeaponName(call[-7]), call[-9],
                WeaponName(call[-11]), call[-13]);

        Override &o = gOverride[slot];
        o.set = true;
        for (int i = 0; i < 3; i++) { o.w[i] = static_cast<uint32_t>(weapon[i]); o.c[i] = static_cast<uint8_t>(chance[i]); }

        injector::WriteMemory<uint8_t>(call - 3,  static_cast<uint8_t>(weapon[0]), true);
        injector::WriteMemory<uint8_t>(call - 5,  static_cast<uint8_t>(chance[0]), true);
        injector::WriteMemory<uint8_t>(call - 7,  static_cast<uint8_t>(weapon[1]), true);
        injector::WriteMemory<uint8_t>(call - 9,  static_cast<uint8_t>(chance[1]), true);
        injector::WriteMemory<uint8_t>(call - 11, static_cast<uint8_t>(weapon[2]), true);
        injector::WriteMemory<uint8_t>(call - 13, static_cast<uint8_t>(chance[2]), true);
        applied++;
    }

    TaceLog("[gangs] %d loadout(s) applied", applied);
}
