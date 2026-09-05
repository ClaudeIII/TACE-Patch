#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Config.h"
#include "Log.h"
#include "Patterns.h"
#include "Weapons.h"

// ============================================================================
// Police weapon loadouts.
//
// Cops do not use the gang table - they are armed directly by the ped setup
// function, which branches on the model:
//
//     if (model == M_Y_Swat || model == M_M_FBI) {
//         giveWeapon(PISTOL);                       // sidearm, always
//         if (rand() < 0x3FFF) giveWeapon(MP5);     // secondary, ~50%
//         primary = (episode == TBoGT)              // three-way in TBoGT
//                 ? (roll < .33 ? M4 : roll < .66 ? AA12 : P90)
//                 : (roll < .80 ? M4 : SHOTGUN);    // two-way otherwise
//         giveWeapon(primary);
//         accuracy = 40; setArmour(100);
//     } else {
//         giveWeapon(PISTOL);                       // ordinary police
//         accuracy = 30; setArmour(0);
//     }
//
// The rooftop sniper (POLICE_ROOFTOP_SNIPER) is a third function again, and the
// simplest: one unconditional giveWeapon, no episode check at all.
//
// Helicopter crews are armed separately again, by POLICE_HELI_WEAPONS, which
// loops over the three passengers and gives each an M249 in TBoGT or an M4
// otherwise - and main.cpp NOPs that check too, so the M249 is what actually
// flies in every episode.
//
// Every weapon is an immediate, so all of it is editable in place. Unlike the
// gang loadouts there is no savegame involvement at all: this runs per ped, and
// the values live in code rather than in a save/load-backed table, so a patched
// immediate simply takes effect on the next cop that spawns.
//
// WHICH PRIMARY ACTUALLY RUNS
// main.cpp's PoliceEpisodicWeaponSupport patch NOPs the `jnz` on the episode
// comparison, so execution falls into the TBoGT three-way branch in EVERY
// episode. SwatPrimaryTBoGT is therefore the live setting, and SwatPrimary is
// dead code unless that patch is removed. It stays configurable so the two do
// not silently disagree if it ever is. The NOP leaves ebp holding 2, which is
// what the displacement arithmetic below depends on.
//
// The one oddity is the TBoGT primary, which the compiler emitted as
// `lea eax, [ebp+0Dh]` with ebp holding 2 - so the weapon is 2 + displacement,
// not the displacement itself. Rewriting it as a plain `mov eax, imm32` would
// need five bytes where there are three, so the displacement is set to
// weapon - 2 instead. Every real weapon id stays in range doing that.
// ============================================================================

namespace
{
    // A loadout that cannot be expressed as a single immediate: one weapon
    // picked at random from `pick`, plus everything in `extra` on top.
    //
    // These are installed by hooking the giveWeapon CALL rather than rewriting
    // the pushed weapon id, which has a useful side effect at the helicopter
    // site: the episode branch still runs and still chooses 34 or 15, but we
    // overwrite the argument, so which branch was taken stops mattering at all.
    struct Loadout
    {
        std::vector<int> pick;
        std::vector<int> extra;
        bool active() const { return !pick.empty() || !extra.empty(); }
    };

    Loadout gSniper;
    Loadout gHeli;

    bool gTrace     = false;
    int  gTraceLeft = 0;

    // thiscall(this, weapon, ammo, a4, a5, a6) - five stack args, callee cleaned.
    int (__fastcall *OrigGiveWeapon)(void *self, void *, int weapon, int ammo, int a4, int a5, int a6) = nullptr;

    int ApplyLoadout(const Loadout &l, const char *who, void *self, int weapon, int ammo, int a4, int a5, int a6)
    {
        int chosen = weapon;
        if (!l.pick.empty())
            chosen = l.pick[static_cast<size_t>(rand()) % l.pick.size()];

        const int result = OrigGiveWeapon(self, nullptr, chosen, ammo, a4, a5, a6);

        for (int e : l.extra)
            OrigGiveWeapon(self, nullptr, e, ammo, a4, a5, a6);

        // The only runtime evidence this hook is live at all. Everything else
        // about the cop features is decided once, at init.
        if (gTrace && gTraceLeft > 0)
        {
            gTraceLeft--;
            TACE_TRACE("[cops] %s armed: %s (game asked for %s)%s%s",
                       who, WeaponName(chosen), WeaponName(weapon),
                       l.extra.empty() ? "" : " + ",
                       l.extra.empty() ? "" : WeaponName(l.extra.front()));
        }

        return result;
    }

    // Reads "<weapon>" or "<weapon>, <weapon>[, <weapon>]" from the ini.
    bool ReadWeaponList(const char *key, std::vector<int> &out, size_t expected)
    {
        const std::string value = TaceIniString("COPWEAPONS", key);
        if (value.empty())
            return false;

        out.clear();
        size_t start = 0;
        for (;;)
        {
            const size_t comma = value.find(',', start);
            const std::string token = TrimToken(value.substr(start, comma - start));

            int id = 0;
            if (!LookUpWeapon(token, id))
            {
                TaceLog("[cops] %s: \"%s\" is not a weapon name or id - skipped", key, token.c_str());
                return false;
            }
            out.push_back(id);

            if (comma == std::string::npos)
                break;
            start = comma + 1;
        }

        if (out.size() != expected)
        {
            TaceLog("[cops] %s: expected %zu weapon(s), got %zu - skipped",
                    key, expected, out.size());
            return false;
        }
        return true;
    }

    // Reads a comma-separated weapon list; absent or unparseable leaves it empty.
    bool ReadLoadoutKey(const char *key, std::vector<int> &out)
    {
        const std::string value = TaceIniString("COPWEAPONS", key);
        if (value.empty())
            return false;

        out.clear();
        size_t start = 0;
        for (;;)
        {
            const size_t comma = value.find(',', start);
            const std::string token = TrimToken(value.substr(start, comma - start));

            int id = 0;
            if (!token.empty() && !LookUpWeapon(token, id))
            {
                TaceLog("[cops] %s: \"%s\" is not a weapon name or id - key ignored", key, token.c_str());
                out.clear();
                return false;
            }
            if (!token.empty())
                out.push_back(id);

            if (comma == std::string::npos)
                break;
            start = comma + 1;
        }
        return !out.empty();
    }

    std::string Describe(const std::vector<int> &v)
    {
        std::string s;
        for (size_t i = 0; i < v.size(); i++)
        {
            if (i) s += ", ";
            s += WeaponName(v[i]);
        }
        return s.empty() ? std::string("-") : s;
    }

    // Writes an imm8, but only if it currently holds what the disassembly said
    // it should. A signature that drifted onto a neighbouring instruction would
    // otherwise corrupt unrelated code.
    bool PatchByte(uint8_t *at, uint8_t expected, uint8_t value, const char *what)
    {
        if (*at != expected)
        {
            TaceLog("[cops] %s: expected 0x%02X at %p, found 0x%02X - not patched",
                    what, expected, (void *)at, *at);
            return false;
        }
        if (value == expected)
            return true;

        injector::WriteMemory<uint8_t>(at, value, true);
        TaceLog("[cops] %s: %s -> %s", what, WeaponName(expected), WeaponName(value));
        return true;
    }
}

int __fastcall CopWeapons_GiveSniper(void *self, void *, int weapon, int ammo, int a4, int a5, int a6)
{
    return ApplyLoadout(gSniper, "rooftop sniper", self, weapon, ammo, a4, a5, a6);
}

int __fastcall CopWeapons_GiveHeli(void *self, void *, int weapon, int ammo, int a4, int a5, int a6)
{
    return ApplyLoadout(gHeli, "helicopter crewman", self, weapon, ammo, a4, a5, a6);
}

void CopWeapons_Init()
{
    if (!TaceIniBool("COPWEAPONS", "Enabled", false))
    {
        TaceLog("[cops] disabled in ini");
        return;
    }

    TaceLog("[cops] ---- init ----");

    gTrace     = TaceIniBool("COPWEAPONS", "Debug", false);
    gTraceLeft = gTrace ? TaceTraceBudget(120) : 0;

    auto copWeapon = find_pattern("6A 00 6A 00 6A 01 68 A8 61 00 00 6A 07 8D 8E B0 02 00 00 "
                                  "E8 ? ? ? ? D9 EE");
    auto copAcc    = find_pattern("D9 EE 51 D9 1C 24 8B CE C6 86 88 03 00 00 1E");
    auto swatMain  = find_pattern("6A 00 6A 00 6A 00 68 A8 61 00 00 8D BE B0 02 00 00 6A 07 8B CF "
                                  "E8 ? ? ? ? E8 ? ? ? ? 3D FF 3F 00 00 7D ? 6A 00 6A 00 6A 00 "
                                  "68 A8 61 00 00 6A 0D 8B CF E8 ? ? ? ?");
    auto swatEp2   = find_pattern("8D 45 0D EB ? F3 0F 10 0D ? ? ? ? 0F 2F C8 76 ? B8 1F 00 00 00 "
                                  "EB ? B8 20 00 00 00");
    auto swatIv    = find_pattern("0F 2F C8 B8 0F 00 00 00 77 ? B8 0A 00 00 00");
    auto swatAcc   = find_pattern("D9 05 ? ? ? ? 51 8B CE D9 1C 24 C6 86 88 03 00 00 28");

    // Helicopter crews are armed by their own function, in a loop over the three
    // passengers. The jnz is wildcarded because main.cpp's "m249 for swat in
    // annihilators and helicopters" patch NOPs it, and this has to match whether
    // it has run yet or not.
    // The rooftop sniper is armed by its own function, unconditionally - no
    // episode check to work around here.
    auto sniper    = find_pattern("6A 01 6A 01 6A 01 68 A8 61 00 00 6A 10 8D 8E B0 02 00 00 "
                                  "E8 ? ? ? ? B0 01");

    auto heli      = find_pattern("83 3D ? ? ? ? ? 6A 00 6A 00 6A 01 8B CF 68 A8 61 00 00 ? ? "
                                  "6A 22 EB ? 6A 0F E8 ? ? ? ?");

    const struct { const char *what; bool missing; } required[] = {
        { "ordinary cop weapon", copWeapon.empty() },
        { "ordinary cop accuracy", copAcc.empty() },
        { "SWAT sidearm and secondary", swatMain.empty() },
        { "SWAT primary (TBoGT)", swatEp2.empty() },
        { "SWAT primary (IV/TLAD)", swatIv.empty() },
        { "SWAT accuracy", swatAcc.empty() },
        { "helicopter crew weapon", heli.empty() },
        { "rooftop sniper weapon", sniper.empty() },
    };
    bool ok = true;
    for (const auto &r : required)
    {
        if (r.missing)
        {
            TaceLog("[cops] signature not found: %s - feature disabled", r.what);
            ok = false;
        }
    }
    if (!ok)
        return;

    std::vector<int> w;

    // --- ordinary police ---
    if (ReadWeaponList("Cop", w, 1))
        PatchByte(copWeapon.get_first<uint8_t>(12), 7, static_cast<uint8_t>(w[0]), "cop sidearm");

    // --- SWAT / FBI ---
    if (ReadWeaponList("SwatSidearm", w, 1))
        PatchByte(swatMain.get_first<uint8_t>(18), 7, static_cast<uint8_t>(w[0]), "SWAT sidearm");

    if (ReadWeaponList("SwatSecondary", w, 1))
        PatchByte(swatMain.get_first<uint8_t>(50), 13, static_cast<uint8_t>(w[0]), "SWAT secondary");

    // Base IV and TLAD: the first weapon normally, the second on the tail of the
    // roll. TBoGT gets its own three-way split.
    // Dead while PoliceEpisodicWeaponSupport is patched in - see the note above.
    if (ReadWeaponList("SwatPrimary", w, 2))
    {
        PatchByte(swatIv.get_first<uint8_t>(4),  15, static_cast<uint8_t>(w[0]), "SWAT primary");
        PatchByte(swatIv.get_first<uint8_t>(11), 10, static_cast<uint8_t>(w[1]), "SWAT primary alt");
    }

    if (ReadWeaponList("SwatPrimaryTBoGT", w, 3))
    {
        // `lea eax, [ebp+disp]` with ebp = 2, so the displacement is weapon - 2.
        uint8_t *lea = swatEp2.get_first<uint8_t>(2);
        if (*lea != 0x0D)
            TaceLog("[cops] SWAT primary (TBoGT): expected 0x0D at %p, found 0x%02X - not patched",
                    (void *)lea, *lea);
        else if (w[0] - 2 < -128 || w[0] - 2 > 127)
            TaceLog("[cops] SWAT primary (TBoGT): weapon %d is out of range for this instruction", w[0]);
        else
        {
            injector::WriteMemory<uint8_t>(lea, static_cast<uint8_t>(w[0] - 2), true);
            TaceLog("[cops] SWAT primary (TBoGT): M4 -> %s", WeaponName(w[0]));
        }

        PatchByte(swatEp2.get_first<uint8_t>(19), 31, static_cast<uint8_t>(w[1]), "SWAT primary (TBoGT) alt 1");
        PatchByte(swatEp2.get_first<uint8_t>(26), 32, static_cast<uint8_t>(w[2]), "SWAT primary (TBoGT) alt 2");
    }

    // Helicopter crews. Hooking the call rather than the pushed id means the
    // episode branch above it becomes irrelevant - whichever weapon it selects
    // is overwritten before giveWeapon sees it.
    ReadLoadoutKey("HeliCop", gHeli.pick);
    ReadLoadoutKey("HeliCopExtra", gHeli.extra);
    if (gHeli.active())
    {
        // Both sites call the same giveWeapon, so whichever hook is installed
        // first yields the real target for both.
        auto prev = injector::MakeCALL(heli.get_first(28), CopWeapons_GiveHeli, true).get();
        if (OrigGiveWeapon == nullptr)
            OrigGiveWeapon = prev;
        TaceLog("[cops] helicopter crew: one of [%s]%s%s", Describe(gHeli.pick).c_str(),
                gHeli.extra.empty() ? "" : " plus ",
                gHeli.extra.empty() ? "" : Describe(gHeli.extra).c_str());
    }

    // Rooftop snipers and helicopter crews take a list, so they are hooked at the
    // giveWeapon call instead of having their pushed weapon id rewritten. One
    // weapon is picked at random from the list, plus any Extra on top.
    ReadLoadoutKey("RooftopSniper", gSniper.pick);
    ReadLoadoutKey("RooftopSniperExtra", gSniper.extra);
    if (gSniper.active())
    {
        OrigGiveWeapon = injector::MakeCALL(sniper.get_first(19), CopWeapons_GiveSniper, true).get();
        TaceLog("[cops] rooftop sniper: one of [%s]%s%s", Describe(gSniper.pick).c_str(),
                gSniper.extra.empty() ? "" : " plus ",
                gSniper.extra.empty() ? "" : Describe(gSniper.extra).c_str());
    }

    // --- chances and accuracy ---
    const int chance = TaceIniInt("COPWEAPONS", "SwatSecondaryChance", -1);
    if (chance >= 0 && chance <= 100)
    {
        // Compared against rand(), which runs 0..32767.
        uint32_t *thr = swatMain.get_first<uint32_t>(32);
        if (*thr == 0x3FFF)
        {
            const uint32_t value = static_cast<uint32_t>(chance * 32767 / 100);
            injector::WriteMemory<uint32_t>(thr, value, true);
            TaceLog("[cops] SWAT secondary chance: 50%% -> %d%%", chance);
        }
        else
        {
            TaceLog("[cops] SWAT secondary chance: expected 0x3FFF, found 0x%X - not patched", *thr);
        }
    }

    const int copAccuracy = TaceIniInt("COPWEAPONS", "CopAccuracy", -1);
    if (copAccuracy >= 0 && copAccuracy <= 100)
    {
        uint8_t *at = copAcc.get_first<uint8_t>(14);
        if (*at == 30)
        {
            injector::WriteMemory<uint8_t>(at, static_cast<uint8_t>(copAccuracy), true);
            TaceLog("[cops] cop accuracy: 30 -> %d", copAccuracy);
        }
    }

    const int swatAccuracy = TaceIniInt("COPWEAPONS", "SwatAccuracy", -1);
    if (swatAccuracy >= 0 && swatAccuracy <= 100)
    {
        uint8_t *at = swatAcc.get_first<uint8_t>(18);
        if (*at == 40)
        {
            injector::WriteMemory<uint8_t>(at, static_cast<uint8_t>(swatAccuracy), true);
            TaceLog("[cops] SWAT accuracy: 40 -> %d", swatAccuracy);
        }
    }

    TaceLog("[cops] note: PoliceEpisodicWeaponSupport makes the TBoGT branch run in every"
            " episode, so SwatPrimaryTBoGT is the setting that takes effect");
    TaceLog("[cops] ---- done ----");
}
