#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <algorithm>
#include <cmath>
#include <cstdint>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Config.h"
#include "Log.h"
#include "Patterns.h"

// ============================================================================
// Silenced weapons that are actually quiet.
//
// WeaponInfo.xml's SILENCED flag (weapon info +0x20, bit 0x100) is read in one
// place: the function that posts the "a gun went off" events after every
// instant-hit shot. All it does there is skip the sound event
// (CEventSoundDynamic, 120 m) and hand the flag on to CEventGunShot. Two
// things still give the shot away:
//
//   - The GunshotFired shocking event is posted either way, and
//     ShockingEvents.dat gives it a 100 m AUDIBLE range - every ambient ped
//     that close panics. This is most of "they can still hear it".
//   - CEventGunShot::affectsPed judges a silenced shot as seen rather than
//     heard, but "seen" is generous: any ped within 45 m (a mission ped: its
//     own sense range) with the shot anywhere in the half in front of them and
//     a clear line of sight.
//
// So a silenced weapon posts no GunshotFired, and the gunshot event's
// affectsPed gets a real range and field of view around the vanilla test,
// which still does the line of sight. Peds right beside the shooter hear it
// as an ordinary shot. Left alone on purpose: bullets whizzing past a ped,
// bullet impacts, and whatever a ped sees happen next (someone hit, a body) -
// those are noticed silenced or not. Script checks such as
// IS_CHAR_SHOOTING_IN_AREA are untouched too, so missions behave as written.
//
// SET_EVERYONE_IGNORE_PLAYER is not the lever for this: its flag (CWanted
// +0x5A bit 4) is only read by combat target selection and the arrest and
// police checks, so it stops peds fighting the player, not hearing the shot.
// ============================================================================

namespace
{
    // CEventGunShot, the same in EFLC 1.1.2.0 and 1.0.8.0
    constexpr size_t kEventShooter  = 0x18;
    constexpr size_t kEventMuzzle   = 0x20;   // where the shot came from
    constexpr size_t kEventSilenced = 0x40;   // the weapon's SILENCED flag
    constexpr size_t kEventWeapon   = 0x48;
    constexpr int    kStickyBomb    = 36;     // EPISODIC_16

    // CEntity: its own position, or its matrix's (forward at +0x10, position at +0x30)
    constexpr size_t kEntityPos     = 0x10;
    constexpr size_t kEntityMatrix  = 0x20;
    constexpr size_t kEntityType    = 0x28;   // (x & 0x3C0) == 0xC0: a ped
    constexpr size_t kPedPlayerInfo = 0x228;  // null for anyone but the player

    constexpr size_t   kWeaponFlags  = 0x20;
    constexpr uint32_t kFlagSilenced = 0x100; // WeaponInfo.xml flags from CAN_AIM = bit 0
    constexpr int      kGunshotFired = 27;    // ShockingEvents.dat line order, from 1

    bool  gTrace = false;
    int   gTraceLeft = 0;
    float gHearRange = 0.0f;
    float gSeeRange = 0.0f;
    float gSeeCos = 0.0f;

    template<typename T>
    T Field(const void *base, size_t offset)
    {
        return *reinterpret_cast<const T *>(static_cast<const uint8_t *>(base) + offset);
    }

    const float *Position(const uint8_t *entity)
    {
        const uint8_t *matrix = Field<uint8_t *>(entity, kEntityMatrix);
        return reinterpret_cast<const float *>(matrix != nullptr ? matrix + 0x30 : entity + kEntityPos);
    }

    const char *Who(const uint8_t *entity)
    {
        if (entity == nullptr)
            return "something";
        if ((Field<uint32_t>(entity, kEntityType) & 0x3C0) != 0xC0)
            return "a vehicle";
        return Field<void *>(entity, kPedPlayerInfo) != nullptr ? "the player" : "a ped";
    }

    bool Tracing()
    {
        return gTrace && gTraceLeft-- > 0;
    }

    // ---- the GunshotFired shocking event -----------------------------------

    using WeaponInfoFn = const uint8_t *(__cdecl *)(int weapon);
    WeaponInfoFn gWeaponInfo = nullptr;

    using ShockingAddFn = void(__cdecl *)(int type, float *pos, uint8_t *entity, int a4, int weapon, float a6);
    ShockingAddFn gShockingAdd = nullptr;

    void __cdecl ShockingAddHook(int type, float *pos, uint8_t *entity, int a4, int weapon, float a6)
    {
        const uint8_t *info = gWeaponInfo(weapon);
        if (type == kGunshotFired && info != nullptr && (Field<uint32_t>(info, kWeaponFlags) & kFlagSilenced) != 0)
        {
            if (Tracing())
                TACE_TRACE("[silenced] %s fired silenced weapon %d - no GunshotFired, no 100 m panic",
                           Who(entity), weapon);
            return;
        }
        gShockingAdd(type, pos, entity, a4, weapon, a6);
    }

    void QuietGunshotFired()
    {
        // prologue ; push <weapon> ; call <weapon info> ; ...
        // mov eax,[eax+20h] ; shr eax,8 ; and al,1                  <- SILENCED
        // cmp [<episode>],2 ; mov [esp+1Ch],al ; jl                 <- NOPed by TacePatch's "Sticky bomb"
        // ... push 1Bh ; call <CShockingEvents::add> ; add esp,18h  <- GunshotFired
        auto pattern = find_pattern("55 8B EC 83 E4 F0 81 EC 14 01 00 00 53 56 57 8B F9 8B 47 18 83 F8 2E 0F 84 ? ? ? ? "
                                    "50 E8 ? ? ? ? 83 C4 04 83 78 08 03 75 0B 83 78 0C 00 C6 44 24 1A 01 75 05 "
                                    "C6 44 24 1A 00 8B 47 18 50 E8 ? ? ? ? 8B 40 20 C1 E8 08 24 01 83 C4 04 "
                                    "83 3D ? ? ? ? 02 88 44 24 1C ? ? 83 7F 18 24 C6 44 24 1B 01 74 05 "
                                    "C6 44 24 1B 00 8B 4F 18 8B 54 24 1C 8B 45 14 8B 5D 0C 8B 75 08 51 52 50 "
                                    "83 C3 30 53 56 8D 4C 24 44 E8 ? ? ? ? 6A 01 8D 4C 24 34 6A 00 51 E8 ? ? ? ? "
                                    "8B C8 E8 ? ? ? ? 85 F6 74 2E 80 7C 24 1B 00 75 27 8B 46 20 85 C0 8B 4F 18 "
                                    "74 05 83 C0 30 EB 03 8D 46 10 D9 EE 51 D9 1C 24 51 6A 00 56 50 6A 1B "
                                    "E8 ? ? ? ? 83 C4 18");
        if (pattern.empty())
        {
            TaceLog("[silenced] GunshotFired: signature not found, not patched");
            return;
        }

        uint8_t *info = pattern.get_first<uint8_t>(30);
        uint8_t *call = pattern.get_first<uint8_t>(205);
        if (*info != 0xE8 || *call != 0xE8)
        {
            TaceLog("[silenced] ABORTED - the gunshot event calls are not calls here. Not patched.");
            return;
        }

        gWeaponInfo  = reinterpret_cast<WeaponInfoFn>(info + 5 + *reinterpret_cast<int32_t *>(info + 1));
        gShockingAdd = reinterpret_cast<ShockingAddFn>(call + 5 + *reinterpret_cast<int32_t *>(call + 1));
        injector::MakeCALL(call, ShockingAddHook, true);
        TaceLog("[silenced] OK - a silenced shot no longer sets off the 100 m GunshotFired panic");
    }

    // ---- who notices a silenced shot ---------------------------------------

    using AffectsPedFn = bool(__thiscall *)(uint8_t *event, uint8_t *ped);
    AffectsPedFn gAffectsPed = nullptr;

    bool __fastcall AffectsPedHook(uint8_t *event, void *, uint8_t *ped)
    {
        const uint8_t *shooter = Field<uint8_t *>(event, kEventShooter);
        if (event[kEventSilenced] == 0 || shooter == nullptr)
            return gAffectsPed(event, ped);

        const float *at   = Position(ped);
        const float *from = Position(shooter);
        const float dx = from[0] - at[0], dy = from[1] - at[1], dz = from[2] - at[2];
        const float dist = std::sqrt(dx * dx + dy * dy + dz * dz);

        // Close enough to hear it: judged as an ordinary shot. Not the sticky
        // bomb - vanilla keeps ambient peds out of its silenced event, and
        // clearing the flag would let them in.
        if (dist <= gHearRange && Field<int>(event, kEventWeapon) != kStickyBomb)
        {
            const uint8_t silenced = event[kEventSilenced];
            event[kEventSilenced] = 0;
            const bool heard = gAffectsPed(event, ped);
            event[kEventSilenced] = silenced;
            if (heard && Tracing())
                TACE_TRACE("[silenced] ped %p heard it, %.1f m away", ped, dist);
            return heard;
        }

        const char *why = nullptr;
        const uint8_t *matrix = Field<uint8_t *>(ped, kEntityMatrix);
        if (dist > gSeeRange)
        {
            why = "too far away";
        }
        else if (matrix != nullptr)
        {
            // Vanilla only asks that the shot is somewhere in front of the ped.
            const float *forward = reinterpret_cast<const float *>(matrix + 0x10);
            const float *muzzle  = reinterpret_cast<const float *>(event + kEventMuzzle);
            const float mx = muzzle[0] - at[0], my = muzzle[1] - at[1], mz = muzzle[2] - at[2];
            const float len = std::sqrt(mx * mx + my * my + mz * mz);
            if (len > 0.01f && forward[0] * mx + forward[1] * my + forward[2] * mz < gSeeCos * len)
                why = "not looking";
        }

        if (why == nullptr)
        {
            const bool saw = gAffectsPed(event, ped);   // vanilla: in front, with a line of sight
            if (saw && Tracing())
                TACE_TRACE("[silenced] ped %p saw it, %.1f m away", ped, dist);
            return saw;
        }

        // Tracing only: would vanilla have alerted this ped?
        if (gTrace && gTraceLeft > 0 && gAffectsPed(event, ped) && Tracing())
            TACE_TRACE("[silenced] ped %p would have reacted at %.1f m - %s", ped, dist, why);
        return false;
    }

    void NarrowWhoNotices()
    {
        // CEventGunShot::affectsPed: no shooter -> no ; shooter a ped and a friend -> no ; ...
        // cmp [ebx+48h],24h (weapon 36) ; cmp [esi+0A70h],1 ; cmp byte [ebx+40h],0 (silenced)
        auto pattern = find_pattern("55 8B EC 83 E4 F0 81 EC A4 01 00 00 53 56 8B D9 57 8B 7B 18 85 FF 0F 84 ? ? ? ? "
                                    "8B 47 28 8B 75 08 25 C0 03 00 00 3D C0 00 00 00 75 2E 57 56 E8 ? ? ? ? "
                                    "83 C4 08 84 C0 0F 85 ? ? ? ? 3B FE 0F 84 ? ? ? ? 8B 8E 24 02 00 00 57 "
                                    "E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 83 7B 48 24 75 13 80 BE 70 0A 00 00 01 75 0A "
                                    "80 7B 40 00");
        if (pattern.empty())
        {
            TaceLog("[silenced] gunshot event affectsPed: signature not found, not patched");
            return;
        }
        const uint32_t fn = uint32_t(uintptr_t(pattern.get_first<void>(0)));

        // Its one vtable slot (CEventGunShot's): the function's address as data,
        // outside the code. The whizzed-by and bullet-impact events have their own.
        auto *mod = reinterpret_cast<uint8_t *>(GetModuleHandleA(nullptr));
        auto *nt  = reinterpret_cast<IMAGE_NT_HEADERS *>(mod + reinterpret_cast<IMAGE_DOS_HEADER *>(mod)->e_lfanew);
        uint32_t *slot = nullptr;
        int found = 0;
        const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;
            auto *p   = reinterpret_cast<uint32_t *>(mod + sec->VirtualAddress);
            auto *end = reinterpret_cast<uint32_t *>(mod + sec->VirtualAddress + (sec->Misc.VirtualSize & ~3u));
            for (; p < end; p++)
                if (*p == fn && found++ == 0)
                    slot = p;
        }
        if (found != 1)
        {
            TaceLog("[silenced] ABORTED - the gunshot event's affectsPed has %d vtable slots, expected 1. Not patched.", found);
            return;
        }

        gAffectsPed = reinterpret_cast<AffectsPedFn>(uintptr_t(fn));
        injector::WriteMemory<uint32_t>(slot, uint32_t(uintptr_t(&AffectsPedHook)), true);
        TaceLog("[silenced] OK - a silenced shot is heard within %.0f m, and seen within %.0f m by peds looking at it",
                gHearRange, gSeeRange);
    }
}

void Silenced_Init()
{
    if (!TaceIniBool("SILENCED", "Enabled", true))
    {
        TaceLog("[silenced] Enabled = 0 - silenced weapons as vanilla");
        return;
    }

    gHearRange = float(std::clamp(TaceIniInt("SILENCED", "HearRange", 3), 0, 100));
    gSeeRange  = float(std::clamp(TaceIniInt("SILENCED", "SeeRange", 25), 0, 200));
    const int angle = std::clamp(TaceIniInt("SILENCED", "SeeAngle", 120), 0, 360);
    gSeeCos = std::cos(float(angle) * 0.5f * 3.14159265f / 180.0f);
    gTrace = TaceTraceEnabled("silenced");
    gTraceLeft = TaceTraceBudget(200);

    QuietGunshotFired();
    NarrowWhoNotices();
}
