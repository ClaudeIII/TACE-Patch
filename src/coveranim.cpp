#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <Hooking.Patterns.h>

#include "Config.h"
#include "Log.h"
#include "Patterns.h"
#include "Weapons.h"

// ============================================================================
// Per-weapon cover blind-fire animations.
//
// Every shotgun in WeaponInfo.xml is group="SHOTGUN", and in cover that group
// plays SHOTGUN_BLINDFIRE - which pumps. Correct for the pump-action, nonsense
// for the sawn-off, the AA-12 and the rest, which have nothing to pump. The
// engine chooses by weapon GROUP, so all six are stuck with the same one.
//
// Eight cover animation sets - cover_l/r_high/low_centre/corner, anim group IDs
// 0x22-0x29 - all share one 27-entry table of animation NAMES, and slot 24 is
// the one group="SHOTGUN" plays:
//
//     [ 7] Pistol_BlindFire     [15] Rifle_BlindFire
//     [22] AK47_BLINDFIRE       [23] UZI_BLINDFIRE
//     [24] SHOTGUN_BLINDFIRE    [25] ROCKET_BLINDFIRE
//
// This repoints slot 24's NAME at another entry's, and puts it back when the
// weapon changes. The selection logic is never touched: it still picks slot 24,
// that slot just names a different animation.
//
// HOW, exactly. Playing an animation goes through
//
//     sub_9267D0(groupId, animId):
//         count = group[+0x38];  arr = group[+0x40];   // pNameIndex
//         ...binary search arr by animId...
//         if (arr[0] == animId) return arr[1];         // the dictionary key
//
// so pNameIndex is an array of {animId, key} pairs sorted BY animId, and the
// key is what actually fetches the animation out of the group's dictionary.
// That lookup runs at PLAY time, every time - which is what makes a per-weapon
// override possible at all.
//
// So: find the pair whose animId is SHOTGUN_BLINDFIRE's and give it another
// pair's key. No id is duplicated, the binary search stays sorted and intact,
// and the change takes effect the next time the animation is played.
//
// The other two arrays are wrong to touch, and both were tried first:
//   +0x3C ppszNames  slot -> name, but it is consumed when the group is
//                    registered. Changing it before that works (and was the
//                    proof of concept); changing it later does nothing.
//   +0x44 pAnimData  slot -> {animId, flags, type}. Those ids are unique and
//                    are the binary search key above - duplicating one
//                    crashed the game in a float blend loop.
//
// LIMITATION, inherent to the approach: the name table is global, so this keys
// off the PLAYER's weapon. An NPC blind-firing a shotgun from cover at the same
// moment gets whatever the player's current override is. Cover blind-fire is
// overwhelmingly player-facing, so that is the trade for not hooking the
// engine's selection path.
//
// Nothing is hardcoded to an address; every global is read out of an
// instruction found by byte signature.
// ============================================================================

namespace
{
    // ---- signatures ------------------------------------------------------

    // Registration of the first cover set. Without the trailing group ID this
    // matches all eight; with it, exactly one.
    //   push <name table>  <- at +14
    //   push 0x1B          <- 27 animations
    //   push "cover_l_high_centre" x2
    //   push 0x22
    const char *kCoverTableSig =
        "6A 00 6A 01 6A 01 6A 01 68 ? ? ? ? 68 ? ? ? ? 6A 1B 68 ? ? ? ? 68 ? ? ? ? 6A 22";
    constexpr int kCoverTableOperand = 14;   // ppszNames
    constexpr int kAnimDataOperand   = 9;    // pAnimData, pushed just before it

    // CPlayer::getPlayerPed:
    //   mov eax,[esp+4] ; test eax,eax ; jne ...
    //   mov eax,[nLocalPlayer] ; cmp eax,-1 ; je ...
    //   mov eax,[eax*4 + g_pPlayers] ; test eax,eax ; je ...
    //   mov eax,[eax + 0x58C] ; ret
    const char *kPlayerPedSig =
        "8B 44 24 04 85 C0 75 15 A1 ? ? ? ? 83 F8 FF 74 12 8B 04 85 ? ? ? ? 85 C0 74 07 8B 80 ? ? 00 00 C3";
    constexpr int kLocalPlayerOperand = 9;
    constexpr int kPlayersOperand     = 21;
    constexpr int kPedOnPlayerOperand = 31;

    // GET_CURRENT_CHAR_WEAPON, for the two CPed offsets:
    //   lea ecx,[eax + <base>] ; mov eax,[ecx + <slot>] ; add eax,<n>
    // then the index is scaled by 12, so <n> is worth n*12 bytes.
    const char *kCurWeaponSig =
        "8B 44 24 04 8B 0D ? ? ? ? 56 50 E8 ? ? ? ? 8B 74 24 0C 8D 88 ? ? 00 00 8B 41 ? 83 C0 ?";
    constexpr int kWeapBaseOperand = 23;
    constexpr int kWeapSlotOperand = 29;
    constexpr int kWeapAddOperand  = 32;

    // CAnimAssociations::getAnimGroupByIndex:
    //   mov eax,[esp+4] ; imul eax,eax,88 ; add eax,[ms_animGroups] ; retn 4
    const char *kAnimGroupsSig = "8B 44 24 04 6B C0 58 03 05 ? ? ? ? C2 04 00";
    constexpr int kAnimGroupsOperand = 9;

    constexpr int kCoverAnimCount = 27;
    constexpr int kSlotShotgun    = 24;   // the slot group="SHOTGUN" plays
    constexpr int kWeaponStride   = 12;   // CPed's weapon array

    constexpr int kCoverGroupFirst  = 0x22;  // cover_l_high_centre
    constexpr int kCoverGroupCount  = 8;     // ... through cover_r_low_corner
    constexpr int kAnimGroupStride  = 88;
    constexpr int kGroupCountOffset = 0x38;  // dwAnimCount
    constexpr int kGroupIndexOffset = 0x40;  // pNameIndex, {animId,key} pairs
    constexpr int kAnimDataStride   = 12;    // pAnimData: {animId,flags,type}

    // ---- resolved at init ------------------------------------------------

    const char **gCoverNames   = nullptr;
    uint32_t    *gAnimData     = nullptr;   // slot -> {animId, flags, type}
    uint8_t    **gAnimGroups   = nullptr;   // &ms_animGroups.pData
    int         *gLocalPlayer  = nullptr;
    uint8_t    **gPlayers      = nullptr;
    uint32_t     gPedOnPlayer  = 0;
    uint32_t     gWeapSlotOfs  = 0;
    uint32_t     gWeapArrayOfs = 0;

    struct Override { int weaponId; uint32_t animId; std::string weapon, anim; };
    std::vector<Override> gOverrides;

    uint32_t gShotgunAnimId = 0;
    uint32_t gVanillaKey[kCoverGroupCount]{};   // per group - keys are per dictionary
    bool     gHaveVanillaKey = false;
    int      gAppliedFor = -1;   // weapon id applied, -1 = vanilla

    // ---- helpers ---------------------------------------------------------

    int FindAnimSlot(const char *want)
    {
        for (int i = 0; i < kCoverAnimCount; i++)
            if (gCoverNames[i] && _stricmp(gCoverNames[i], want) == 0)
                return i;
        return -1;
    }

    uint8_t *PlayerPed()
    {
        if (!gLocalPlayer || !gPlayers || *gLocalPlayer < 0)
            return nullptr;
        uint8_t *player = gPlayers[*gLocalPlayer];
        return player ? *reinterpret_cast<uint8_t **>(player + gPedOnPlayer) : nullptr;
    }

    int CurrentWeapon()
    {
        uint8_t *ped = PlayerPed();
        if (!ped)
            return -1;
        const int slot = *reinterpret_cast<int *>(ped + gWeapSlotOfs);
        if (slot < 0 || slot > 16)
            return -1;
        return *reinterpret_cast<int *>(ped + gWeapArrayOfs + kWeaponStride * slot);
    }

    uint8_t *CoverGroup(int index)
    {
        uint8_t *base = *gAnimGroups;
        return base ? base + kAnimGroupStride * (kCoverGroupFirst + index) : nullptr;
    }

    // The {animId, key} pair for `animId` in one group, or null. Linear rather
    // than binary: 27 entries, and it must not care whether the array is
    // perfectly sorted.
    uint32_t *FindPair(uint8_t *group, uint32_t animId)
    {
        const int count = *reinterpret_cast<int *>(group + kGroupCountOffset);
        uint32_t *arr = *reinterpret_cast<uint32_t **>(group + kGroupIndexOffset);
        if (!arr || count <= 0 || count > 256)
            return nullptr;
        for (int i = 0; i < count; i++)
            if (arr[2 * i] == animId)
                return arr + 2 * i;
        return nullptr;
    }

    // Every cover set registered, the right size, and carrying the shotgun id.
    bool GroupsReady()
    {
        if (!gAnimGroups || !*gAnimGroups || !gShotgunAnimId)
            return false;
        for (int g = 0; g < kCoverGroupCount; g++)
        {
            uint8_t *group = CoverGroup(g);
            if (!group || *reinterpret_cast<int *>(group + kGroupCountOffset) != kCoverAnimCount)
                return false;
            if (!FindPair(group, gShotgunAnimId))
                return false;
        }
        return true;
    }

    // Give SHOTGUN_BLINDFIRE's pair the key belonging to `animId`, per group -
    // the keys differ per dictionary, so each set is looked up on its own.
    // animId == 0 restores vanilla.
    void ApplyKey(uint32_t animId)
    {
        for (int g = 0; g < kCoverGroupCount; g++)
        {
            uint8_t *group = CoverGroup(g);
            uint32_t *shotgun = FindPair(group, gShotgunAnimId);
            if (!shotgun)
                continue;

            uint32_t key;
            if (animId == 0)
            {
                key = gVanillaKey[g];
            }
            else
            {
                uint32_t *src = FindPair(group, animId);
                if (!src)
                    continue;
                key = src[1];
            }

            DWORD old = 0;
            if (VirtualProtect(shotgun + 1, sizeof(uint32_t), PAGE_READWRITE, &old))
            {
                shotgun[1] = key;
                VirtualProtect(shotgun + 1, sizeof(uint32_t), old, &old);
            }
        }
    }

    const Override *OverrideFor(int weaponId)
    {
        for (const Override &o : gOverrides)
            if (o.weaponId == weaponId)
                return &o;
        return nullptr;
    }

    DWORD WINAPI CoverThread(LPVOID)
    {
        static const bool trace = TaceTraceEnabled("cover");

        // The cover sets do not exist until the game registers them, well after
        // the .asi loads.
        while (!GroupsReady())
            Sleep(250);

        for (int g = 0; g < kCoverGroupCount; g++)
            gVanillaKey[g] = FindPair(CoverGroup(g), gShotgunAnimId)[1];
        gHaveVanillaKey = true;

        TACE_OK("[cover] cover animation sets ready - %d weapon override(s) armed",
                static_cast<int>(gOverrides.size()));

        if (trace)
            for (int g = 0; g < kCoverGroupCount; g++)
                TACE_TRACE("[cover] group 0x%02X: SHOTGUN_BLINDFIRE (id 0x%X) key 0x%08X",
                           kCoverGroupFirst + g, gShotgunAnimId, gVanillaKey[g]);

        bool reportedFirst = false;
        int  quietTicks = 0;

        for (;;)
        {
            Sleep(100);

            const int weapon = CurrentWeapon();

            // Report the first weapon actually read. Without this, a bad offset
            // just means nothing ever happens, quietly - which is how an
            // earlier build failed: a healthy-looking log and no swap.
            if (!reportedFirst && weapon >= 0)
            {
                reportedFirst = true;
                TACE_INFO("[cover] reading the player's weapon: currently %d", weapon);
            }
            else if (!reportedFirst && ++quietTicks == 300)   // ~30s of nothing
            {
                TACE_WARN("[cover] the player's weapon has not been readable for 30s - "
                          "the ped offsets look wrong, no override will ever apply");
            }

            const Override *o = weapon >= 0 ? OverrideFor(weapon) : nullptr;
            const int want = o ? o->weaponId : -1;

            if (want == gAppliedFor)
                continue;

            ApplyKey(o ? o->animId : 0);
            gAppliedFor = want;

            if (trace)
            {
                if (o)
                    TACE_TRACE("[cover] %s in hand - blind-fire now plays %s (id 0x%X)",
                               o->weapon.c_str(), o->anim.c_str(), o->animId);
                else
                    TACE_TRACE("[cover] weapon %d has no override - blind-fire back to vanilla",
                               weapon);
            }
        }
    }
}

void CoverAnim_Init()
{
    if (!TaceIniBool("COVERANIM", "Enabled", false))
        return;

    hook::pattern pattern = find_pattern(kCoverTableSig);
    if (pattern.empty() || pattern.size() != 1)
    {
        TACE_WARN("[cover] cover animation table: signature %s - not applied",
                  pattern.empty() ? "not found" : "matched more than once");
        return;
    }
    gCoverNames = *pattern.get_first<const char **>(kCoverTableOperand);
    gAnimData   = *pattern.get_first<uint32_t *>(kAnimDataOperand);

    if (!gCoverNames || !gCoverNames[kSlotShotgun] ||
        _stricmp(gCoverNames[kSlotShotgun], "SHOTGUN_BLINDFIRE") != 0)
    {
        TACE_WARN("[cover] slot %d is \"%s\", expected \"SHOTGUN_BLINDFIRE\" - "
                  "not the layout this was written for, nothing applied", kSlotShotgun,
                  (gCoverNames && gCoverNames[kSlotShotgun]) ? gCoverNames[kSlotShotgun] : "<null>");
        return;
    }
    if (!gAnimData)
    {
        TACE_WARN("[cover] animation id table resolved to null - not applied");
        return;
    }
    gShotgunAnimId = gAnimData[kSlotShotgun * kAnimDataStride / sizeof(uint32_t)];

    static const bool trace = TaceTraceEnabled("cover");
    if (trace)
    {
        TACE_TRACE("[cover] names at %p, animation ids at %p", gCoverNames, gAnimData);
        for (int i = 0; i < kCoverAnimCount; i++)
            TACE_TRACE("[cover]   [%2d] id 0x%03X  %s", i,
                       gAnimData[i * kAnimDataStride / sizeof(uint32_t)],
                       gCoverNames[i] ? gCoverNames[i] : "<null>");
    }

    pattern = find_pattern(kAnimGroupsSig);
    if (pattern.empty())
    {
        TACE_WARN("[cover] anim group array: signature not found - not applied");
        return;
    }
    gAnimGroups = *pattern.get_first<uint8_t **>(kAnimGroupsOperand);

    pattern = find_pattern(kPlayerPedSig);
    if (pattern.empty())
    {
        TACE_WARN("[cover] player ped accessor: signature not found - not applied");
        return;
    }
    gLocalPlayer = *pattern.get_first<int *>(kLocalPlayerOperand);
    gPlayers     = *pattern.get_first<uint8_t **>(kPlayersOperand);
    gPedOnPlayer = *pattern.get_first<uint32_t>(kPedOnPlayerOperand);

    pattern = find_pattern(kCurWeaponSig);
    if (pattern.empty())
    {
        TACE_WARN("[cover] current weapon accessor: signature not found - not applied");
        return;
    }
    {
        const uint32_t base = *pattern.get_first<uint32_t>(kWeapBaseOperand);
        const uint8_t  slot = *pattern.get_first<uint8_t>(kWeapSlotOperand);
        const uint8_t  add  = *pattern.get_first<uint8_t>(kWeapAddOperand);
        gWeapSlotOfs  = base + slot;
        gWeapArrayOfs = base + add * kWeaponStride;
    }

    if (trace)
        TACE_TRACE("[cover] players %p  ped+0x%X  weapon slot ped+0x%X  weapons ped+0x%X",
                   gPlayers, gPedOnPlayer, gWeapSlotOfs, gWeapArrayOfs);

    // Any key naming a weapon is an override; the value is the animation it
    // should blind-fire with. Only weapons the engine treats as group="SHOTGUN"
    // reach slot 24, so anything else is accepted and simply never fires.
    for (const NamedId &w : kWeapons)
    {
        const std::string value = TaceIniString("COVERANIM", w.name);
        if (value.empty())
            continue;

        const int slot = FindAnimSlot(value.c_str());
        if (slot < 0)
        {
            TACE_WARN("[cover] %s = \"%s\" is not an animation in the cover set - ignored. "
                      "Set [DEBUG] Trace = cover to list the valid names", w.name, value.c_str());
            continue;
        }
        if (OverrideFor(w.id))
            continue;   // an alias for a weapon already configured

        const uint32_t animId = gAnimData[slot * kAnimDataStride / sizeof(uint32_t)];
        gOverrides.push_back({ w.id, animId, w.name, value });
        TACE_INFO("[cover] %s blind-fires with %s (id 0x%X)", w.name, value.c_str(), animId);
    }

    if (gOverrides.empty())
    {
        TACE_INFO("[cover] enabled, but no weapon overrides set - nothing to do");
        return;
    }

    CreateThread(nullptr, 0, CoverThread, nullptr, 0, nullptr);
}
