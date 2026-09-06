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
    // The clip is not a plain field: GET_AMMO_IN_CLIP goes
    //   weaponMgr = ped + <base>  ->  sub(weaponMgr) = weapon object
    //   -> CPBuffer::get(obj + 92) -> XLivePBufferGetDWORD
    // because ammo lives in a Games for Windows Live protected buffer. So both
    // accessors are called rather than the memory being read directly.
    //
    //   mov eax,[ecx+2C] ; test eax,eax ; jz .. ; mov eax,[eax+25C] ; ...
    const char *kWeaponObjSig =
        "8B 41 2C 85 C0 74 1E 8B 80 5C 02 00 00 85 C0 74 20 8B 51 18 83 C2 05 56 8B 70 18 8D 14 52 3B 34 91 5E 75 0D C3";
    //   push ecx ; mov ecx,[ecx] ; lea eax,[esp] ; push eax ; push 0 ; push ecx
    //   mov [esp+0C],0 ; call XLivePBufferGetDWORD ; mov eax,[esp] ; pop ecx ; ret
    const char *kPBufferGetSig =
        "51 8B 09 8D 04 24 50 6A 00 51 C7 44 24 0C 00 00 00 00 E8 ? ? ? ? 8B 04 24 59 C3";

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
    uint32_t     gWeapMgrOfs   = 0;   // ped -> weapon manager
    uint32_t     gWeapSlotOfs  = 0;
    uint32_t     gWeapArrayOfs = 0;

    // Both are __thiscall with no arguments; __fastcall with an unused edx is
    // the usual way to spell that for a plain function pointer.
    using ThisCall0 = int(__fastcall *)(void *ecx, void *edx);
    ThisCall0 gWeaponObj  = nullptr;
    ThisCall0 gPBufferGet = nullptr;

    struct Override { int weaponId; uint32_t animId; std::string weapon, anim; };
    std::vector<Override> gOverrides;

    bool  gCutWhenEmpty = true;   // end the blind-fire animation on an empty clip
    int   gCutDelayMs   = 0;      // ... but not until this long after it empties
    float gCutAt        = 1.0f;   // the point to jump to; 1.0 is the end
    uint32_t gShotgunAnimId = 0;
    uint32_t gVanillaKey[kCoverGroupCount]{};   // per group - keys are per dictionary
    bool     gHaveVanillaKey = false;
    int      gAppliedFor = -1;   // weapon id applied, -1 = vanilla
    bool     gAppliedEmpty = false;

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

    // The animation instance currently playing `animId` on this ped, or null.
    //
    // A walk of the blender's association list, replicated rather than called:
    // the game's own lookup is __thiscall with stack arguments, and getting
    // that wrong is a crash, whereas these reads are harmless. Every offset
    // below was verified byte-identical between 1.0.8.0 and EFLC 1.1.2.0.
    //
    //   ped+0x78      -> blender
    //   blender+0x1A28-> first node
    //   node+0x48     == 1 for a live node
    //   node+4        -> the association
    //   node+0x8C     -> next node
    //   assoc+0x40    != 0
    //   assoc+0x0C    == the animation id
    uint8_t *FindPlayingAnim(uint8_t *ped, uint32_t animId)
    {
        uint8_t *blender = *reinterpret_cast<uint8_t **>(ped + 0x78);
        if (!blender)
            return nullptr;

        uint8_t *node = *reinterpret_cast<uint8_t **>(blender + 0x1A28);
        for (int guard = 0; node && guard < 256; guard++)
        {
            uint8_t *assoc = node + 4;
            if (*reinterpret_cast<uint16_t *>(node + 0x48) == 1 &&
                *reinterpret_cast<uint32_t *>(assoc + 0x40) != 0 &&
                *reinterpret_cast<uint32_t *>(assoc + 0x0C) == animId)
                return assoc;
            node = *reinterpret_cast<uint8_t **>(node + 0x8C);
        }
        return nullptr;
    }

    // Every animation id currently playing on this ped, for diagnosis when a
    // lookup comes up empty.
    void TracePlayingAnims(uint8_t *ped)
    {
        uint8_t *blender = *reinterpret_cast<uint8_t **>(ped + 0x78);
        if (!blender)
        {
            TACE_TRACE("[cover] ped has no animation blender");
            return;
        }
        uint8_t *node = *reinterpret_cast<uint8_t **>(blender + 0x1A28);
        int n = 0;
        for (int guard = 0; node && guard < 256; guard++)
        {
            uint8_t *assoc = node + 4;
            if (*reinterpret_cast<uint16_t *>(node + 0x48) == 1 &&
                *reinterpret_cast<uint32_t *>(assoc + 0x40) != 0)
            {
                TACE_TRACE("[cover]   playing id 0x%X",
                           *reinterpret_cast<uint32_t *>(assoc + 0x0C));
                n++;
            }
            node = *reinterpret_cast<uint8_t **>(node + 0x8C);
        }
        TACE_TRACE("[cover] %d animation(s) playing", n);
    }

    // Wind a playing animation forward to `target`. setAnimCurrentTime clamps
    // to 0..1 and writes exactly these two floats, so 1.0 means finished -
    // which lets a looping blind-fire stop and the reload begin. A lower value
    // leaves a tail of animation still to play, which reads less abruptly.
    //
    // Only ever winds FORWARD. This is re-asserted every tick while the clip is
    // empty, and writing the same value repeatedly would otherwise pin the
    // animation in place and stop it ever finishing.
    bool EndPlayingAnim(uint8_t *ped, uint32_t animId, float target)
    {
        uint8_t *assoc = FindPlayingAnim(ped, animId);
        if (!assoc)
            return false;

        float *now = reinterpret_cast<float *>(assoc + 0x4C);
        if (*now >= target)
            return false;

        *now = target;
        *reinterpret_cast<float *>(assoc + 0x50) = target;
        return true;
    }

    // Rounds in the current weapon's clip, or -1 if it cannot be read.
    int ClipAmmo()
    {
        if (!gWeaponObj || !gPBufferGet)
            return -1;
        uint8_t *ped = PlayerPed();
        if (!ped)
            return -1;
        const int obj = gWeaponObj(ped + gWeapMgrOfs, nullptr);
        if (!obj)
            return -1;
        return gPBufferGet(reinterpret_cast<void *>(obj + 92), nullptr);
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
        int   lastAmmo = -2;
        DWORD emptySince = 0;

        for (;;)
        {
            // Poll faster while an override is in hand: the whole point is to
            // catch the clip emptying within a beat of the animation, not a
            // tenth of a second later.
            Sleep(gAppliedFor >= 0 ? 25 : 100);

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

            // Once the clip is empty the animation has nothing left to fire,
            // but a looping one carries on regardless - AK47_BLINDFIRE spends
            // about five seconds on an empty chamber before the game reaches
            // the reload, against 1.4s for a non-looping one.
            //
            // Swapping the key cannot help here: the animation is resolved
            // when the burst starts and cached for its duration, so the change
            // lands on an instance that has already been chosen (measured - the
            // swap fired on the same millisecond and the dead time did not
            // move). Ending the playing instance is what actually works.
            bool empty = false;
            if (o)
            {
                const int ammo = ClipAmmo();
                empty = (ammo == 0);

                if (ammo != lastAmmo)
                {
                    if (trace)
                        TACE_TRACE("[cover] %s clip: %d", o->weapon.c_str(), ammo);
                    if (empty)
                        emptySince = GetTickCount();
                    lastAmmo = ammo;
                }

                // Keep asserting it: the loop may start another cycle, and each
                // one is a fresh instance to finish off.
                //
                // Search for the SHOTGUN id, not the override's. The engine
                // still asks for slot 24's animation - all we changed is what
                // that id resolves to - so the live association is tagged
                // 0x112 even while it is playing the AK47 clip.
                // Hold off for CutDelay so the last shot's animation is not
                // snatched away the instant the chamber runs dry.
                const bool delayPassed =
                    emptySince && (GetTickCount() - emptySince) >= static_cast<DWORD>(gCutDelayMs);

                if (empty && gCutWhenEmpty && delayPassed)
                {
                    uint8_t *ped = PlayerPed();
                    const bool ended = ped && EndPlayingAnim(ped, gShotgunAnimId, gCutAt);
                    if (trace && !gAppliedEmpty)
                    {
                        if (ended)
                            TACE_TRACE("[cover] %s empty - ended the blind-fire animation (id 0x%X)",
                                       o->weapon.c_str(), gShotgunAnimId);
                        else if (ped)
                        {
                            TACE_TRACE("[cover] %s empty - no animation with id 0x%X is playing:",
                                       o->weapon.c_str(), gShotgunAnimId);
                            TracePlayingAnims(ped);
                        }
                    }
                }
            }

            if (want == gAppliedFor && empty == gAppliedEmpty)
                continue;

            if (!o)
                ApplyKey(0);
            else
                ApplyKey(o->animId);

            gAppliedFor   = want;
            gAppliedEmpty = empty;

            if (trace)
            {
                if (o && empty)
                    ;   // already reported above
                else if (o)
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
        gWeapMgrOfs   = base;
        gWeapSlotOfs  = base + slot;
        gWeapArrayOfs = base + add * kWeaponStride;
    }

    pattern = find_pattern(kWeaponObjSig);
    if (!pattern.empty())
        gWeaponObj = pattern.get_first<int(__fastcall)(void *, void *)>(0);
    else
        TACE_WARN("[cover] weapon object accessor: signature not found - clip ammo unavailable");

    pattern = find_pattern(kPBufferGetSig);
    if (!pattern.empty())
        gPBufferGet = pattern.get_first<int(__fastcall)(void *, void *)>(0);
    else
        TACE_WARN("[cover] CPBuffer::get: signature not found - clip ammo unavailable");

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

    gCutWhenEmpty = TaceIniBool("COVERANIM", "CutWhenEmpty", true);
    gCutDelayMs   = TaceIniInt("COVERANIM", "CutDelay", 0);
    if (gCutDelayMs < 0)    gCutDelayMs = 0;
    if (gCutDelayMs > 3000) gCutDelayMs = 3000;

    // Written as a percentage so the ini stays whole numbers.
    {
        int at = TaceIniInt("COVERANIM", "CutAt", 100);
        if (at < 10)  at = 10;
        if (at > 100) at = 100;
        gCutAt = static_cast<float>(at) / 100.0f;
    }

    TACE_INFO("[cover] cut on an empty clip: %s (delay %dms, wind to %d%%)",
              gCutWhenEmpty ? "yes" : "no", gCutDelayMs,
              static_cast<int>(gCutAt * 100.0f));

    if (gOverrides.empty())
    {
        TACE_INFO("[cover] enabled, but no weapon overrides set - nothing to do");
        return;
    }

    CreateThread(nullptr, 0, CoverThread, nullptr, 0, nullptr);
}
