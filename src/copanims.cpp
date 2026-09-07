#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Config.h"
#include "Log.h"
#include "Patterns.h"

// ============================================================================
// Cop-style weapon animations for the player.
//
// GTA IV has TWO ways a ped can carry a gun, and the player only ever gets one
// of them.
//
//   THE PLAYER'S WAY. Draw a rifle and CPed::chooseMoveAnimGroup swaps the
//   whole MOVEMENT set: move_player becomes move_rifle (anim group 50), or
//   move_f@armed (51) on a female, or move_crouch_rifle (55) ducked. The
//   walkstyle is gone - every step, turn and idle now comes out of the rifle
//   set. That is why an armed player walks like nobody else in the game.
//
//   THE COP'S WAY. A cop keeps their own walkstyle - move_cop, move_m@swat,
//   whatever their model ships with - and the gun is a PARTIAL animation
//   layered on top of it. That is what gun@cops.wad is for. The whole
//   dictionary is four animations, anim group 0x20:
//
//       slot 0  PISTOL_PARTIAL_A    id 0xE9 (233)
//       slot 1  PISTOL_PARTIAL_B    id 0xEA (234)
//       slot 2  SWAT_RIFLE          id 0xEB (235)
//       slot 3  SWAT_RIFLE_CROUCH   id 0xEC (236)
//
// This makes the player use the cop's way.
//
// HOW THE ENGINE CHOOSES, exactly. CTaskSimplePlayUpperCombatAnim asks a
// helper - `chooseUpperCombatAnim(ped, &group, &anim)`, 1.0.8.0 0x00C20BC0 -
// which is short enough to quote:
//
//     if (ped->modelId == M_Y_Swat)            return false;   // SWAT is special
//     w = ped->weapons.currentSlot();
//     if (!w)                                  return false;
//     f = weaponInfo(w->type)->flags;
//     if ((f & GUN) && !(f & 2HANDED)) {                       // one-handed
//         *group = 0x20;  *anim = 234 - (ped->seed > 0x3FDE);  // PISTOL_PARTIAL_A/B
//         return true;
//     }
//     if (!(f & GUN) || !(f & 2HANDED))        return false;
//     *group = 0x20;  *anim = 235 + isDucking(ped);            // SWAT_RIFLE[_CROUCH]
//     return true;
//
// So the 2HANDED flag in WeaponInfo.xml is the whole switch, and A-vs-B is a
// per-ped coin flip off the ped's random seed. Nothing in there is cop-only -
// it works verbatim on the player - so this feature CALLS THAT FUNCTION rather
// than reimplementing it. Add a 2HANDED flag to a weapon and it gets the rifle
// pose here for free, with no code change.
//
// Only CTaskComplexCombatAdditionalTask ever starts that task, and the player
// never runs the AI combat task, which is why the player has never seen these
// animations.
//
// TWO HALVES, both optional:
//
//   KeepWalkstyle  intercepts CPedMoveBlend::setMoveAnimGroup for the player
//                  and rewrites move_rifle / move_f@armed back to the ped's
//                  own m_nDefaultAnimGroup, and move_crouch_rifle to
//                  move_crouch. Exactly the fallthrough a ped with no rifle
//                  would have taken.
//   Partial        plays the animation the engine's own chooser picks, and
//                  replays it when it ends - which is all
//                  CTaskSimplePlayUpperCombatAnim does.
//
// Both are needed for the effect. KeepWalkstyle alone gives an armed player
// walking empty-handed; Partial alone layers a partial gun pose over the
// full-body rifle walk that is already playing.
//
// Nothing here is hardcoded to an address: every function and every structure
// offset is read out of an instruction found by byte signature.
// ============================================================================

extern "C" int __cdecl CopAnims_MoveGroup(void *ped, int group);

namespace
{
    // ---- anim group ids --------------------------------------------------
    //
    // Registered by CAnimAssociations::defineGroup with these ids baked in as
    // immediates, identical on 1.0.8.0 and EFLC 1.1.2.0. Verified against the
    // executable by locating each group NAME string and reading the id pushed
    // beside it, rather than trusted from a table.
    constexpr int kMoveGenericM    = 0x2F;   // 47  move_m@generic (0x30 = move_f@generic,
                                             //     0x31 = move_player - the on-foot sets)
    constexpr int kMoveRifle       = 0x32;   // 50  move_rifle
    constexpr int kMoveFArmed      = 0x33;   // 51  move_f@armed
    constexpr int kMoveCrouch      = 0x36;   // 54  move_crouch
    constexpr int kMoveCrouchRifle = 0x37;   // 55  move_crouch_rifle
    constexpr int kMoveRpg         = 0x38;   // 56  move_rpg
    constexpr int kMoveCrouchRpg   = 0x39;   // 57  move_crouch_rpg
    constexpr int kMoveCrouchTrans = 0x3C;   // 60  move_crouch_trans  (idle2crouchidle)
    constexpr int kMoveCrouchTransA= 0x3D;   // 61  move_crouch_trans_armed
    constexpr int kAnimIdle        = 0x00F;  // "Idle", slot 0 of every movement set
    constexpr int kGroupGunCops    = 0x20;   // 32  GUN@COPS
    constexpr int kAnimPistolA     = 233;    // 0xE9  PISTOL_PARTIAL_A
    constexpr int kAnimPistolB     = 234;    // 0xEA  PISTOL_PARTIAL_B
    constexpr int kAnimSwatRifle   = 235;    // 0xEB  SWAT_RIFLE       - the 2HANDED pose
    constexpr int kAnimSwatCrouch  = 236;    // 0xEC  SWAT_RIFLE_CROUCH

    // ---- signatures ------------------------------------------------------

    // CPedMoveBlend::setMoveAnimGroup(int group):
    //   mov eax,[ecx+3Ch] ; mov edx,[esp+4] ; cmp edx,eax ; mov [ecx+3Ch],edx
    //   jz .. ; cmp eax,-1 ; jz .. ; movss xmm0,<1.0f>
    //   mov [ecx+40h],eax ; movss [ecx+44h],xmm0 ; retn 4
    //
    // main.cpp finds the same function with a shorter signature for its own
    // per-model override; this one is spelled out in full so a build where the
    // short form drifts onto something else is caught here.
    const char *kSetAnimGroupSig =
        "8B 41 3C 8B 54 24 04 3B D0 89 51 3C 74 15 83 F8 FF 74 10 F3 0F 10 05 ? ? ? ? "
        "89 41 40 F3 0F 11 41 44 C2 04 00";

    // CPedMoveBlend::setDefaultAnimGroup - the source of two offsets:
    //   mov eax,[ecx+24h]        <- CPedMoveBlendBase::m_pPed
    //   mov edx,[eax+0BA4h]      <- CPed::m_nDefaultAnimGroup
    //   mov [ecx+3Ch],edx ; mov [ecx+40h],-1 ; ret
    const char *kDefaultGroupSig =
        "8B 41 24 8B 90 ? ? ? ? 89 51 3C C7 41 40 FF FF FF FF C3";
    constexpr int kPedOnBlendOperand  = 2;    // disp8
    constexpr int kDefaultGrpOperand  = 5;    // disp32
    constexpr int kMoveGrpOperand     = 11;   // disp8 - the move blend's group field

    // The two `push 55 ; call setMoveAnimGroup` sites inside
    // CPed::chooseMoveAnimGroup - the ducked-with-a-rifle path. main.cpp
    // already redirects the standing ones (50 / 51 / 56); these are the two it
    // does not, and without them a crouching player keeps the rifle crouch set.
    //
    // esi holds the CPed at every call site in that function, which is what
    // makes a call-site hook workable at all.
    const char *kCrouchSiteASig = "74 11 8B 8E ? ? ? ? 6A 37 E8 ? ? ? ?";
    constexpr int kCrouchSiteACall = 11;
    const char *kCrouchSiteBSig = "C1 E8 06 A8 01 75 1A 6A 37 E8 ? ? ? ?";
    constexpr int kCrouchSiteBCall = 9;
    // ... and the ducked-with-a-rocket-launcher one, for the RPG half.
    const char *kCrouchRpgSiteSig = "83 C4 04 84 C0 74 29 6A 39 E8 ? ? ? ?";
    constexpr int kCrouchRpgCall = 9;

    // chooseUpperCombatAnim(ped, &group, &anim) - quoted in full at the top.
    const char *kChooseAnimSig =
        "57 8B 7C 24 08 0F BF 47 2E 3B 05 ? ? ? ? 75 04 32 C0 5F C3 56 8D 8F B0 02 00 00 "
        "E8 ? ? ? ? 8B F0";

    // CAnimBlender::playAnim(group, anim, blend, fallbackGroup) - __thiscall on
    // the ped's blender (ped+0x78). Three functions in this cluster share a
    // prologue, so the signature runs on into the body to stay unique.
    const char *kPlayAnimSig =
        "83 EC 0C 53 8B 5C 24 18 55 56 57 8B 7C 24 20 53 57 8B E9 E8 ? ? ? ? 8B F0 "
        "83 C4 08 85 F6 75 19 8B 7C 24 2C 83 FF FF 74 50";

    // The anim-group streaming request the task uses:
    //   requestAnimGroup(state, group) -> true once the dictionary is resident.
    // `state` is a 12-byte block: +4 resource index, +8 group id (int16),
    // +0xA flags (bit 0 = we hold a reference).
    const char *kAnimReqSig =
        "56 8B F1 0F BF 46 08 57 8B 7C 24 0C 3B F8 74 3C F6 46 0A 01 74 11 8B 4E 04 51 "
        "E8 ? ? ? ? 83 C4 04 66 83 66 0A FE";

    // CPed::updateMovement's call to CPed::chooseMoveAnimGroup - the per-frame,
    // per-ped, GAME-THREAD hook the partial animation runs on:
    //   jz .. ; push 1 ; call .. ; mov ecx,esi ; call chooseMoveAnimGroup
    //   mov ecx,[esi+0A90h] ; mov eax,[ecx] ; mov edx,[eax+4] ; call edx
    //
    // Starting an animation means allocating an association and linking it into
    // the ped's blender. Doing that from a worker thread races the game's own
    // animation update, so it is done here instead, in the same phase of the
    // frame the engine's own task would have used.
    const char *kPedUpdateSig =
        "74 07 6A 01 E8 ? ? ? ? 8B CE E8 ? ? ? ? 8B 8E 90 0A 00 00 8B 01 8B 50 04 FF D2";
    constexpr int kPedUpdateCall = 11;
    constexpr int kMoveBlendOperand = 18;   // disp32 of mov ecx,[esi+<m_pMoveBlend>]

    // CAnimPlayer::setBlend(float delta) - __thiscall on an association.
    // Positive blends in towards weight 1, NEGATIVE blends out to 0 and the
    // association is dropped. This is how the engine itself retires an
    // animation that a new one is displacing (sub_9D8340 does exactly that).
    const char *kSetBlendSig =
        "F3 0F 10 4C 24 04 0F 57 C0 0F 2F C8 76 35 F3 0F 10 05 ? ? ? ? 0F 2F 41 58 77 0F "
        "E8 ? ? ? ? D9 44 24 04 DF F1 DD D8 76 60";

    // CPedWeapons::getCurrentSlot - __thiscall on ped+0x2B0; +0x18 is the weapon type.
    const char *kWeaponSlotSig =
        "8B 41 2C 85 C0 74 1E 8B 80 5C 02 00 00 85 C0 74 20 8B 51 18 83 C2 05 56 8B 70 18 "
        "8D 14 52 3B 34 91 5E 75 0D C3";

    // getWeaponByType(type) -> CWeaponInfo*, stride 0x110:
    //   mov eax,[esp+4] ; cmp eax,3Ch ; jge .. ; imul eax,110h ; add eax,<table> ; ret
    const char *kWeaponInfoSig =
        "8B 44 24 04 83 F8 3C 7D 0C 69 C0 10 01 00 00 05 ? ? ? ? C3 B8 ? ? ? ? C3";

    // CAnimAssociations::getAnimGroupIndexByName(name) -> index, or -1.
    // Walks ms_animGroups comparing szAnimGroupName (group+0, stride 88).
    const char *kGroupByNameSig =
        "55 57 33 FF 83 CD FF 39 3D ? ? ? ? 7E 3D 53 8B 5C 24 10 56 33 F6 A1 ? ? ? ? 03 C6 "
        "50 53 E8 ? ? ? ? 83 C4 08 85 C0 74 17";

    // CAnimAssociations::getAnimGroupByIndex - for the movement set's own name
    // table, so "is the player jogging" can be read off the animation that is
    // actually playing:
    //   mov eax,[esp+4] ; imul eax,eax,88 ; add eax,[ms_animGroups] ; retn 4
    const char *kAnimGroupsSig = "8B 44 24 04 6B C0 58 03 05 ? ? ? ? C2 04 00";
    constexpr int kAnimGroupsOperand = 9;

    // CAnimAssociations__AnimData, 88 bytes - the fields defineGroup writes.
    constexpr uint32_t kGroupStride    = 88;
    constexpr uint32_t kGroupCount     = 0x38;   // dwAnimCount
    constexpr uint32_t kGroupNames     = 0x3C;   // ppszNames
    constexpr uint32_t kGroupAnimData  = 0x44;   // pAnimData, {animId, flags, type}
    constexpr uint32_t kAnimDataStride = 12;

    // CPlayer::getPlayerPed - the same signature coveranim.cpp uses.
    const char *kPlayerPedSig =
        "8B 44 24 04 85 C0 75 15 A1 ? ? ? ? 83 F8 FF 74 12 8B 04 85 ? ? ? ? 85 C0 74 07 "
        "8B 80 ? ? 00 00 C3";
    constexpr int kLocalPlayerOperand = 9;
    constexpr int kPlayersOperand     = 21;
    constexpr int kPedOnPlayerOperand = 31;

    // ---- ped / blender offsets ------------------------------------------
    constexpr uint32_t kPedBlender    = 0x78;    // CPed -> animation blender
    constexpr uint32_t kPedWeapons    = 0x2B0;   // CPed::m_weapons
    constexpr uint32_t kSlotWeaponType = 0x18;   // CWeaponSlot -> weapon type
    constexpr uint32_t kWeaponFlags   = 0x20;    // CWeaponInfo -> flags

    // WeaponInfo.xml flags, CAN_AIM = bit 0.
    constexpr uint32_t kFlagHeavy     = 0x80;      // HEAVY
    constexpr uint32_t kFlagHeavyRifle = 0x400000; // HEAVY_WEAPON_USES_RIFLE_ANIMS

    // Blender association walk. The first three were verified byte-identical on
    // 1.0.8.0 and EFLC 1.1.2.0 for coveranim.cpp; the group at +0x10 comes from
    // CAnimPlayer's initialiser (EFLC 0xA7B7E0), which writes
    //   this[3] = animId    -> assoc+0x0C
    //   this[4] = groupId   -> assoc+0x10
    // and is what makes it possible to ask what SET a playing animation is from.
    constexpr uint32_t kBlendFirstNode = 0x1A28;
    constexpr uint32_t kNodeLive       = 0x48;
    constexpr uint32_t kNodeNext       = 0x8C;
    constexpr uint32_t kAssocAnimPtr   = 0x40;   // crAnimation*, null = not playing
    constexpr uint32_t kAssocAnimId    = 0x0C;
    constexpr uint32_t kAssocGroup     = 0x10;
    constexpr uint32_t kAssocWeight    = 0x34;   // current blend weight
    constexpr uint32_t kAssocBlendBits = 0x46;   // word; 0x20 = a blend is running
    constexpr uint32_t kAssocBlendTo   = 0x5C;   // the weight that blend is heading for
    constexpr uint16_t kBlending       = 0x20;

    // An association that is on its way out. CAnimPlayer::setBlend with a
    // negative delta parks a 0.0 target here and sets the blending bit; the
    // association stays in the list, at a shrinking weight, until it lands.
    //
    // Treating one of those as "the pose is already up" is what made the first
    // build stutter: the pose would fade to nothing while this code sat back
    // and watched, then snap in again once the association was finally
    // collected. It has to read as absent so the pose is re-asserted, which
    // reverses the fade smoothly - sub_9D8340 reuses the association and blends
    // it straight back in rather than building a second one.
    bool IsFadingOut(uint8_t *assoc)
    {
        return (*reinterpret_cast<uint16_t *>(assoc + kAssocBlendBits) & kBlending) != 0 &&
               *reinterpret_cast<float *>(assoc + kAssocBlendTo) <= 0.0f;
    }

    // ---- animation CHANNELS ---------------------------------------------
    //
    // Every animation carries a `type` alongside its id and flags, and the type
    // is a CHANNEL with exclusive occupancy: sub_9D8340 blends out any playing
    // association that has the same type as the one being started. Reading the
    // registration table straight out of the executable:
    //
    //   type 0   move_m@generic, move_f@generic, move_player, move_rifle,
    //            move_combat_strafe, move_crouch, move_melee, swim, ... - all
    //            65 animations of every movement set, and nothing else.
    //   type 3   jump_std, jump_rifle, climb, get_up, cellphone, melee, cover,
    //            damage_ko, arrest, busted, pickup_object, the veh@ sets,
    //            gun@rifle (aim, fire, reload, holster) - and GUN@COPS.
    //
    // So the engine has already answered both questions this feature needs to
    // ask, and there is no list of animation sets to maintain:
    //
    //   "which moveset is the player on?"  -> the group of the live type 0
    //                                         association
    //   "is the player busy doing something else?"
    //                                      -> some OTHER type 3 association is
    //                                         playing
    //
    // The second one is not just a convenience, it is the bug fix. The pose is
    // type 3, so starting it BLENDS OUT whatever else held that channel - the
    // weapon's own aim/fire/reload, a jump, a holster - and the game then
    // restarts that animation, which blends out the pose, every frame. That
    // fight is what made the first build stutter.
    constexpr int kTypeMoveset = 0;
    constexpr int kTypeAction  = 3;
    constexpr uint32_t kAssocType = 0x08;

    // The movesets that count as walking around: the ped's own walkstyle, the
    // stock on-foot sets, and the crouch pair when crouching is included.
    // Aiming (move_combat_strafe), melee, swimming, RPG and injured are all
    // separate movement groups, so they fall out here without being named.
    bool IsLocomotionGroup(int g, int defaultGroup);

    // ---- resolved at init ------------------------------------------------

    int      *gLocalPlayer  = nullptr;
    uint8_t **gPlayers      = nullptr;
    uint32_t  gPedOnPlayer  = 0;
    uint32_t  gPedOnBlend   = 0;
    uint32_t  gDefaultGroup = 0;
    uint32_t  gMoveGroupOnBlend = 0;   // CPedMoveBlendBase::m_nMoveBlendAnimGroup
    uint32_t  gMoveBlendOnPed  = 0;    // CPed::m_pMoveBlend

    void *gSetAnimGroup = nullptr;
    void *gChooseMoveGroup = nullptr;
    uint8_t **gAnimGroups = nullptr;   // &ms_animGroups.pData

    // True while the launcher pose is actually up. The walkstyle is only taken
    // off move_rpg once it is - otherwise a launcher whose pose cannot play
    // leaves the player carrying it with no carry animation at all, which is
    // worse than vanilla.
    bool gRpgPoseUp = false;

    using ChooseAnimFn = int(__cdecl *)(void *ped, int *group, int *anim);
    using PlayAnimFn   = void *(__fastcall *)(void *blender, void *edx, int group, int anim,
                                              float blend, int fallbackGroup);
    using AnimReqFn    = char(__fastcall *)(void *state, void *edx, int group);
    using SetBlendFn   = void(__fastcall *)(void *assoc, void *edx, float delta);
    using WeaponSlotFn = void *(__fastcall *)(void *weapons, void *edx);
    using WeaponInfoFn = uint8_t *(__cdecl *)(int weaponType);
    using GroupByNameFn = int(__fastcall *)(void *ecx, void *edx, const char *name);

    ChooseAnimFn gChooseAnim = nullptr;
    PlayAnimFn   gPlayAnim   = nullptr;
    AnimReqFn    gAnimReq    = nullptr;
    SetBlendFn   gSetBlend   = nullptr;
    WeaponSlotFn gWeaponSlot = nullptr;
    WeaponInfoFn gWeaponInfo = nullptr;
    GroupByNameFn gGroupByName = nullptr;

    // The task keeps one of these per instance; one shared block is enough for
    // a single ped, and it holds the streaming reference for as long as the
    // player is armed.
    uint8_t gStream[12]{};
    bool    gStreamHeld = false;   // gun@cops requested, and to be given back

    bool  gKeepWalkstyle    = false;
    bool  gPartial          = false;
    bool  gOnlyWhileMoving  = true;
    bool  gStopWhenBusy     = true;
    bool  gIncludeCrouch    = true;
    bool  gOneHanded        = true;   // pistols and SMGs get PISTOL_PARTIAL_A/B
    bool  gRpg              = true;   // rocket launchers pose from move_rpg
    bool  gActive           = true;   // the live on/off state the hotkey drives
    int   gToggleKey        = 0;      // 0 = no hotkey
    int   gPistolPose       = kAnimPistolB;   // standing or walking; -1 = engine's coin flip
    int   gPistolPoseJog    = kAnimPistolA;   // jogging
    int   gPistolPoseSprint = kAnimPistolA;   // sprinting
    int   gStartDelayMs     = 80;     // gate must hold open this long before starting
    int   gRetryDelayMs     = 250;    // ... and this long between starts
    float gBlend            = 4.0f;
    bool  gTrace            = false;

    // ---- helpers ---------------------------------------------------------

    uint8_t *PlayerPed()
    {
        if (!gLocalPlayer || !gPlayers || *gLocalPlayer < 0)
            return nullptr;
        uint8_t *player = gPlayers[*gLocalPlayer];
        return player ? *reinterpret_cast<uint8_t **>(player + gPedOnPlayer) : nullptr;
    }

    // The player's pace, read off the movement animation that is playing.
    //
    // Every movement group in the game - move_player, move_rifle, move_cop, the
    // lot - shares ONE 65-entry name table and ONE animation-id table, so the
    // ids mean the same thing whatever walkstyle the ped is on. The three sets
    // are built by reading that table and taking the names, rather than by
    // pinning a range of ids, so a custom walkstyle is classified too:
    //
    //   Idle, Turn_360_*, WStart*, Walk*, WStop_*, Shuffle_Stop, Walk_Up/Down
    //   RunStart_*, Run*, RStop_*, Run_Up/Down                     -> jogging
    //   Sprint*, SStop_*                                           -> sprinting
    enum Gait { kWalking, kJogging, kSprinting };

    std::vector<int> gJogAnims;
    std::vector<int> gSprintAnims;
    bool gGaitsReady = false;

    void BuildGaitSets(int moveGroup)
    {
        if (gGaitsReady || !gAnimGroups || !*gAnimGroups || moveGroup < 0)
            return;

        uint8_t *group = *gAnimGroups + kGroupStride * moveGroup;
        const int count = *reinterpret_cast<int *>(group + kGroupCount);
        const char **names = *reinterpret_cast<const char ***>(group + kGroupNames);
        uint8_t *data = *reinterpret_cast<uint8_t **>(group + kGroupAnimData);
        if (count <= 0 || count > 256 || !names || !data)
            return;

        for (int i = 0; i < count; i++)
        {
            const char *n = names[i];
            if (!n)
                continue;
            const int id = *reinterpret_cast<int *>(data + kAnimDataStride * i);

            // Sprint first: "SStop" would otherwise never be reached, and
            // nothing in the walking set starts with either prefix.
            if (_strnicmp(n, "Sprint", 6) == 0 || _strnicmp(n, "SStop", 5) == 0)
                gSprintAnims.push_back(id);
            else if (_strnicmp(n, "Run", 3) == 0 || _strnicmp(n, "RStop", 5) == 0)
                gJogAnims.push_back(id);
        }
        gGaitsReady = true;

        if (gTrace)
            TACE_TRACE("[copanims] of %d movement animations, %d jog and %d sprint",
                       count, static_cast<int>(gJogAnims.size()),
                       static_cast<int>(gSprintAnims.size()));
    }

    // Would the engine put this ped on move_rpg? Its own test, both flags:
    // HEAVY and not HEAVY_WEAPON_USES_RIFLE_ANIMS.
    //
    // Asked of the WEAPON rather than watching for the engine to request
    // move_rpg, because that request never comes once the walkstyle is kept.
    // CPed::chooseMoveAnimGroup only takes its move_rpg branch if move_rpg is
    // ALREADY streamed in, and the thing that streams it is the move blend
    // being put on it - so keeping the walkstyle stopped it ever loading, the
    // engine fell back to move_rifle every frame, and the launcher branch was
    // never reached. This asks the question directly and then holds the
    // dictionary resident itself.
    bool WantsRpgPose(uint8_t *ped)
    {
        if (!gWeaponSlot || !gWeaponInfo)
            return false;
        void *slot = gWeaponSlot(ped + kPedWeapons, nullptr);
        if (!slot)
            return false;
        const int type = *reinterpret_cast<int *>(static_cast<uint8_t *>(slot) + kSlotWeaponType);
        uint8_t *info = gWeaponInfo(type);
        if (!info)
            return false;
        const uint32_t f = *reinterpret_cast<uint32_t *>(info + kWeaponFlags);
        return (f & kFlagHeavy) != 0 && (f & kFlagHeavyRifle) == 0;
    }

    // A pose named in the ini: "SWAT_RIFLE" for one out of gun@cops, or
    // "SET:NAME" for one out of any other animation set - "move_rpg:Idle",
    // or whatever a custom set adds. Resolved once the groups are registered,
    // which is well after this .asi loads.
    struct PoseRef
    {
        std::string text;
        int  group = -1;
        int  anim  = -1;
        int  type  = kTypeAction;
        bool tried = false;
        bool ok    = false;
    };

    // Find an animation by name inside a group, returning its id and channel.
    bool FindAnimInGroup(int groupIndex, const char *name, int *animId, int *animType)
    {
        if (!gAnimGroups || !*gAnimGroups || groupIndex < 0)
            return false;

        uint8_t *group = *gAnimGroups + kGroupStride * groupIndex;
        const int count = *reinterpret_cast<int *>(group + kGroupCount);
        const char **names = *reinterpret_cast<const char ***>(group + kGroupNames);
        uint8_t *data = *reinterpret_cast<uint8_t **>(group + kGroupAnimData);
        if (count <= 0 || count > 256 || !names || !data)
            return false;

        for (int i = 0; i < count; i++)
        {
            if (names[i] && _stricmp(names[i], name) == 0)
            {
                *animId   = *reinterpret_cast<int *>(data + kAnimDataStride * i);
                *animType = *reinterpret_cast<int *>(data + kAnimDataStride * i + 8);
                return true;
            }
        }
        return false;
    }

    void ListGroup(int groupIndex)
    {
        if (!gAnimGroups || !*gAnimGroups || groupIndex < 0)
            return;
        uint8_t *group = *gAnimGroups + kGroupStride * groupIndex;
        const int count = *reinterpret_cast<int *>(group + kGroupCount);
        const char **names = *reinterpret_cast<const char ***>(group + kGroupNames);
        if (count <= 0 || count > 256 || !names)
            return;
        for (int i = 0; i < count; i++)
            if (names[i])
                TACE_WARN("[copanims]     %s", names[i]);
    }

    void Resolve(PoseRef &r)
    {
        if (r.tried || r.text.empty() || !gAnimGroups || !*gAnimGroups)
            return;
        r.tried = true;

        std::string set, anim = r.text;
        const size_t colon = r.text.find(':');
        if (colon != std::string::npos)
        {
            set  = r.text.substr(0, colon);
            anim = r.text.substr(colon + 1);
        }

        int groupIndex = kGroupGunCops;
        if (!set.empty())
        {
            if (!gGroupByName)
            {
                TACE_WARN("[copanims] %s: no way to look up animation set \"%s\"",
                          r.text.c_str(), set.c_str());
                return;
            }
            groupIndex = gGroupByName(nullptr, nullptr, set.c_str());
            if (groupIndex < 0)
            {
                TACE_WARN("[copanims] %s: no animation set called \"%s\"",
                          r.text.c_str(), set.c_str());
                return;
            }
        }

        if (!FindAnimInGroup(groupIndex, anim.c_str(), &r.anim, &r.type))
        {
            TACE_WARN("[copanims] %s: set 0x%02X has no animation called \"%s\". It has:",
                      r.text.c_str(), groupIndex, anim.c_str());
            ListGroup(groupIndex);
            return;
        }

        r.group = groupIndex;
        r.ok    = true;
        TACE_INFO("[copanims] launcher pose: %s = set 0x%02X animation %d, channel %d%s",
                  r.text.c_str(), r.group, r.anim, r.type,
                  r.type == kTypeAction ? "" : " (moved to the pose channel)");
    }

    PoseRef gRpgPose;

    // Play a pose, putting it on the action channel whatever the data says.
    //
    // Animations out of a MOVEMENT set are on channel 0, so playing one as-is
    // would blend out the walk and the two would fight. The channel comes from
    // the group's pAnimData, which every movement group SHARES, so it cannot be
    // edited in place. Instead: keep a private copy of that table with this one
    // animation moved to the action channel, point the group at it for the
    // length of the play call, and put the real one back. Nothing else runs in
    // between - this is the game thread - so the swap is unobservable.
    //
    // A pose already on the action channel (anything from gun@cops) needs none
    // of that and is played directly.
    std::vector<uint8_t> gPatchedData;
    int gPatchedFor = -1;

    void *PlayPose(uint8_t *blender, const PoseRef &r)
    {
        if (r.type == kTypeAction)
            return gPlayAnim(blender, nullptr, r.group, r.anim, gBlend, -1);

        uint8_t *group = *gAnimGroups + kGroupStride * r.group;
        const int count = *reinterpret_cast<int *>(group + kGroupCount);
        uint8_t **slot = reinterpret_cast<uint8_t **>(group + kGroupAnimData);
        uint8_t *real = *slot;
        if (count <= 0 || count > 256 || !real)
            return nullptr;

        if (gPatchedFor != r.anim)
        {
            gPatchedData.assign(real, real + kAnimDataStride * count);
            for (int i = 0; i < count; i++)
            {
                uint8_t *e = gPatchedData.data() + kAnimDataStride * i;
                if (*reinterpret_cast<int *>(e) == r.anim)
                    *reinterpret_cast<int *>(e + 8) = kTypeAction;
            }
            gPatchedFor = r.anim;
        }

        *slot = gPatchedData.data();
        void *assoc = gPlayAnim(blender, nullptr, r.group, r.anim, gBlend, -1);
        *slot = real;
        return assoc;
    }

    Gait GaitOf(int animId)
    {
        for (int id : gSprintAnims)
            if (id == animId)
                return kSprinting;
        for (int id : gJogAnims)
            if (id == animId)
                return kJogging;
        return kWalking;
    }

    // A key name from the ini as a virtual-key code. Accepts a single letter or
    // digit, F1-F24, a few named keys, or a raw code as 0x# or decimal. Blank or
    // unrecognised gives 0 - no hotkey.
    int ParseKey(const std::string &name)
    {
        if (name.empty())
            return 0;

        if (name.size() == 1)
        {
            const char c = static_cast<char>(toupper(static_cast<unsigned char>(name[0])));
            if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
                return c;                       // VK codes match ASCII for these
        }

        std::string up;
        for (char c : name)
            up += static_cast<char>(toupper(static_cast<unsigned char>(c)));

        if (up.size() >= 2 && up[0] == 'F')
        {
            const int n = atoi(up.c_str() + 1);
            if (n >= 1 && n <= 24)
                return VK_F1 + (n - 1);
        }

        static const struct { const char *name; int vk; } kNamed[] = {
            { "INSERT", VK_INSERT }, { "DELETE", VK_DELETE }, { "HOME", VK_HOME },
            { "END", VK_END }, { "PAGEUP", VK_PRIOR }, { "PGUP", VK_PRIOR },
            { "PAGEDOWN", VK_NEXT }, { "PGDN", VK_NEXT }, { "TAB", VK_TAB },
            { "SPACE", VK_SPACE }, { "BACKSPACE", VK_BACK },
            { "NUMPAD0", VK_NUMPAD0 }, { "NUMPAD1", VK_NUMPAD1 }, { "NUMPAD2", VK_NUMPAD2 },
            { "NUMPAD3", VK_NUMPAD3 }, { "NUMPAD4", VK_NUMPAD4 }, { "NUMPAD5", VK_NUMPAD5 },
            { "NUMPAD6", VK_NUMPAD6 }, { "NUMPAD7", VK_NUMPAD7 }, { "NUMPAD8", VK_NUMPAD8 },
            { "NUMPAD9", VK_NUMPAD9 },
        };
        for (const auto &k : kNamed)
            if (up == k.name)
                return k.vk;

        const int raw = static_cast<int>(strtol(name.c_str(), nullptr, 0));
        return (raw > 0 && raw < 256) ? raw : 0;
    }

    // "A" / "B" / anything else ("vanilla") - leave the engine's coin flip alone.
    int ReadPose(const char *key, const char *def)
    {
        const std::string v = TaceIniString("COPANIMS", key, def);
        const std::string pick = v.empty() ? std::string(def) : v;
        if (pick == "A" || pick == "a")
            return kAnimPistolA;
        if (pick == "B" || pick == "b")
            return kAnimPistolB;
        return -1;
    }

    const char *GaitName(Gait g)
    {
        return g == kSprinting ? "sprinting" : g == kJogging ? "jogging" : "idle/walking";
    }

    bool IsLocomotionGroup(int g, int defaultGroup)
    {
        if (g < 0)
            return false;
        if (g == defaultGroup)
            return true;
        if (g >= kMoveGenericM && g <= kMoveFArmed)     // 0x2F..0x33
            return true;
        // move_rpg is a full movement set like the rest - the same 65 walk, run
        // and sprint animations, in the launcher's flavour. It has to count, or
        // the launcher pose can never start: the walkstyle is not taken off
        // move_rpg until the pose is up, and the pose will not start unless the
        // ped is on a movement set. Each was waiting for the other.
        if (g == kMoveRpg)
            return true;
        // move_crouch_trans[_armed] are idle2crouchidle / crouchidle2idle - the
        // transitions into and out of a crouch. They read as their own movement
        // set for the second or so they run, and dropping the pose across them
        // just makes the ducking look broken, so they count as moving.
        return gIncludeCrouch &&
               (g == kMoveCrouch || g == kMoveCrouchRifle || g == kMoveCrouchRpg ||
                g == kMoveCrouchTrans || g == kMoveCrouchTransA);
    }

    struct Playing
    {
        int      moveset   = -1;     // group of the live moveset (type 0)
        int      moveAnim  = -1;     // ... and which animation of it, by weight
        bool     busy      = false;  // another type 3 animation owns that channel
        int      busyGroup = -1;     // ... and which set it came from
        uint8_t *ours      = nullptr;// our GUN@COPS association, if it is really up
        int      oursAnim  = -1;
    };

    // One walk of the ped's association list. Each entry says which GROUP it
    // came from (+0x10) and which CHANNEL it occupies (+0x08), so the two
    // questions - what moveset, and is anything else animating - are answered
    // by reading the engine's own bookkeeping. Associations on their way out
    // are skipped: they are still in the list at a falling weight, and counting
    // them is what made the pose stutter.
    Playing ScanBlender(uint8_t *ped, int ourGroup)
    {
        Playing p;
        float topWeight = -1.0f;

        uint8_t *blender = *reinterpret_cast<uint8_t **>(ped + kPedBlender);
        if (!blender)
            return p;

        uint8_t *node = *reinterpret_cast<uint8_t **>(blender + kBlendFirstNode);
        for (int guard = 0; node && guard < 256; guard++)
        {
            uint8_t *assoc = node + 4;
            if (*reinterpret_cast<uint16_t *>(node + kNodeLive) == 1 &&
                *reinterpret_cast<uint32_t *>(assoc + kAssocAnimPtr) != 0 &&
                !IsFadingOut(assoc))
            {
                const int g = *reinterpret_cast<int *>(assoc + kAssocGroup);
                const int t = *reinterpret_cast<int *>(assoc + kAssocType);

                // Ours is identified by group AND channel: the RPG pose comes
                // from a movement set, and only the copy this code started sits
                // on the action channel.
                if (g == ourGroup && t == kTypeAction)
                {
                    p.ours     = assoc;
                    p.oursAnim = *reinterpret_cast<int *>(assoc + kAssocAnimId);
                }
                else if (t == kTypeMoveset)
                {
                    // Several locomotion animations blend at once through a
                    // change of pace, so take the one carrying the most weight
                    // - that is the gait the player reads as being in.
                    const float w = *reinterpret_cast<float *>(assoc + kAssocWeight);
                    if (w > topWeight)
                    {
                        topWeight   = w;
                        p.moveset   = g;
                        p.moveAnim  = *reinterpret_cast<int *>(assoc + kAssocAnimId);
                    }
                }
                else if (t == kTypeAction)
                {
                    p.busy = true;
                    if (p.busyGroup < 0)
                        p.busyGroup = g;
                }
            }
            node = *reinterpret_cast<uint8_t **>(node + kNodeNext);
        }
        return p;
    }

    // Every group with something playing, for working out why a gate is closed.
    void TracePlaying(uint8_t *ped)
    {
        uint8_t *blender = *reinterpret_cast<uint8_t **>(ped + kPedBlender);
        if (!blender)
            return;
        uint8_t *node = *reinterpret_cast<uint8_t **>(blender + kBlendFirstNode);
        for (int guard = 0; node && guard < 256; guard++)
        {
            uint8_t *assoc = node + 4;
            if (*reinterpret_cast<uint16_t *>(node + kNodeLive) == 1 &&
                *reinterpret_cast<uint32_t *>(assoc + kAssocAnimPtr) != 0)
                TACE_TRACE("[copanims]     group 0x%02X type %d anim %d weight %.2f%s",
                           *reinterpret_cast<int *>(assoc + kAssocGroup),
                           *reinterpret_cast<int *>(assoc + kAssocType),
                           *reinterpret_cast<int *>(assoc + kAssocAnimId),
                           *reinterpret_cast<float *>(assoc + kAssocWeight),
                           IsFadingOut(assoc) ? " (fading out)" : "");
            node = *reinterpret_cast<uint8_t **>(node + kNodeNext);
        }
    }

    // Give back the streaming reference on gun@cops. Passing -1 is how the task
    // itself releases it.
    void ReleaseGroup()
    {
        if (gAnimReq && gStreamHeld)
        {
            gAnimReq(gStream, nullptr, -1);
            gStreamHeld = false;
        }
    }

    // Runs once per ped per frame, on the game thread, right after the engine
    // has chosen that ped's movement group. Everything but the player leaves
    // immediately.
    //
    // This is CTaskSimplePlayUpperCombatAnim reduced to what it actually does:
    // ask the chooser, keep the dictionary streamed, and start the animation
    // again whenever it is not playing - the task's own state 2 -> 3 -> 1 loop.
    // Blend our pose out. Negative is how the engine retires an animation it is
    // displacing - it fades to weight 0 and the association is dropped - as
    // opposed to winding it to the end, which a looping animation ignores.
    void CancelPose(Playing &p)
    {
        if (p.ours && gSetBlend)
        {
            gSetBlend(p.ours, nullptr, -gBlend);
            p.ours = nullptr;
        }
    }

    DWORD gOpenSince  = 0;
    DWORD gLastStart  = 0;
    bool  gHadPose    = false;
    bool  gKeyWasDown = false;

    void Tick(uint8_t *ped)
    {
        static bool reported = false;
        static const char *lastGate = nullptr;

        if (!ped || ped != PlayerPed())
            return;

        // Once per frame, now that this is known to be the player.
        if (gToggleKey)
        {
            const bool down = (GetAsyncKeyState(gToggleKey) & 0x8000) != 0;
            if (down && !gKeyWasDown)
            {
                gActive = !gActive;
                TACE_OK("[copanims] %s", gActive ? "on" : "off");
            }
            gKeyWasDown = down;
        }

        void *moveBlend = *reinterpret_cast<void **>(ped + gMoveBlendOnPed);
        const int moveGroup = moveBlend
            ? *reinterpret_cast<int *>(static_cast<uint8_t *>(moveBlend) + gMoveGroupOnBlend)
            : -1;

        int group = -1, anim = -1;
        bool wanted = gPartial && gActive &&
                      gChooseAnim(ped, &group, &anim) != 0 && group == kGroupGunCops;

        // Rocket launchers fall out of the chooser - they are in the HEAVY slot,
        // and gun@cops has no launcher pose. They get "Idle" from their own
        // movement set instead, which is the shouldered-launcher stance, layered
        // the same way over whatever walkstyle the ped has.
        bool rpg = false;
        if (!wanted && gPartial && gActive && gRpg && WantsRpgPose(ped))
        {
            Resolve(gRpgPose);
            if (gRpgPose.ok)
            {
                group  = gRpgPose.group;
                anim   = gRpgPose.anim;
                wanted = true;
                rpg    = true;
            }
        }

        Playing p = ScanBlender(ped, group);

        // If nothing on the moveset channel is playing, fall back to the group
        // the move blend is set to - the answer is the same, it just cannot go
        // stale between two locomotion animations.
        const int moveset = (p.moveset >= 0) ? p.moveset : moveGroup;
        const int defaultGroup = *reinterpret_cast<int *>(ped + gDefaultGroup);

        BuildGaitSets(moveset);
        const Gait gait = GaitOf(p.moveAnim);

        // Which of the two pistol poses. The engine flips a per-ped coin off the
        // entity's random seed and takes either for the ped's whole life, but
        // the two are not interchangeable in practice - PISTOL_PARTIAL_A judders
        // on its own at a stand or a walk, while reading correctly at pace. So
        // the pose follows the gait rather than the seed, and each pace is
        // configured on its own.
        if (wanted && !rpg && (anim == kAnimPistolA || anim == kAnimPistolB))
        {
            const int want = gait == kSprinting ? gPistolPoseSprint
                           : gait == kJogging   ? gPistolPoseJog
                                                : gPistolPose;
            if (want >= 0)
                anim = want;
        }

        // One-handed weapons can be left out: the two-handed pose is the one
        // most of the value is in, and this keeps the pistols out of the way
        // while their behaviour is still being worked out.
        const bool oneHanded = wanted && !rpg &&
                               anim != kAnimSwatRifle && anim != kAnimSwatCrouch;

        // Every reason to not be holding the pose right now.
        const char *gate = nullptr;
        if (!wanted)
            gate = "no cop pose for the weapon in hand";
        else if (oneHanded && !gOneHanded)
            gate = "one-handed weapon, and OneHanded is off";
        else if (gStopWhenBusy && p.busy)
            gate = "another animation owns the upper body";
        else if (gOnlyWhileMoving && !IsLocomotionGroup(moveset, defaultGroup))
            gate = "not on a walk/run/sprint moveset";

        const DWORD now = GetTickCount();

        if (gate)
        {
            // Something took the channel out from under a pose that was up.
            // Worth saying so by name: that is the animation to look at if the
            // pose is fighting for the body rather than simply standing down.
            if (gTrace && gHadPose && p.busy)
                TACE_TRACE("[copanims] pose displaced by group 0x%02X", p.busyGroup);

            if (p.ours || gStreamHeld)
            {
                CancelPose(p);
                ReleaseGroup();
            }
            gOpenSince = 0;
            gHadPose   = false;
            gRpgPoseUp = false;
            // Traced whether or not there was anything to cancel: a gate that
            // never opens is otherwise completely silent, and the listing below
            // is what says which group the player is actually animating from.
            if (gTrace && gate != lastGate)
            {
                TACE_TRACE("[copanims] pose off - %s (moveset 0x%02X)", gate, moveset);
                TracePlaying(ped);
            }
            lastGate = gate;
            return;
        }
        lastGate = nullptr;

        gStreamHeld = true;
        if (!gAnimReq(gStream, nullptr, group))
            return;             // gun@cops.wad still streaming in

        // Already up and right for the stance. The two pistol variants are the
        // same pose, so either one counts as correct - only a standing/ducked
        // change is worth swapping for, and that is left to the engine's own
        // same-channel displacement rather than being cancelled first.
        if (p.ours)
        {
            gHadPose   = true;
            gRpgPoseUp = rpg;
            // With a pose forced, an exact match is required so a pistol that
            // came up as the wrong variant is swapped out. Left on the engine's
            // coin flip the two are interchangeable, and swapping between them
            // would be churn for no visible difference.
            const bool oursOneHanded =
                p.oursAnim != kAnimSwatRifle && p.oursAnim != kAnimSwatCrouch;
            if (p.oursAnim == anim ||
                (gPistolPose < 0 && oneHanded && oursOneHanded))
                return;
        }

        // Debounce and rate-limit. If something else is contending for the
        // channel, backing off leaves the pose simply absent instead of
        // strobing on and off once a frame.
        if (gOpenSince == 0)
            gOpenSince = now;
        if (!p.ours && now - gOpenSince < static_cast<DWORD>(gStartDelayMs))
            return;
        if (now - gLastStart < static_cast<DWORD>(gRetryDelayMs))
            return;

        uint8_t *blender = *reinterpret_cast<uint8_t **>(ped + kPedBlender);
        if (!blender)
            return;

        if (rpg)
        {
            gRpgPoseUp = PlayPose(blender, gRpgPose) != nullptr;
            if (gTrace)
                TACE_TRACE("[copanims] launcher pose %s: %s", gRpgPose.text.c_str(),
                           gRpgPoseUp ? "started" : "FAILED - dictionary not ready?");
        }
        else
        {
            gPlayAnim(blender, nullptr, group, anim, gBlend, -1);
        }
        gLastStart = now;
        gHadPose   = true;

        if (!reported)
        {
            reported = true;
            TACE_OK("[copanims] player is using the cop weapon animations "
                    "(group 0x%02X, first pose id %d)", group, anim);
        }
        else if (gTrace)
        {
            TACE_TRACE("[copanims] pose on - id %d (moveset 0x%02X, move anim %d, %s)",
                       anim, moveset, p.moveAnim, GaitName(gait));
        }
    }

    // CPed::updateMovement's call to chooseMoveAnimGroup, wrapped. ecx is the
    // CPed on the way in; the original is __thiscall with no arguments and its
    // return value is discarded by the caller.
    __declspec(naked) void CopAnims_UpdateH()
    {
        __asm
        {
            push ecx
            call gChooseMoveGroup
            pop  ecx
            push ecx
            call Tick
            add  esp, 4
            ret
        }
    }

    // The crouch call sites. esi is the CPed, ecx the move blend, and the group
    // is the single stack argument - so the group is rewritten in place and the
    // real function tail-called, which keeps its `retn 4` correct.
    //
    // CopAnims_MoveGroup is __cdecl and may clobber ecx, which is the `this`
    // the real function needs, so it is saved across the call.
    __declspec(naked) void CopAnims_SetAnimGroupH()
    {
        __asm
        {
            push ecx
            mov  eax, [esp + 8]
            push eax
            push esi
            call CopAnims_MoveGroup
            add  esp, 8
            pop  ecx
            mov  [esp + 4], eax
            jmp  gSetAnimGroup
        }
    }
}

// The group the player should actually move with. Returning the group
// unchanged means "not mine" - main.cpp's hook then carries on to its own
// per-model rifle/rpg override, which is left alone.
extern "C" int __cdecl CopAnims_MoveGroup(void *ped, int group)
{
    if (!gActive || !ped || ped != PlayerPed())
        return group;

    if (!gKeepWalkstyle)
        return group;

    switch (group)
    {
    case kMoveRifle:
    case kMoveFArmed:
        // Whatever this ped would move with unarmed - move_player for Niko,
        // and the right thing for a custom or multiplayer model too.
        return *reinterpret_cast<int *>(static_cast<uint8_t *>(ped) + gDefaultGroup);
    case kMoveCrouchRifle:
        return kMoveCrouch;
    // Only once the launcher pose is actually up. Until then the vanilla
    // move_rpg walk stays, so a pose that cannot play degrades to vanilla
    // rather than to a launcher carried with no animation at all.
    case kMoveRpg:
        return (gRpg && gRpgPoseUp)
                   ? *reinterpret_cast<int *>(static_cast<uint8_t *>(ped) + gDefaultGroup)
                   : group;
    case kMoveCrouchRpg:
        return (gRpg && gRpgPoseUp) ? kMoveCrouch : group;
    default:
        return group;
    }
}

void CopAnims_Init()
{
    if (!TaceIniBool("COPANIMS", "Enabled", false))
        return;

    gTrace           = TaceTraceEnabled("copanims");
    gKeepWalkstyle   = TaceIniBool("COPANIMS", "KeepWalkstyle", true);
    gPartial         = TaceIniBool("COPANIMS", "Partial", true);
    gOnlyWhileMoving  = TaceIniBool("COPANIMS", "OnlyWhileMoving", true);
    gStopWhenBusy     = TaceIniBool("COPANIMS", "StopWhenBusy", true);
    gIncludeCrouch    = TaceIniBool("COPANIMS", "IncludeCrouch", true);
    gOneHanded        = TaceIniBool("COPANIMS", "OneHanded", true);
    gRpg              = TaceIniBool("COPANIMS", "Rpg", true);
    gRpgPose.text     = TaceIniString("COPANIMS", "RpgPose", "SWAT_RIFLE");
    gToggleKey        = ParseKey(TaceIniString("COPANIMS", "ToggleKey"));
    {
        gPistolPose = ReadPose("PistolPose", "B");

        // PistolPoseRunning covered jogging and sprinting together before they
        // were split, so it still stands as the default for both.
        const std::string both = TaceIniString("COPANIMS", "PistolPoseRunning", "A");
        gPistolPoseJog    = ReadPose("PistolPoseJogging",   both.c_str());
        gPistolPoseSprint = ReadPose("PistolPoseSprinting", both.c_str());
    }
    gStartDelayMs     = TaceIniInt("COPANIMS", "StartDelay", 80);
    gRetryDelayMs     = TaceIniInt("COPANIMS", "RetryDelay", 250);
    if (gStartDelayMs < 0)    gStartDelayMs = 0;
    if (gStartDelayMs > 2000) gStartDelayMs = 2000;
    if (gRetryDelayMs < 0)    gRetryDelayMs = 0;
    if (gRetryDelayMs > 5000) gRetryDelayMs = 5000;

    // Written in hundredths so the ini stays whole numbers, same as
    // [COVERANIM] CutAt.
    {
        int blend = TaceIniInt("COPANIMS", "Blend", 400);
        if (blend < 25)   blend = 25;
        if (blend > 2000) blend = 2000;
        gBlend = static_cast<float>(blend) / 100.0f;
    }

    hook::pattern pattern = find_pattern(kPlayerPedSig);
    if (pattern.empty())
    {
        TACE_WARN("[copanims] player ped accessor: signature not found - not applied");
        return;
    }
    gLocalPlayer = *pattern.get_first<int *>(kLocalPlayerOperand);
    gPlayers     = *pattern.get_first<uint8_t **>(kPlayersOperand);
    gPedOnPlayer = *pattern.get_first<uint32_t>(kPedOnPlayerOperand);

    pattern = find_pattern(kDefaultGroupSig);
    if (pattern.empty())
    {
        TACE_WARN("[copanims] CPedMoveBlend::setDefaultAnimGroup: signature not found - "
                  "not applied");
        return;
    }
    gPedOnBlend       = *pattern.get_first<uint8_t>(kPedOnBlendOperand);
    gDefaultGroup     = *pattern.get_first<uint32_t>(kDefaultGrpOperand);
    gMoveGroupOnBlend = *pattern.get_first<uint8_t>(kMoveGrpOperand);

    if (gTrace)
        TACE_TRACE("[copanims] ped+0x%X on the move blend, m_nDefaultAnimGroup at ped+0x%X",
                   gPedOnBlend, gDefaultGroup);

    if (gKeepWalkstyle)
    {
        pattern = find_pattern(kSetAnimGroupSig);
        if (pattern.empty())
        {
            TACE_WARN("[copanims] CPedMoveBlend::setMoveAnimGroup: signature not found - "
                      "the walkstyle will stay vanilla");
            gKeepWalkstyle = false;
        }
        else
        {
            gSetAnimGroup = pattern.get_first(0);

            // main.cpp already redirects the standing rifle / armed / rpg call
            // sites through its own hook, and that hook asks
            // CopAnims_MoveGroup first. Only the two ducked sites are left.
            int hooked = 0;
            pattern = find_pattern(kCrouchSiteASig);
            if (!pattern.empty())
            {
                injector::MakeCALL(pattern.get_first(kCrouchSiteACall), CopAnims_SetAnimGroupH);
                hooked++;
            }
            pattern = find_pattern(kCrouchSiteBSig);
            if (!pattern.empty())
            {
                injector::MakeCALL(pattern.get_first(kCrouchSiteBCall), CopAnims_SetAnimGroupH);
                hooked++;
            }
            // The ducked-with-a-launcher site, for the RPG half.
            pattern = find_pattern(kCrouchRpgSiteSig);
            if (!pattern.empty())
            {
                injector::MakeCALL(pattern.get_first(kCrouchRpgCall), CopAnims_SetAnimGroupH);
                hooked++;
            }
            if (hooked != 3)
                TACE_WARN("[copanims] %d of 3 ducked call site(s) found - crouching with a "
                          "rifle or launcher may keep the vanilla crouch walk", hooked);
        }
    }

    if (gPartial)
    {
        pattern = find_pattern(kChooseAnimSig);
        if (pattern.empty())
        {
            TACE_WARN("[copanims] chooseUpperCombatAnim: signature not found - "
                      "no partial animation");
            gPartial = false;
        }
        else
        {
            gChooseAnim = pattern.get_first<int(__cdecl)(void *, int *, int *)>(0);
        }
    }

    if (gPartial)
    {
        pattern = find_pattern(kPlayAnimSig);
        if (pattern.empty())
        {
            TACE_WARN("[copanims] CAnimBlender::playAnim: signature not found - "
                      "no partial animation");
            gPartial = false;
        }
        else
        {
            gPlayAnim = reinterpret_cast<PlayAnimFn>(pattern.get_first(0));
        }
    }

    if (gPartial)
    {
        pattern = find_pattern(kAnimReqSig);
        if (pattern.empty())
        {
            TACE_WARN("[copanims] anim group streaming request: signature not found - "
                      "no partial animation");
            gPartial = false;
        }
        else
        {
            gAnimReq = reinterpret_cast<AnimReqFn>(pattern.get_first(0));
        }
    }

    // Installed whenever the feature is on, not just for the pose: this is also
    // where the toggle key is read, and where a pose left up by a toggle-off
    // gets blended away.
    {
        pattern = find_pattern(kPedUpdateSig);
        if (pattern.empty())
        {
            TACE_WARN("[copanims] per-frame ped update: signature not found - "
                      "no partial animation and no toggle key");
            gPartial = false;
        }
        else
        {
            gMoveBlendOnPed = *pattern.get_first<uint32_t>(kMoveBlendOperand);
            gChooseMoveGroup =
                injector::MakeCALL(pattern.get_first(kPedUpdateCall), CopAnims_UpdateH).get();
        }
    }

    // The movement set's name table, for telling a jog from a walk.
    if (gPartial)
    {
        pattern = find_pattern(kAnimGroupsSig);
        if (pattern.empty())
            TACE_WARN("[copanims] anim group array: signature not found - the pistol pose will "
                      "not follow the player's pace");
        else
            gAnimGroups = *pattern.get_first<uint8_t **>(kAnimGroupsOperand);
    }

    // Weapon lookup, for spotting a launcher.
    if (gPartial && gRpg)
    {
        pattern = find_pattern(kWeaponSlotSig);
        if (!pattern.empty())
            gWeaponSlot = reinterpret_cast<WeaponSlotFn>(pattern.get_first(0));
        pattern = find_pattern(kWeaponInfoSig);
        if (!pattern.empty())
            gWeaponInfo = reinterpret_cast<WeaponInfoFn>(pattern.get_first(0));
        pattern = find_pattern(kGroupByNameSig);
        if (!pattern.empty())
            gGroupByName = reinterpret_cast<GroupByNameFn>(pattern.get_first(0));
        else
            TACE_WARN("[copanims] animation set lookup: signature not found - RpgPose can "
                      "only name an animation inside gun@cops");
        if (!gWeaponSlot || !gWeaponInfo)
        {
            TACE_WARN("[copanims] weapon info accessors: signature not found - "
                      "no launcher pose");
            gRpg = false;
        }
    }

    // Blending the pose back out again when a gate closes.
    if (gPartial)
    {
        pattern = find_pattern(kSetBlendSig);
        if (pattern.empty())
            TACE_WARN("[copanims] CAnimPlayer::setBlend: signature not found - the pose will "
                      "play out instead of being blended away");
        else
            gSetBlend = reinterpret_cast<SetBlendFn>(pattern.get_first(0));
    }

    if (!gKeepWalkstyle && !gPartial)
    {
        TACE_WARN("[copanims] enabled, but neither half could be applied");
        return;
    }

    TACE_INFO("[copanims] walkstyle kept: %s, partial gun animation: %s, rocket launchers: %s",
              gKeepWalkstyle ? "yes" : "no", gPartial ? "yes" : "no", gRpg ? "yes" : "no");
    if (gToggleKey)
        TACE_INFO("[copanims] toggle in game with %s",
                  TaceIniString("COPANIMS", "ToggleKey").c_str());
    if (gPartial)
        TACE_INFO("[copanims] pose held only while: on a moveset %s, nothing else "
                  "animating %s (crouch %s)",
                  gOnlyWhileMoving ? "yes" : "no", gStopWhenBusy ? "yes" : "no",
                  gIncludeCrouch ? "counts" : "excluded");
    if (gPartial && gOneHanded)
    {
        auto poseName = [](int a) {
            return a == kAnimPistolA ? "PISTOL_PARTIAL_A"
                 : a == kAnimPistolB ? "PISTOL_PARTIAL_B"
                                     : "whichever pose the engine picks";
        };
        TACE_INFO("[copanims] one-handed: %s standing or walking, %s jogging, %s sprinting",
                  poseName(gPistolPose), poseName(gPistolPoseJog), poseName(gPistolPoseSprint));
    }
}
