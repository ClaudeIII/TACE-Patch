#define _CRT_SECURE_NO_WARNINGS

#include <string>
#include <unordered_map>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "rage/Hash.h"
#include "Types.h"
#include "Log.h"
#include "CrashLog.h"

std::unordered_map<uint32_t, AnimationOverride> gAnimationOverrides;
namespace ModelIndices
{
    int32_t M_Y_Multiplayer = -1;
    int32_t M_Y_Multiplayer2 = -1;
    int32_t F_Y_Multiplayer = -1;
    int32_t F_Y_Multiplayer2 = -1;
};

int32_t *_dwCurrentEpisode = nullptr;

uint32_t GetAnimGroupIdForModel(uint32_t modelHash, eAnimGroup animGroup);
void NewAnimationOverride(const char *modelName, const char *rifleAnim, const char *rpgAnim);
void PainVoice_Init();
void PainVoice_OnInitMap();
void GangWeapons_Init();
void CopWeapons_Init();
void GateProfile_Init();
void CoverAnim_Init();
void CopAnims_Init();

// copanims.cpp - the group the player should actually move with. Returns its
// argument unchanged when the feature is off or the ped is not the player.
extern "C" int __cdecl CopAnims_MoveGroup(void *ped, int group);

//requests the animation to be loaded if it hasnt
bool (*CAnimMgr__HasAnimLoaded)(uint32_t animGroup) = nullptr;
uint32_t (__stdcall *CAnimMgr__GetDictionaryIdAtAnimGroup)(eAnimGroup animGroup) = nullptr;
uint32_t (__stdcall *CAnimMgr__GetAnimGroupIdByName)(const char *name) = nullptr;

uint32_t *CModelInfoStore__msModels = nullptr;
void *(*CModelInfoStore__GetModelByName)(const char *name, int32_t *index) = nullptr;

void (*CGame__InitMapO)() = nullptr;
void __declspec(naked) CGame__InitMapH()
{
    _asm
    {
        push ebp
        mov ebp, esp
        sub esp, __LOCAL_SIZE
        pushad

        call CGame__InitMapO
    }

    //example:
    //                     modelName     rifleAnim     rpgAnim
    if (*_dwCurrentEpisode == 2)
    {
        NewAnimationOverride("ig_niko", "move_rifle_niko", "move_rpg_niko");
        NewAnimationOverride("ig_johnnybiker", "move_rifle_johnny", "move_rpg_johnny");
    }
    else if (*_dwCurrentEpisode == 1)
    {
        NewAnimationOverride("ig_niko", "move_rifle_niko", "move_rpg_niko");
        NewAnimationOverride("ig_luis", "move_rifle_luis", "move_rpg_luis");
    }
    else
    {
        NewAnimationOverride("ig_johnnybiker", "move_rifle_johnny", "move_rpg_johnny");
        NewAnimationOverride("ig_luis", "move_rifle_luis", "move_rpg_luis");
    }

    CModelInfoStore__GetModelByName("M_Y_Multiplayer", &ModelIndices::M_Y_Multiplayer);
    CModelInfoStore__GetModelByName("M_Y_Multiplayer2", &ModelIndices::M_Y_Multiplayer2);
    CModelInfoStore__GetModelByName("F_Y_Multiplayer", &ModelIndices::F_Y_Multiplayer);
    CModelInfoStore__GetModelByName("F_Y_Multiplayer2", &ModelIndices::F_Y_Multiplayer2);

    PainVoice_OnInitMap();

    _asm
    {
        popad
        mov esp, ebp
        pop ebp
        ret
    }
}

bool __declspec(naked) IsPedFemale(uint32_t)
{
    _asm
    {
        //CEntity::mModelIndex
        movzx eax, word ptr[esi + 0x2E]

        //return (CPedModelInfo::field_120 & 2) == 0
        push edx

        mov edx, [CModelInfoStore__msModels]
        mov eax, [edx + eax * 4]
        mov eax, [eax + 0x120]
        and eax, 2

        pop edx

        jg yes

        mov eax, 1
        ret

        yes :
        xor eax, eax
            ret
    }
}

void *CPedMoveBlendOnFoot__SetAnimGroupO = nullptr;
void __declspec(naked) CPedMoveBlendOnFoot__SetAnimGroupH()
{
    _asm
    {
        // [COPANIMS] first refusal: the player keeps their own walkstyle
        // instead of move_rifle / move_f@armed. esi is the CPed at every call
        // site this hook is installed on. A group that comes back unchanged
        // means the feature is off, or this is not the player - carry on to
        // the per-model override below.
        //
        // CopAnims_MoveGroup is __cdecl and may clobber ecx, so the move blend
        // is reloaded rather than relied on.
        mov edx, [esp+4]
        push edx
        push esi
        call CopAnims_MoveGroup
        add esp, 8
        cmp eax, [esp+4]
        je NotPlayerWalkstyle

        push eax
        mov ecx, [esi+0xA90]
        call CPedMoveBlendOnFoot__SetAnimGroupO
        ret 4

        NotPlayerWalkstyle:
        mov edx, [esp+4]
        cmp edx, ANIMGRP_MOVE_RIFLE
        je IsRifleOrRpgAnim

        //cmp edx, ANIMGRP_MOVE_F_ARMED
        //je IsRifleOrRpgAnim

        cmp edx, ANIMGRP_MOVE_RPG
        je IsRifleOrRpgAnim
        
        push [esp+4]
        call CPedMoveBlendOnFoot__SetAnimGroupO
        ret 4

        IsRifleOrRpgAnim:
            //esi = CPed
            movzx ecx, word ptr [esi+0x2E]

            push edx
            mov edx, [CModelInfoStore__msModels]
            mov ecx, [edx+ecx*4]
            pop edx

            pushad
            //model hash
            push edx
            mov ecx, [ecx+0x3C]
            push ecx
            call GetAnimGroupIdForModel
            add esp, 8

            push eax
            mov ecx, [esi+0xA90]
            call CPedMoveBlendOnFoot__SetAnimGroupO
            popad

            ret 4
    }
}

bool __declspec(naked) IsModelMultiplayerPed()
{
    _asm
    {
        mov eax, [esp+4]
        test eax, eax
        jge ModelIndexIsValid

        xor al, al
        ret
        ModelIndexIsValid:
            cmp ModelIndices::M_Y_Multiplayer, eax
            jz Yes

            cmp ModelIndices::M_Y_Multiplayer2, eax
            jz Yes

            cmp ModelIndices::F_Y_Multiplayer, eax
            jz Yes

            cmp ModelIndices::F_Y_Multiplayer2, eax
            jz Yes

            xor eax, eax
            ret
        Yes:
            mov eax, 1
            ret
    }
}
void __declspec(naked) IsMultiplayerModelMale()
{
    _asm
    {
        cmp eax, ModelIndices::M_Y_Multiplayer
        jz Return
        cmp eax, ModelIndices::M_Y_Multiplayer2
        Return:
            ret
    }
}

void InitializeAllLimitAdjusters();

// ============================================================================
// Patch reporting.
//
// Everything below this point is a byte signature that may or may not match.
// Applied silently, a signature that drifted is indistinguishable from a
// feature that was never there: the game quietly behaves like vanilla, which is
// exactly what these patches exist to stop. Worse, hook::pattern's own
// diagnostics are assert()s, which are compiled out in Release - a pattern
// matching several sites patches the first one with nothing said at all.
//
// So every patch is named and reported: successes at trace level (they are
// numerous and only interesting when you are hunting), anything unexpected at
// warn level so it shows up in a default run.
// ============================================================================

namespace
{
    int gPatchApplied = 0;
    int gPatchAlready = 0;   // gate already opened by an earlier entry
    int gPatchMissing = 0;
    int gPatchAmbiguous = 0;

    // `expected` is how many sites the signature is supposed to hit; 0 means a
    // site count that is legitimately variable and gets reported rather than
    // judged (two of the anim-group hooks patch every match on purpose).
    // Non-const: hook::pattern resolves its matches lazily, so even size()
    // and get_first() mutate it.
    void ReportPattern(const char *what, hook::pattern &p, size_t expected = 1)
    {
        if (p.empty())
        {
            gPatchMissing++;
            CrashLog_NoteFailedPatch(what);
            TACE_WARN("[patch] %s: signature not found - not applied", what);
        }
        else if (expected != 0 && p.size() != expected)
        {
            gPatchAmbiguous++;
            CrashLog_NoteFailedPatch(what);
            TACE_WARN("[patch] %s: signature matches %zu sites, expected %zu - using the first (%p)",
                      what, p.size(), expected, p.get_first(0));
        }
        else
        {
            gPatchApplied++;
            static const bool trace = TaceTraceEnabled("patch");
            if (trace)
                TACE_TRACE("[patch] %s: %p%s", what, p.get_first(0),
                           p.size() > 1 ? " (and more)" : "");
        }
    }

    // For the core hooks, whose failure would break the mod outright. Control
    // flow is deliberately unchanged - this only makes the failure visible.
    hook::pattern FindPattern(const char *what, const char *sig, size_t expected = 1)
    {
        hook::pattern p(sig);
        ReportPattern(what, p, expected);
        return p;
    }

    // The episodic patches: NOP out an episode check so DLC content is active
    // in every episode. Same semantics as the hand-written form it replaces -
    // match, bail if absent, NOP - with the outcome recorded.
    // Rewrites a signature with the bytes this patch would overwrite turned into
    // wildcards, so it can still be found after something else has NOPed it.
    std::string Relaxed(const char *sig, uintptr_t offset, size_t bytes)
    {
        std::string out;
        size_t index = 0;
        for (const char *t = sig; *t;)
        {
            while (*t == ' ') t++;
            if (!*t) break;
            const char *end = t;
            while (*end && *end != ' ') end++;
            if (!out.empty()) out += ' ';
            out += (index >= offset && index < offset + bytes) ? "?" : std::string(t, end);
            t = end;
            index++;
        }
        return out;
    }

    // Two entries in this file sometimes describe the SAME gate - a pinned
    // variant and a wildcarded one, written at different times. Whichever runs
    // first NOPs it, and the second then fails to match its own signature and
    // reports "not found", which is true and completely useless: the gate is
    // open. Re-scan with the target bytes wildcarded, and if that lands on the
    // expected number of sites and they are already NOPs, say so instead.
    //
    // Only ever a fallback. Wildcarding the target wholesale would be far too
    // lossy - for some of these signatures the NOPed bytes are most of what
    // makes them unique (one goes from 1 match to 281).
    bool AlreadyOpen(const char *what, const char *sig, uintptr_t offset, size_t bytes,
                     size_t expected = 1)
    {
        hook::pattern p(Relaxed(sig, offset, bytes));
        if (p.size() != expected)
            return false;
        for (size_t i = 0; i < p.size(); i++)
        {
            const uint8_t *at = p.get(i).get<uint8_t>(offset);
            for (size_t b = 0; b < bytes; b++)
                if (at[b] != 0x90)
                    return false;
        }
        gPatchAlready++;
        TACE_INFO("[patch] %s: already open - an earlier patch NOPs the same gate", what);
        return true;
    }

    bool NopPatch(const char *what, const char *sig, uintptr_t offset, size_t bytes = 2)
    {
        hook::pattern p(sig);
        if (p.empty() && AlreadyOpen(what, sig, offset, bytes))
            return true;
        ReportPattern(what, p);
        if (p.empty())
            return false;
        injector::MakeNOP(p.get_first(offset), bytes, true);
        return true;
    }

    // One gate, more than one spelling. Tries each signature in turn - the same
    // idea as find_pattern() in Patterns.h, which carries per-build variants.
    // Both spellings are kept rather than the loser deleted: a build where one
    // form drifts may still match the other.
    bool NopPatchAny(const char *what, uintptr_t offset, size_t bytes,
                     const char *sigA, const char *sigB)
    {
        hook::pattern p(sigA);
        if (p.empty())
            p = hook::pattern(sigB);
        if (p.empty() && AlreadyOpen(what, sigA, offset, bytes))
            return true;
        ReportPattern(what, p);
        if (p.empty())
            return false;
        injector::MakeNOP(p.get_first(offset), bytes, true);
        return true;
    }

    // Patches EVERY match, not just the first.
    //
    // get_first() returns match 0 and only match 0, so a signature covering
    // several gates has always patched one of them and left the rest in place
    // silently - which meant some DLC content stayed locked to its own episode.
    // `expected` is the number of sites reviewed on 1.0.8.0; a different count
    // on another build is reported rather than assumed.
    //
    // The guard: in `cmp dword [global], imm` the compared global sits at
    // offset 2, and every gate one patch covers must test the SAME global. When
    // they disagree the signature has drifted onto unrelated code - exactly the
    // case with "Parachute anims", whose second match was a `cmp [x], 0` with
    // nothing to do with episodes. Those sites are skipped, not NOPed.
    bool NopPatchAll(const char *what, const char *sig, uintptr_t offset, size_t expected,
                     size_t bytes = 2)
    {
        hook::pattern p(sig);
        if (p.size() != expected)
        {
            // Fewer sites than were reviewed usually means an earlier entry
            // already NOPed one of them - check before calling it a problem.
            hook::pattern relaxed(Relaxed(sig, offset, bytes));
            if (relaxed.size() == expected)
            {
                TACE_INFO("[patch] %s: %zu of %zu site(s) already open, patching the rest",
                          what, expected - p.size(), expected);
                gPatchAlready++;
                p = relaxed;
            }
        }
        ReportPattern(what, p, expected);
        if (p.empty())
            return false;

        const uint32_t gate = *p.get(0).get<uint32_t>(2);
        size_t done = 0;
        for (size_t i = 0; i < p.size(); i++)
        {
            const uint32_t here = *p.get(i).get<uint32_t>(2);
            if (here != gate)
            {
                TACE_WARN("[patch] %s: site %zu tests %08X, not %08X - skipped as unrelated",
                          what, i, here, gate);
                continue;
            }
            injector::MakeNOP(p.get(i).get<void>(offset), bytes, true);
            done++;
        }
        TACE_TRACE("[patch] %s: %zu of %zu site(s) patched", what, done, p.size());
        return done > 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if(fdwReason == DLL_PROCESS_ATTACH)
    {
        TaceLog_Init();

        // First, deliberately: a crash inside TacePatch's own startup is
        // exactly the crash worth catching, and everything below this line is
        // signature matching against an executable we do not control.
        CrashLog_Init();

        InitializeAllLimitAdjusters();
        PainVoice_Init();
        GangWeapons_Init();
        CopWeapons_Init();
        CoverAnim_Init();
        CopAnims_Init();

        hook::pattern pattern {};

        pattern = FindPattern("model store base", "8B C8 E8 ? ? ? ? B9 ? ? ? ? A3");
        auto CModelInfoStore__ms_baseModels = *pattern.get_first<CDataStore*>(8);

        for (size_t i = CModelInfoStore::ms_baseModels; i < CModelInfoStore::amount; i++)
            CModelInfoStore__ms_baseModels[i].nSize *= 2; // limit adjuster code from FusionFix

        pattern = FindPattern("current episode global", "89 35 ? ? ? ? 89 35 ? ? ? ? 6A 00 6A 01");
        _dwCurrentEpisode = *(int32_t**)pattern.get_first(2);

        pattern = FindPattern("CPedMoveBlendOnFoot::SetAnimGroup", "8B 41 3C 8B 54 24 04");
        CPedMoveBlendOnFoot__SetAnimGroupO = pattern.get_first(0);

        pattern = FindPattern("SetAnimGroup call sites (rifle)", "74 ? 6A 33 E8 ? ? ? ?", 0);
        for(size_t i = 0; i < pattern.size(); i++)
            injector::MakeCALL(pattern.get(i).get<void*>(4), CPedMoveBlendOnFoot__SetAnimGroupH);

        pattern = FindPattern("SetAnimGroup call sites (rpg)", "5E ? 6A 32 E8 ? ? ? ?", 0);
        for(size_t i = 0; i < pattern.size(); i++)
            injector::MakeCALL(pattern.get(i).get<void*>(4), CPedMoveBlendOnFoot__SetAnimGroupH);

        pattern = FindPattern("SetAnimGroup call site (armed)", "8B 8E ? ? ? ? 6A 38 E8 ? ? ? ?");
        injector::MakeCALL(pattern.get_first(8), CPedMoveBlendOnFoot__SetAnimGroupH);

        pattern = FindPattern("CModelInfoStore::ms_models", "68 60 E4 01 00 6A 00 68 ? ? ? ?");
        CModelInfoStore__msModels = *(uint32_t**)pattern.get_first(8);

        pattern = FindPattern("CModelInfoStore::GetModelByName", "E8 ? ? ? ? 8B F0 8D 47 FF");
        CModelInfoStore__GetModelByName = injector::GetBranchDestination(pattern.get_first(0), true).get();

        pattern = FindPattern("multiplayer ped model test", "8B 44 24 04 85 C0 7D 03");
        injector::MakeJMP(pattern.get_first(0), IsModelMultiplayerPed);

        pattern = FindPattern("CAnimMgr::GetAnimGroupIdByName", "E8 ? ? ? ? 83 F8 3A");
        CAnimMgr__GetAnimGroupIdByName = injector::GetBranchDestination(pattern.get_first(0), true).get();

        pattern = FindPattern("CGame::InitMap", "E8 ? ? ? ? 38 1D ? ? ? ? 74 06 88 1D ? ? ? ? 38 1D ? ? ? ? 74 05");
        CGame__InitMapO = injector::MakeCALL(pattern.get_first(0), CGame__InitMapH).get();

        pattern = FindPattern("CAnimMgr::GetDictionaryIdAtAnimGroup", "E8 ? ? ? ? 85 ED 74 0E");
        CAnimMgr__GetDictionaryIdAtAnimGroup = injector::GetBranchDestination(pattern.get_first(0), true).get();

        pattern = FindPattern("CAnimMgr::HasAnimLoaded", "E8 ? ? ? ? 83 C4 04 84 C0 75 1C");
        CAnimMgr__HasAnimLoaded = injector::GetBranchDestination(pattern.get_first(0), true).get();

        pattern = FindPattern("multiplayer ped gender", "0F BF 45 2E 39 05 ? ? ? ?");
        injector::MakeCALL(pattern.get_first(4), IsMultiplayerModelMale);
        injector::MakeNOP(pattern.get_first(9));

        pattern = FindPattern("ped gender test (1)", "E8 ? ? ? ? 8B 8E ? ? ? ? 83 C4 04 84 C0 74 0C");
        injector::MakeCALL(pattern.get_first(0), IsPedFemale);
        pattern = FindPattern("ped gender test (2)", "E8 ? ? ? ? 8B 8E ? ? ? ? 83 C4 04 84 C0 74 0B");
        injector::MakeCALL(pattern.get_first(0), IsPedFemale);

        {
            // The episode immediate is pinned to 02 deliberately. Wildcarded, this
            // signature also matched a `cmp episode,1` that picks between the
            // "PU_SEADONE" / "PU_SEADONEE2" pickup names - and since get_first()
            // returns match 0, THAT is the site this patch used to NOP, leaving
            // wpn_bullet_trace_e2 locked to TBoGT. Pinning it lands on the gate
            // the name describes and leaves the pickup names alone.
            NopPatch("E2 Bullet traces", "83 3D ? ? ? ? 02 75 07 68 ? ? ? ? EB 05 68 ? ? ? ?", 7);

            NopPatch("TBoGT counter anims fix #1", "83 3D ? ? ? ? ? 53 55 8B 6C 24 20 57 8B F9 BB ? ? ? ? 75 29", 21);

            NopPatch("TBoGT counter anims fix #2", "39 1D ? ? ? ? 75 2A 80 7F 28 00", 6);

            //pattern = hook::pattern("83 3D ? ? ? ? ? 75 32 8B 56 34"); // TBoGT melee stuff?
            //if (!pattern.empty())
            //    injector::MakeNOP(pattern.get_first(7), 2, true);

            // One signature, two gates, and it was written out twice under two names -
            // so site 0 was NOPed twice and site 1 never. Both are patched here.
            NopPatchAll("parachute wind sounds / explosive weapons networking",
                        "83 3D ? ? ? ? 02 75 0A F3 0F 10 05 ? ? ? ?", 7, 2);

            NopPatch("disco camera shake #1", "83 3D ? ? ? ? ? 8A 81", 18);

            NopPatch("disco camera shake #2", "83 3D ? ? ? ? ? 75 05 E8 ? ? ? ? 8B 4E 04", 7);

            NopPatch("disco camera shake #3", "83 3D ? ? ? ? ? 75 23 80 3D", 7);

            NopPatch("m249 for swat in annihilators and helicopters", "83 3D ? ? ? ? ? 6A 00 6A 00 6A 01", 20);

            NopPatch("phone model change", "83 3D ? ? ? ? ? 0F 8C ? ? ? ? 8B CF", 7, 6);

            NopPatch("explosive sniper cheat", "DD D8 83 3D ? ? ? ? ? 0F 85 ? ? ? ? 39 9C 24 ? ? ? ? 0F 84 ? ? ? ? E8 ? ? ? ?", 9, 6);

            NopPatch("explosive fists cheat", "83 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 3D ? ? ? ? ? 0F 84 ? ? ? ? 6A FF", 7, 6);

            NopPatch("annihilator explosive shots", "83 3D ? ? ? ? ? 0F 8C ? ? ? ? 85 FF", 7, 6);

            NopPatch("Grenade launcher explode on impact", "83 3D ? ? ? ? ? 75 30 83 7E 14 19 75 2A ", 7);

            NopPatch("CExplosions__addExplosion", "83 3D ? ? ? ? ? 75 57 83 F8 02 75 52", 7);

            NopPatch("CExplosions__addExplosion disable ped rolling", "83 3D ? ? ? ? ? 75 1B 8B 56 40 F3 0F 10 05 ? ? ? ? ", 7);

            NopPatch("P90 scroll block", "83 3D ? ? ? ? ? 0F 8C ? ? ? ? 83 7F 6C 20", 7, 6);

            NopPatch("P90 get in car block", "39 35 ? ? ? ? 7C 05", 6);

            NopPatch("ADD_GROUP_TO_NETWORK_RESTART_NODE_GROUP_LIST", "83 3D ? ? ? ? ? 75 13 8B 44 24 04", 7);

            NopPatch("E2_Landing marker request model #1", "89 94 24 ? ? ? ? 88 8C 24 ? ? ? ? 75 2F", 14);

            NopPatch("E2_Landing marker request model #2", "57 BD ? ? ? ? 75 05", 6);

            NopPatch("E2_Landing marker request model #3", "83 3D ? ? ? ? ? BB ? ? ? ? 75 05", 12);

            NopPatch("E2_Landing marker Enable", "39 3D ? ? ? ? 0F 85 ? ? ? ? 66 83 7E ? ? 0F 85 ? ? ? ?", 6, 6);

            NopPatch("Give parachute during load save", "83 3D ? ? ? ? ? 75 1E E8 ? ? ? ? 84 C0", 7);

            NopPatch("Check if player had a parachute", "83 3D ? ? ? ? ? 75 0C 80 3D ? ? ? ? ? 74 03", 7);

            NopPatch("Check for parachute during savegame #1", "83 3D ? ? ? ? ? 75 0D 80 7E 7D 00 74 07 C6 05 ? ? ? ? ?", 7);

            NopPatch("Check for parachute during savegame #2", "83 3D ? ? ? ? ? 75 20 E8 ? ? ? ? 85 C0", 7);

            NopPatch("E2 stats check #1", "83 3D ? ? ? ? ? 75 12 80 3D ? ? ? ? ? 0F 85 ? ? ? ?", 7);

            NopPatch("E2 stats check #2", "83 3D ? ? ? ? ? 75 05 E8 ? ? ? ? 80 3D ? ? ? ? ?", 7);

            /*NopPatch("Default.dat load order #1", "BE ? ? ? ? 39 35 ? ? ? ? 75 0E 56", 11);

            NopPatch("Default.dat load order #2", "39 35 ? ? ? ? 75 09 6A 01 68 ? ? ? ?", 6);*/

            pattern = FindPattern("cops carry a Baretta, not a pump shotgun", "6A 0A 81 C1 ? ? ? ? E8 ? ? ? ? EB 04"); // Make cops spawn with baretta instead of pumpshot
            if (!pattern.empty())
                injector::WriteMemory<int8_t>(pattern.get_first(1), 11, true);

            NopPatch("Explosive AA12 enabler", "83 3D ? ? ? ? 02 0F 8C D5 00", 7, 6);
            
            NopPatch("Explosive AA12", "83 F8 02 7C E3 83 FB 1E 75 DE", 3);

            NopPatch("CPedWeapons__giveWeapon Explosive AA12", "83 3D ? ? ? ? ? 7C 1A 83 FE 03 75 15", 7);

            NopPatch("APC Cannon", "83 F8 02 7C 25 83 FB 28", 3);

            NopPatch("dsr1", "83 3D ? ? ? ? 02 7C 32 8B 41", 7);

            NopPatch("dsr1 hud", "83 3D ? ? ? ? ? 75 5B 83 3D ? ? ? ? ?", 7);

            // Two episode-2 gates, only one of which was ever patched. Wildcarded, the
            // signature also caught a `cmp episode,1` loading the TLAD value in a
            // third function; that one is left alone on purpose - forcing a TLAD
            // constant would override TBoGT's own in that path.
            NopPatchAll("Sniper rifle checks #1", "83 3D ? ? ? ? 02 75 0E F3 0F 10 05 ? ? ? ?", 7, 2);

            NopPatch("Sniper rifle checks #2", "83 3D ? ? ? ? ? 75 04 B3 01 EB 02", 7);

            NopPatch("weap checks #1", "83 3D ? ? ? ? 02 7C 7D 8B 4C 24 0C", 7);

            NopPatch("exp aa12 & apc cannon", "39 3D ? ? ? ? 7C 14 8B 46 18", 6);

            // (explosive weapons networking shares the signature above and is
            //  patched by it - it used to be a second call that re-NOPed site 0.)

            NopPatch("weap checks? nearby explosive weapon checks", "83 3D ? ? ? ? ? 75 22 83 F8 02 75 1D", 7);

            NopPatch("sticky bomb move disable", "83 3D ? ? ? ? 02 75 50", 7);

            NopPatch("CTaskComplexAimAndThrowProjectile::createNextSubTask", "83 3D ? ? ? ? ? 75 20 8B 07 8B 90 ? ? ? ?", 7);

            NopPatch("CTaskSimplePlayerAimProjectile::process", "83 3D ? ? ? ? ? 75 1C 8B 47 18 50 E8 ? ? ? ?", 7);

            NopPatchAny("CTaskSimpleThrowProjectile::process", 7, 6,
                        "83 3D ? ? ? ? ? 0F 85 ? ? ? ? 8B 46 4C",
                        "83 3D ? ? ? ? 02 0F 85 8C 01 00 00");   // 2nd spelling was its own entry


            NopPatchAny("Sticky bomb something", 7, 2,
                        "83 3D ? ? ? ? ? 75 29 8B 44 24 04",
                        "83 3D ? ? ? ? ? 75 29 8B 44 24 04 8A 88 ? ? ? ?");   // was #1 and #2


            NopPatch("Sticky bomb drop icon", "83 3D ? ? ? ? 02 75 20 8B CD E8", 7);

            NopPatch("Sticky bomb faster throw in vehicle #1", "83 3D ? ? ? ? ? 75 3C 8B 41 20 85 C0", 7);
            
            NopPatch("Sticky bomb faster throw in vehicle #2", "83 3D ? ? ? ? ? 7C 69 8D 8F ? ? ? ?", 7);

            NopPatch("Sticky bomb faster throw in vehicle #3", "39 05 ? ? ? ? F3 0F 59 EC", 44, 6);

            NopPatch("Sticky bomb", "83 3D ? ? ? ? ? 88 44 24 1C 7C 0B", 11);

            NopPatch("Sticky bomb mp sync", "83 3D ? ? ? ? ? 7C 4C 83 F8 15 75 47", 7);

            NopPatch("weap checks #2", "83 3D ? ? ? ? 02 7C 21 8B 44 24 0C", 7);

            NopPatch("TBoGT heli height limit", "83 3D ? ? ? ? 02 7C 0A F3 0F", 7);

            NopPatch("PoliceEpisodicWeaponSupport", "39 2D ? ? ? ? 75 3E", 6);

            NopPatch("PipeBombDropIconSupport", "83 3D ? ? ? ? ? 74 1A 83 7D 18 1C", 7);

            NopPatch("BikeFeetFix", "39 05 ? ? ? ? 0F 85 ? ? ? ? 68 ? ? ? ?", 6, 6);

            NopPatch("BikePhoneAnimsFix", "83 3D ? ? ? ? ? 0F 8C ? ? ? ? F6 86 ? ? ? ? ?", 7, 6);

            // Pinned to 02: the second match of the wildcarded form was a `cmp [x],0`
            // on an unrelated global. Behaviour is unchanged - that site was never
            // patched - but the signature can no longer reach it.
            NopPatch("Parachute anims", "83 3D ? ? ? ? 02 75 14 E8", 7);

            NopPatch("Parachute #1", "83 3D ? ? ? ? ? 7C 0D F3 0F 10 05 ? ? ? ?", 7);

            NopPatch("Parachute #2", "83 3D ? ? ? ? ? 75 6D 56 8B 74 24 0C", 7);

            NopPatch("Parachute #3", "83 3D ? ? ? ? ? 75 18 0F B7 46 0A", 7);

            NopPatch("parachute extended camera", "83 3D ? ? ? ? ? 0F 85 ? ? ? ? 8B 54 24 0C", 7, 6);

            NopPatchAny("Buzzards minigun", 7, 2,
                        "83 3D ? ? ? ? ? 7C 1F 8B 56 18",
                        "83 3D ? ? ? ? 02 7C 1F 8B");   // 2nd spelling was a BUZZARD entry
 
            NopPatch("EpisodicVehicleSupport (APC) #1", "83 3D ? ? ? ? 02 0F 8C 0E 05 00 00", 7, 6);

            NopPatch("EpisodicVehicleSupport (APC) #2", "83 3D ? ? ? ? 02 7C 35 0F BF 43 2E", 7);

            NopPatch("EpisodicVehicleSupport (APC) #3", "83 3D ? ? ? ? 02 8A 0D", 17);

            NopPatch("EpisodicVehicleSupport (APC) #4", "83 3D ? ? ? ? 02 75 21 8B 96 20 08 00 00", 7);

            NopPatch("EpisodicVehicleSupport (APC) #5", "83 3D ? ? ? ? 02 7C 4A 0F BF 46 2E", 7);

            NopPatch("EpisodicVehicleSupport (APC) respray", "83 3D ? ? ? ? 02 75 08 3B 05", 7);

            NopPatch("EpisodicVehicleSupport APC & BUZZARD", "83 3D ? ? ? ? 02 75 1F 8B 44 24 04", 7);

            NopPatch("EpisodicVehicleSupport (APC) #6", "83 3D ? ? ? ? 02 75 38 8B 16", 7);

            NopPatch("EpisodicVehicleSupport (APC) #7", "83 3D ? ? ? ? 02 75 24 F6 87 6C 02 00 00 04", 7);

            NopPatch("EpisodicVehicleSupport (APC) #8", "83 3D ? ? ? ? ? 75 0E F3 0F 10 05 ? ? ? ? F3 0F 11 44 24 ? 8B 47 04 0F BF 48 2E", 7);

            NopPatch("EpisodicVehicleSupport (APC) #9", "83 3D ? ? ? ? ? 8B 07 8B B0 ? ? ? ? 8B 56 04 8B 4A 0C 89 4C 24 1C 7C 18", 25);

            NopPatch("EpisodicVehicleSupport (APC) #10", "83 3D ? ? ? ? 02 75 35 0F BF 46 2E", 7);

            NopPatch("EpisodicVehicleSupport (APC) #11", "83 3D ? ? ? ? 02 7C 26 8B 85 40 0B 00 00", 7);

            NopPatch("EpisodicVehicleSupport (APC) #12", "83 3D ? ? ? ? 02 75 17 F3 0F 10 44 24 0C", 7);

            NopPatch("Weapon sounds sub_B5D970", "83 3D ? ? ? ? ? F3 0F 10 15 ? ? ? ? 8B 35 ? ? ? ? F3 0F 11 54 24 ? 75 09", 27);

            NopPatch("SHOTGUN_EXPLOSION sub_B5D970", "83 3D ? ? ? ? ? 75 7C 8B 35 ? ? ? ?", 7);

            NopPatch("APC_EXPLOSION sub_B5D970", "83 3D ? ? ? ? 02 F3 0F 10 05 ? ? ? ? F3 0F 11 44 24 20 75 4C", 21);

            NopPatch("GRENADE_EXPLOSION sub_B5D970", "83 3D ? ? ? ? ? 0F 85 ? ? ? ? 84 C0", 7, 6);
            
            NopPatch("EpisodicVehicleSupport (APC) sounds", "83 3D ? ? ? ? ? 57 7C 22", 8);
            
            NopPatch("EpisodicVehicleSupport (BUZZARD) #1", "83 3D ? ? ? ? ? 75 09 83 BE ? ? ? ? ? 7F 26", 7);

            NopPatch("EpisodicVehicleSupport (BUZZARD) #2", "83 3D ? ? ? ? ? 7C 58 0F BF 4E 2E 3B 0D ? ? ? ?", 7);

            NopPatchAll("EpisodicVehicleSupport (BUZZARD) #3",
                        "83 3D ? ? ? ? 02 0F 8C ? ? ? ? 0F BF 46 2E 3B 05 ? ? ? ? 74 0C", 7, 2, 6);
            
            NopPatch("EpisodicVehicleSupport (BUZZARD) #4", "83 3D ? ? ? ? ? F3 0F 11 44 24 ? F3 0F 10 40 ? F3 0F 11 44 24 ? 0F 85 ? ? ? ?", 24, 6);

            NopPatch("EpisodicVehicleSupport (BUZZARD & SWIFT)", "83 3D ? ? ? ? ? 7C 64 0F BF 46 2E 3B 05 ? ? ? ?", 7);

            NopPatch("EpisodicVehicleSupport (BUZZARD) sounds", "83 3D ? ? ? ? 02 89 44 24 38", 11);

            NopPatch("EpisodicVehicleSupport (BUZZARD) BULLET_IMPACT_WATER", "83 3D ? ? ? ? ? 7C 11 8B 46 18 50 E8 ? ? ? ?", 7);

            NopPatch("EpisodicVehicleSupport (BUZZARD) weapon effects", "83 3D ? ? ? ? 02 7C 43", 7);


            NopPatch("EpisodicVehicleSupport (BUZZARD) minigun #2", "83 3D ? ? ? ? 02 7C 11 8B 4E", 7);

            NopPatch("BUZZARD rubble effects", "83 3D ? ? ? ? ? 7C 11 8B 4F 18 51 E8 ? ? ? ?", 7);

            NopPatch("EpisodicVehicleSupport Altimeter", "39 35 ? ? ? ? 75 0E 80 3D", 6);

            NopPatch("EpisodicVehicleSupport Boat models #1", "83 3D ? ? ? ? ? 75 5A 3B 05 ? ? ? ? 75 19", 7);

            NopPatchAll("EpisodicVehicleSupport Boat models #2",
                        "83 3D ? ? ? ? 02 75 3C 3B 05 ? ? ? ? 75 0A", 7, 2);

            NopPatch("EpisodicVehicleSupport Boat models #3", "EB 61 3B 05 ? ? ? ? 75 0A F3 0F 10 05 ? ? ? ? EB 4F 3B 05 ? ? ? ? 75 0A F3 0F 10 05 ? ? ? ? EB 3D 83 3D ? ? ? ? ? 75 3C", 45);

            NopPatch("EpisodicVehicleSupport Boat models #4", "83 3D ? ? ? ? ? 75 32 3B 05 ? ? ? ? 75 0A F3 0F 10 05 ? ? ? ?", 7);

            NopPatch("EpisodicVehicleSupport Floater camera", "83 3D ? ? ? ? ? 75 20 0F BF 56 2E 3B 15 ? ? ? ?", 7);

            NopPatch("EpisodicVehicleSupport Boat models #5", "83 3D ? ? ? ? ? 75 2C 3B 05 ? ? ? ? 0F 84 ? ? ? ?", 7);

            NopPatch("EpisodicVehicleSupport Boats", "83 3D ? ? ? ? ? 75 28 3B 05 ? ? ? ? 74 C3 3B 05 ? ? ? ? 74 08 3B 05 ? ? ? ?", 7);

            NopPatch("EpisodicVehicleSupport Boat models #6", "EB 31 83 3D ? ? ? ? ? 75 30 3B 05 ? ? ? ?", 9);

            NopPatch("EpisodicVehicleSupport Boat models #7", "3B 05 ? ? ? ? 74 EE 83 3D ? ? ? ? ? 75 28", 15);
        }

        /*NopPatch("Achievement/Rank10 unlocks for all episodes #1", "83 3D ? ? ? ? ? 8B F0 75 09", 9);

        NopPatch("Achievement/Rank10 unlocks for all episodes #2", "83 3D ? ? ? ? ? 0F 85 ? ? ? ? 6A 00 E8 ? ? ? ? 83 C4 04 83 F8 0A 0F 8C ? ? ? ?", 7, 6);

        NopPatch("Achievement/Rank10 unlocks for all episodes #3", "83 3D ? ? ? ? ? 75 0D F6 05 ? ? ? ? ?", 7);

        NopPatch("Achievement/Rank10 unlocks for all episodes #4", "83 3D ? ? ? ? ? 75 70 F6 05 ? ? ? ? ?", 7);

        NopPatch("Achievement/Rank10 unlocks for all episodes #5", "83 3D ? ? ? ? ? 75 0D B8 ? ? ? ?", 7);

        NopPatch("Achievement/Rank10 unlocks for all episodes #6", "83 3D ? ? ? ? ? 75 0F F6 05 ? ? ? ? ?", 7);

        NopPatch("Achievement/Rank10 unlocks for all episodes #7", "8B 1D ? ? ? ? 85 DB 55 56 57 0F 85 ? ? ? ?", 11, 6);

        NopPatch("Achievement/Rank10 unlocks for all episodes #8", "85 C9 0F B6 C0 75 20", 5);

        NopPatch("Achievement/Rank10 unlocks for all episodes #9", "83 C4 0C 83 3D ? ? ? ? ? 75 75", 10);

        NopPatch("Achievement/Rank10 unlocks for all episodes #10", "83 C4 0C 83 3D ? ? ? ? ? 75 54", 10);

        NopPatch("Achievement/Rank10 unlocks for all episodes #11", "85 D2 8B 40 04 75 0E", 5);*/

        TACE_INFO("[patch] %d applied, %d already open, %d not found, %d ambiguous",
                  gPatchApplied, gPatchAlready, gPatchMissing, gPatchAmbiguous);
        CrashLog_SetPatchStats(gPatchApplied, gPatchAlready, gPatchMissing, gPatchAmbiguous);
        if (_dwCurrentEpisode)
        {
            char ep[32];
            sprintf(ep, "%d", *_dwCurrentEpisode);
            CrashLog_SetNote("episode at startup", ep);
        }

        // LAST, deliberately. The profiler rewrites the compare instruction
        // at every gate, which would destroy the byte signatures every patch
        // above searches for - so it must not run until they have all been
        // applied. It also needs to see the finished state to tell a gate
        // TacePatch has forced open from one that is still episode-locked.
        GateProfile_Init();

        TaceLog_Summary();
    }

    return true;
}

uint32_t GetAnimGroupIdForModel(uint32_t modelHash, eAnimGroup animGroup)
{
    if(gAnimationOverrides.find(modelHash) != gAnimationOverrides.end())
    {
        if ((animGroup == ANIMGRP_MOVE_RPG) && (CAnimMgr__HasAnimLoaded(gAnimationOverrides[modelHash].RpgAnimGroupID)))
                return gAnimationOverrides[modelHash].RpgAnimGroupID;

        if (CAnimMgr__HasAnimLoaded(gAnimationOverrides[modelHash].RifleAnimGroupID))
           return gAnimationOverrides[modelHash].RifleAnimGroupID;

    }
    
    static uint32_t moveRifle = CAnimMgr__GetAnimGroupIdByName("move_rifle");
    static uint32_t moveRpg = CAnimMgr__GetAnimGroupIdByName("move_rpg");
    return animGroup == ANIMGRP_MOVE_RPG ? moveRpg : moveRifle;
}

void NewAnimationOverride(const char *modelName, const char *rifleAnim, const char *rpgAnim)
{
    uint32_t hash = rage::atStringHash(modelName);
    gAnimationOverrides[hash].RifleAnimGroupID = CAnimMgr__GetAnimGroupIdByName(rifleAnim);
    gAnimationOverrides[hash].RpgAnimGroupID = CAnimMgr__GetAnimGroupIdByName(rpgAnim);
}