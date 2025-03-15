#define _CRT_SECURE_NO_WARNINGS

#include <unordered_map>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "rage/Hash.h"
#include "Types.h"

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

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if(fdwReason == DLL_PROCESS_ATTACH)
    {
        hook::pattern pattern {};

        pattern = hook::pattern("8B C8 E8 ? ? ? ? B9 ? ? ? ? A3");
        auto CModelInfoStore__ms_baseModels = *pattern.get_first<CDataStore*>(8);

        for (size_t i = CModelInfoStore::ms_baseModels; i < CModelInfoStore::amount; i++)
        {
            CModelInfoStore__ms_baseModels[i].nSize *= 2;
        }

        pattern = hook::pattern("89 35 ? ? ? ? 89 35 ? ? ? ? 6A 00 6A 01");
        _dwCurrentEpisode = *(int32_t**)pattern.get_first(2);

        pattern = hook::pattern("8B 41 3C 8B 54 24 04");
        CPedMoveBlendOnFoot__SetAnimGroupO = pattern.get_first(0);

        pattern = hook::pattern("74 ? 6A 33 E8 ? ? ? ?");
        for(size_t i = 0; i < pattern.size(); i++)
        {
            injector::MakeCALL(pattern.get(i).get<void*>(4), CPedMoveBlendOnFoot__SetAnimGroupH);
        }
        pattern = hook::pattern("5E ? 6A 32 E8 ? ? ? ?");
        for(size_t i = 0; i < pattern.size(); i++)
        {
            injector::MakeCALL(pattern.get(i).get<void*>(4), CPedMoveBlendOnFoot__SetAnimGroupH);
        }
        pattern = hook::pattern("8B 8E ? ? ? ? 6A 38 E8 ? ? ? ?");
        injector::MakeCALL(pattern.get_first(8), CPedMoveBlendOnFoot__SetAnimGroupH);

        pattern = hook::pattern("68 60 E4 01 00 6A 00 68 ? ? ? ?");
        CModelInfoStore__msModels = *(uint32_t**)pattern.get_first(8);

        pattern = hook::pattern("E8 ? ? ? ? 8B F0 8D 47 FF");
        CModelInfoStore__GetModelByName = injector::GetBranchDestination(pattern.get_first(0), true).get();

        pattern = hook::pattern("8B 44 24 04 85 C0 7D 03");
        injector::MakeJMP(pattern.get_first(0), IsModelMultiplayerPed);

        pattern = hook::pattern("E8 ? ? ? ? 83 F8 3A");
        CAnimMgr__GetAnimGroupIdByName = injector::GetBranchDestination(pattern.get_first(0), true).get();

        pattern = hook::pattern("E8 ? ? ? ? 38 1D ? ? ? ? 74 06 88 1D ? ? ? ? 38 1D ? ? ? ? 74 05");
        CGame__InitMapO = injector::MakeCALL(pattern.get_first(0), CGame__InitMapH).get();

        pattern = hook::pattern("E8 ? ? ? ? 85 ED 74 0E");
        CAnimMgr__GetDictionaryIdAtAnimGroup = injector::GetBranchDestination(pattern.get_first(0), true).get();

        pattern = hook::pattern("E8 ? ? ? ? 83 C4 04 84 C0 75 1C");
        CAnimMgr__HasAnimLoaded = injector::GetBranchDestination(pattern.get_first(0), true).get();

        pattern = hook::pattern("0F BF 45 2E 39 05 ? ? ? ?");
        injector::MakeCALL(pattern.get_first(4), IsMultiplayerModelMale);
        injector::MakeNOP(pattern.get_first(9));

        pattern = hook::pattern("E8 ? ? ? ? 8B 8E ? ? ? ? 83 C4 04 84 C0 74 0C");
        injector::MakeCALL(pattern.get_first(0), IsPedFemale);
        pattern = hook::pattern("E8 ? ? ? ? 8B 8E ? ? ? ? 83 C4 04 84 C0 74 0B");
        injector::MakeCALL(pattern.get_first(0), IsPedFemale);

        {
            pattern = hook::pattern("83 3D ? ? ? ? ? 75 07 68 ? ? ? ? EB 05 68 ? ? ? ?"); // E2 Bullet traces
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 53 55 8B 6C 24 20 57 8B F9 BB ? ? ? ? 75 29"); // TBoGT counter anims fix
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(21), 2, true);

            pattern = hook::pattern("39 1D ? ? ? ? 75 2A 80 7F 28 00"); // TBoGT counter anims fix
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 2, true);

            //pattern = hook::pattern("83 3D ? ? ? ? ? 75 32 8B 56 34"); // TBoGT melee stuff?
            //if (!pattern.empty())
            //    injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 0A F3 0F 10 05 ? ? ? ?"); // parachute wind sounds
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 8A 81"); // disco camera shake
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(18), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 05 E8 ? ? ? ? 8B 4E 04"); // disco camera shake
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            auto pattern = hook::pattern("83 3D ? ? ? ? ? 75 23 80 3D");  // disco camera shake
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 6A 00 6A 00 6A 01"); // m249 for swat in annihilators and helicopters
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(20), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 8C ? ? ? ? 8B CF"); // phone model change
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("DD D8 83 3D ? ? ? ? ? 0F 85 ? ? ? ? 39 9C 24 ? ? ? ? 0F 84 ? ? ? ? E8 ? ? ? ?"); // explosive sniper cheat
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(9), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 3D ? ? ? ? ? 0F 84 ? ? ? ? 6A FF"); // explosive fists cheat
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 8C ? ? ? ? 85 FF"); // annihilator explosive shots
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 30 83 7E 14 19 75 2A "); // Grenade launcher explode on impact
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 57 83 F8 02 75 52"); // CExplosions__addExplosion
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 1B 8B 56 40 F3 0F 10 05 ? ? ? ? "); // CExplosions__addExplosion disable ped rolling
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 8C ? ? ? ? 83 7F 6C 20"); // P90 scroll block
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("39 35 ? ? ? ? 7C 05"); // P90 get in car block
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 13 8B 44 24 04"); // ADD_GROUP_TO_NETWORK_RESTART_NODE_GROUP_LIST
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("89 94 24 ? ? ? ? 88 8C 24 ? ? ? ? 75 2F"); // E2_Landing marker request model
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(14), 2, true);

            pattern = hook::pattern("57 BD ? ? ? ? 75 05"); // E2_Landing marker request model
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? BB ? ? ? ? 75 05"); // E2_Landing marker request model
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(12), 2, true);

            pattern = hook::pattern("39 3D ? ? ? ? 0F 85 ? ? ? ? 66 83 7E ? ? 0F 85 ? ? ? ?"); // E2_Landing marker Enable
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 1E E8 ? ? ? ? 84 C0"); // Give parachute during load save
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 0C 80 3D ? ? ? ? ? 74 03"); // Check if player had a parachute
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 0D 80 7E 7D 00 74 07 C6 05 ? ? ? ? ?"); // Check for parachute during savegame
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 20 E8 ? ? ? ? 85 C0"); // Check for parachute during savegame
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 12 80 3D ? ? ? ? ? 0F 85 ? ? ? ?"); // E2 stats check?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 05 E8 ? ? ? ? 80 3D ? ? ? ? ?"); // E2 stats check?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            /*pattern = hook::pattern("BE ? ? ? ? 39 35 ? ? ? ? 75 0E 56"); // Default.dat load order?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(11), 2, true);

            pattern = hook::pattern("39 35 ? ? ? ? 75 09 6A 01 68 ? ? ? ?"); // Default.dat load order?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 2, true);*/

            pattern = hook::pattern("6A 0A 81 C1 ? ? ? ? E8 ? ? ? ? EB 04"); // Make cops spawn with baretta instead of pumpshot
            if (!pattern.empty())
                injector::WriteMemory<int8_t>(pattern.get_first(1), 11, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 0F 8C D5 00"); // Explosive AA12 enabler
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);
            
            pattern = hook::pattern("83 F8 02 7C E3 83 FB 1E 75 DE"); // Explosive AA12
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(3), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 1A 83 FE 03 75 15"); // CPedWeapons__giveWeapon Explosive AA12
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 F8 02 7C 25 83 FB 28"); // APC Cannon
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(3), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 32 8B 41"); // dsr1?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 5B 83 3D ? ? ? ? ?"); // dsr1 hud
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 0E F3 0F 10 05 ? ? ? ?"); // Sniper rifle checks?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 04 B3 01 EB 02"); // Sniper rifle checks?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 7D 8B 4C 24 0C"); // weap checks
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("39 3D ? ? ? ? 7C 14 8B 46 18"); // exp aa12 & apc cannon
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 0A F3 0F 10 05 ? ? ? ?"); // explosive weapons networking
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 22 83 F8 02 75 1D"); // weap checks? nearby explosive weapon checks
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 50"); // sticky bomb move disable?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 20 8B 07 8B 90 ? ? ? ?"); // CTaskComplexAimAndThrowProjectile::createNextSubTask
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 1C 8B 47 18 50 E8 ? ? ? ?"); // CTaskSimplePlayerAimProjectile::process
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 85 ? ? ? ? 8B 46 4C"); // CTaskSimpleThrowProjectile::process
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 0F 85 8C 01 00 00"); // Sticky bomb CTaskSimpleThrowProjectile::process
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 29 8B 44 24 04"); // Sticky bomb something?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 29 8B 44 24 04 8A 88 ? ? ? ?"); // Sticky bomb something?
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 20 8B CD E8"); // Sticky bomb drop icon
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 3C 8B 41 20 85 C0"); // Sticky bomb faster throw in vehicle ??
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);
            
            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 69 8D 8F ? ? ? ?"); // Sticky bomb faster throw in vehicle
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("39 05 ? ? ? ? F3 0F 59 EC"); // Sticky bomb faster throw in vehicle
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(44), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 88 44 24 1C 7C 0B"); // Sticky bomb ??
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(11), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 4C 83 F8 15 75 47"); // Sticky bomb mp sync
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 21 8B 44 24 0C"); // weap checks
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 0A F3 0F"); // TBoGT heli height limit
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("39 2D ? ? ? ? 75 3E"); // PoliceEpisodicWeaponSupport
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 74 1A 83 7D 18 1C"); // PipeBombDropIconSupport
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("39 05 ? ? ? ? 0F 85 ? ? ? ? 68 ? ? ? ?"); // BikeFeetFix
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 8C ? ? ? ? F6 86 ? ? ? ? ?"); // BikePhoneAnimsFix
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 14 E8"); // parachute anims
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 0D F3 0F 10 05 ? ? ? ?"); // Parachute
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 6D 56 8B 74 24 0C"); // Parachute
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 18 0F B7 46 0A"); // Parachute
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 85 ? ? ? ? 8B 54 24 0C"); // parachute extended camera
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 1F 8B 56 18"); // Buzzards minigun
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);
 
            pattern = hook::pattern("83 3D ? ? ? ? 02 0F 8C 0E 05 00 00"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 35 0F BF 43 2E"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 8A 0D"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(17), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 21 8B 96 20 08 00 00"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 4A 0F BF 46 2E"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 08 3B 05"); // EpisodicVehicleSupport (APC) respray
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 1F 8B 44 24 04"); // EpisodicVehicleSupport APC & BUZZARD
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 38 8B 16"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 24 F6 87 6C 02 00 00 04"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 0E F3 0F 10 05 ? ? ? ? F3 0F 11 44 24 ? 8B 47 04 0F BF 48 2E"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 8B 07 8B B0 ? ? ? ? 8B 56 04 8B 4A 0C 89 4C 24 1C 7C 18"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(25), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 35 0F BF 46 2E"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 26 8B 85 40 0B 00 00"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 75 17 F3 0F 10 44 24 0C"); // EpisodicVehicleSupport (APC)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? F3 0F 10 15 ? ? ? ? 8B 35 ? ? ? ? F3 0F 11 54 24 ? 75 09"); // Weapon sounds sub_B5D970
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(27), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 7C 8B 35 ? ? ? ?"); // SHOTGUN_EXPLOSION sub_B5D970
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 F3 0F 10 05 ? ? ? ? F3 0F 11 44 24 20 75 4C"); // APC_EXPLOSION sub_B5D970
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(21), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 85 ? ? ? ? 84 C0"); // GRENADE_EXPLOSION sub_B5D970
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);
            
            pattern = hook::pattern("83 3D ? ? ? ? ? 57 7C 22"); // EpisodicVehicleSupport (APC) sounds
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(8), 2, true);
            
            pattern = hook::pattern("83 3D ? ? ? ? ? 75 09 83 BE ? ? ? ? ? 7F 26"); // EpisodicVehicleSupport (BUZZARD)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 58 0F BF 4E 2E 3B 0D ? ? ? ?"); // EpisodicVehicleSupport (BUZZARD)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 0F 8C ? ? ? ? 0F BF 46 2E 3B 05 ? ? ? ? 74 0C"); // EpisodicVehicleSupport (BUZZARD)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 6, true);
            
            pattern = hook::pattern("83 3D ? ? ? ? ? F3 0F 11 44 24 ? F3 0F 10 40 ? F3 0F 11 44 24 ? 0F 85 ? ? ? ?"); // EpisodicVehicleSupport (BUZZARD)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(24), 6, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 64 0F BF 46 2E 3B 05 ? ? ? ?"); // EpisodicVehicleSupport (BUZZARD & SWIFT)
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 89 44 24 38"); // EpisodicVehicleSupport (BUZZARD) sounds
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(11), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 11 8B 46 18 50 E8 ? ? ? ?"); // EpisodicVehicleSupport (BUZZARD) BULLET_IMPACT_WATER
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 43"); // EpisodicVehicleSupport (BUZZARD) weapon effects
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 1F 8B"); // EpisodicVehicleSupport (BUZZARD) minigun
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? 02 7C 11 8B 4E"); // EpisodicVehicleSupport (BUZZARD) minigun
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 7C 11 8B 4F 18 51 E8 ? ? ? ?"); // BUZZARD rubble effects
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("39 35 ? ? ? ? 75 0E 80 3D"); // EpisodicVehicleSupport Altimeter
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(6), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 5A 3B 05 ? ? ? ? 75 19"); // EpisodicVehicleSupport Boat models
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 3C 3B 05 ? ? ? ? 75 0A"); // EpisodicVehicleSupport Boat models
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("EB 61 3B 05 ? ? ? ? 75 0A F3 0F 10 05 ? ? ? ? EB 4F 3B 05 ? ? ? ? 75 0A F3 0F 10 05 ? ? ? ? EB 3D 83 3D ? ? ? ? ? 75 3C"); // EpisodicVehicleSupport Boat models
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(45), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 32 3B 05 ? ? ? ? 75 0A F3 0F 10 05 ? ? ? ?"); // EpisodicVehicleSupport Boat models
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 20 0F BF 56 2E 3B 15 ? ? ? ?"); // EpisodicVehicleSupport Floater camera
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 2C 3B 05 ? ? ? ? 0F 84 ? ? ? ?"); // EpisodicVehicleSupport Boat models
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("83 3D ? ? ? ? ? 75 28 3B 05 ? ? ? ? 74 C3 3B 05 ? ? ? ? 74 08 3B 05 ? ? ? ?"); // EpisodicVehicleSupport Boats
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(7), 2, true);

            pattern = hook::pattern("EB 31 83 3D ? ? ? ? ? 75 30 3B 05 ? ? ? ?"); // EpisodicVehicleSupport Boat models
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(9), 2, true);

            pattern = hook::pattern("3B 05 ? ? ? ? 74 EE 83 3D ? ? ? ? ? 75 28"); // EpisodicVehicleSupport Boat models
            if (!pattern.empty())
                injector::MakeNOP(pattern.get_first(15), 2, true);

        }

        /*pattern = hook::pattern("83 3D ? ? ? ? ? 8B F0 75 09"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(9), 2, true);

        pattern = hook::pattern("83 3D ? ? ? ? ? 0F 85 ? ? ? ? 6A 00 E8 ? ? ? ? 83 C4 04 83 F8 0A 0F 8C ? ? ? ?"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(7), 6, true);

        pattern = hook::pattern("83 3D ? ? ? ? ? 75 0D F6 05 ? ? ? ? ?"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(7), 2, true);

        pattern = hook::pattern("83 3D ? ? ? ? ? 75 70 F6 05 ? ? ? ? ?"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(7), 2, true);

        pattern = hook::pattern("83 3D ? ? ? ? ? 75 0D B8 ? ? ? ?"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(7), 2, true);

        pattern = hook::pattern("83 3D ? ? ? ? ? 75 0F F6 05 ? ? ? ? ?"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(7), 2, true);

        pattern = hook::pattern("8B 1D ? ? ? ? 85 DB 55 56 57 0F 85 ? ? ? ?"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(11), 6, true);

        pattern = hook::pattern("85 C9 0F B6 C0 75 20"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(5), 2, true);

        pattern = hook::pattern("83 C4 0C 83 3D ? ? ? ? ? 75 75"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(10), 2, true);

        pattern = hook::pattern("83 C4 0C 83 3D ? ? ? ? ? 75 54"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(10), 2, true);

        pattern = hook::pattern("85 D2 8B 40 04 75 0E"); // Achievement/Rank10 unlocks for all episodes
        if (!pattern.empty())
            injector::MakeNOP(pattern.get_first(5), 2, true);*/
    }

    return true;
}

uint32_t GetAnimGroupIdForModel(uint32_t modelHash, eAnimGroup animGroup)
{
    if(gAnimationOverrides.find(modelHash) != gAnimationOverrides.end())
    {
        if(animGroup == ANIMGRP_MOVE_RPG)
        {
            if(CAnimMgr__HasAnimLoaded(gAnimationOverrides[modelHash].RpgAnimGroupID))
            {
                return gAnimationOverrides[modelHash].RpgAnimGroupID;
            }
        }

        if(CAnimMgr__HasAnimLoaded(gAnimationOverrides[modelHash].RifleAnimGroupID))
        {
            return gAnimationOverrides[modelHash].RifleAnimGroupID;
        }
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