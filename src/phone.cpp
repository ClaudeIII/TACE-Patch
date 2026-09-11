#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cmath>
#include <cstdint>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Config.h"
#include "Log.h"
#include "Patterns.h"

// ============================================================================
// Run and sprint with the phone out.
//
// Holding the phone holds the player to a walk. The cellphone animations are
// not what does it: the phone task (CTaskComplexUseMobilePhone) only plays
// CellPHONE_in, then CellPHONE_talk, then CellPHONE_out from the "cellphone"
// anim group (7 standing, 8 crouched) as CTaskSimpleRunAnims, and puts the
// phone model in the ped's hand as its weapon object once CellPHONE_in reaches
// the grab.
//
// The limit is in the player's on-foot speed, which CTaskSimpleMovePlayer::
// process works out every frame from the stick (1.0 walk, 2.0 run, 3.0 sprint):
//
//     inHand = the weapon object's model is the ped's phone model
//     noRun  = inHand && !(multiplayer && OverrideNoSprintingOnPhoneInMultiplayer)
//     if ((m_bDisablePlayerSprint || noRun) && speed >= 1.0) speed = 1.0   // no sprint
//     ...and noRun takes full stick as 1.0 instead of 2.0                  // no run
//
// Rockstar's override only works in multiplayer. Here the phone test itself
// reads "not in hand" - one byte, the `mov bl,1` that records it - and both
// limits go with it. DISABLE_PLAYER_SPRINT is a separate flag and keeps
// working, so a mission that wants no sprinting still gets none.
//
// Answering a call on the move also stopped the player dead: with the sprint
// held throughout, the move state went 4 -> 1 -> 2 -> 3 -> 4, a standstill and
// ~0.75 s to build back up (Trace = phone). The move state just follows the
// ped's actual move blend (sub_8EA890), and two things zero that blend as the
// call's task (TASK_USE_MOBILE_PHONE -> CTaskComplexUseMobilePhoneAndMovement)
// starts:
//   - createFirstSubTask runs a CTaskSimpleStandStill once, on the stack;
//   - the task's CTaskComplexControlMovement starts on a
//     CTaskSimpleMoveDoNothing, whose process sets the move blend to 0 until
//     the phone task swaps in the player's real move task on its next step.
// For the player, both leave the movement alone - the DoNothing only while the
// phone task is running. (The DoNothing that runs is a copy of the one the
// task holds, so it cannot be matched by pointer: logged as "owned by the
// phone 0 | phone task present 1" at every call.) A DoNothing given for any
// other reason still stops the player, or a scripted scene would let him keep
// running.
// (Not the animations: playing CellPHONE_in, Cell_Text_to_Ear and
// CellPHONE_out upper-body only - anim flags 0x200001 - changed nothing.)
// ============================================================================

namespace
{
    // CPed / CPlayerInfo / task fields, the same in EFLC 1.1.2.0 and 1.0.8.0
    constexpr size_t kPedIntelligence = 0x224;
    constexpr size_t kPedPlayerInfo   = 0x228;   // null for anyone but the player
    constexpr size_t kPedFlags5       = 0x29C;   // 0x400 = the DoNothing leaves the move blend alone
    constexpr size_t kPedWeaponObject = 0x2DC;
    constexpr size_t kPedMoveState    = 0xB90;   // 1 still, 2 walk, 3 run, 4 sprint
    constexpr size_t kPhoneModelVfunc = 0x12C;   // CPed vtable: the ped's phone model
    constexpr size_t kIntelPrimary    = 0x44;    // CTaskManager's 5 primary task slots
    constexpr size_t kTaskSubTask     = 0x08;    // CTaskComplex::m_pSubTask
    constexpr int    kTypeUsePhone    = 1600;    // CTaskComplexUseMobilePhone
    constexpr size_t kInfoWanted      = 0x60;    // CWanted inside CPlayerInfo
    constexpr size_t kSprintStamina   = 0x3B4;   // floats read by the sprint-input code
    constexpr size_t kSprintLevel     = 0x3B8;
    constexpr size_t kSprintFlags     = 0x3D0;   // 0x1000 = sprint used up
    constexpr size_t kDisableSprint   = 0x414;   // m_bDisablePlayerSprint

    bool gTrace = false;

    template<typename T>
    T Field(const void *base, size_t offset)
    {
        return *reinterpret_cast<const T *>(static_cast<const uint8_t *>(base) + offset);
    }

    bool IsPlayer(uint8_t *ped)
    {
        return Field<void *>(ped, kPedPlayerInfo) != nullptr;
    }

    int TaskType(const void *task)
    {
        using GetTypeFn = int(__thiscall *)(const void *);
        return (*reinterpret_cast<GetTypeFn *const *>(task))[3](task);   // vtable +0x0C
    }

    // ---- the call-start standstill -----------------------------------------

    using StandStillFn = bool(__thiscall *)(void *task, void *ped);
    StandStillFn gStandStill = nullptr;

    bool __fastcall StandStillHook(void *task, void *, uint8_t *ped)
    {
        if (IsPlayer(ped))
        {
            if (gTrace)
                TaceLog("[phone] call start: the player's standstill passed over");
            return false;   // the player keeps moving into the call
        }
        return gStandStill(task, ped);
    }

    void KeepMovingIntoCalls()
    {
        // lea ecx,[esp+30h] ; mov byte [edi+2Ah],1 ; call <CTaskSimpleStandStill ctor> ;
        // push esi ; lea ecx,[esp+24h] ; call <CTaskSimpleStandStill::process> ; mov ecx,[<task pool>]
        auto pattern = find_pattern("8D 4C 24 30 C6 47 2A 01 E8 ? ? ? ? 56 8D 4C 24 24 E8 ? ? ? ? 8B 0D ? ? ? ? E8");
        if (pattern.empty())
        {
            TaceLog("[phone] call-start standstill: signature not found, not patched");
            return;
        }

        uint8_t *call = pattern.get_first<uint8_t>(18);
        if (*call != 0xE8)
        {
            TaceLog("[phone] ABORTED - the call-start standstill is not a call here. Not patched.");
            return;
        }

        gStandStill = reinterpret_cast<StandStillFn>(call + 5 + *reinterpret_cast<int32_t *>(call + 1));
        injector::MakeCALL(call, StandStillHook, true);
        TaceLog("[phone] OK - the player no longer stands still when a call starts");
    }

    // ---- the phone's DoNothing move task -----------------------------------

    using TaskProcessFn = bool(__thiscall *)(void *task, void *ped);
    TaskProcessFn gDoNothingProcess = nullptr;

    // Is the phone task in any of the ped's primary task chains? Walks them the
    // way CTaskManager::findPrimarySubTaskByID does.
    bool HasPhoneTask(uint8_t *ped)
    {
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (intel == nullptr)
            return false;
        for (int slot = 0; slot < 5; slot++)
            for (const void *t = Field<void *>(intel, kIntelPrimary + 4 * slot); t != nullptr;
                 t = Field<void *>(t, kTaskSubTask))
                if (TaskType(t) == kTypeUsePhone)
                    return true;
        return false;
    }

    // Run the game's own process with ped flags5 0x400 set - the flag it
    // already checks before zeroing the move blend - so everything else it does
    // (its timer, its return value) is untouched.
    bool __fastcall DoNothingProcessHook(void *task, void *, uint8_t *ped)
    {
        if (!IsPlayer(ped) || !HasPhoneTask(ped))
            return gDoNothingProcess(task, ped);

        uint32_t &flags5 = *reinterpret_cast<uint32_t *>(ped + kPedFlags5);
        const uint32_t had = flags5 & 0x400;
        flags5 |= 0x400;
        const bool done = gDoNothingProcess(task, ped);
        flags5 = (flags5 & ~0x400u) | had;

        if (gTrace)
            TaceLog("[phone] call start: the phone's stand-in move task kept the player's movement");
        return done;
    }

    void KeepMovementThroughPhoneTask()
    {
        // CTaskSimpleMoveDoNothing::process: count down its timer, then
        // `if (!(ped flags5 & 0x400)) moveBlend->vfunc[0x50](0)` - the zeroing
        auto pattern = find_pattern("8B 51 20 83 EC 0C 85 D2 7E 43 D9 05 ? ? ? ? 56 D8 0D ? ? ? ? D9 7C 24 06 "
                                    "0F B7 44 24 06 0D 00 0C 00 00 89 44 24 08 8B C2 D9 6C 24 08 DF 7C 24 08 "
                                    "8B 74 24 08 2B C6 85 C0 D9 6C 24 06 89 41 20 5E 7F 08 B0 01 83 C4 0C C2 04 00 "
                                    "8B 44 24 10 F7 80 9C 02 00 00 00 04 00 00 75 0F 8B 88 90 0A 00 00 8B 01 8B 50 50 "
                                    "6A 00 FF D2 32 C0");
        if (pattern.empty())
        {
            TaceLog("[phone] phone move stand-in: signature not found, not patched");
            return;
        }
        const uint32_t process = uint32_t(uintptr_t(pattern.get_first<void>(0)));

        // Its one vtable slot: the function's address as data, outside the code.
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
                if (*p == process && found++ == 0)
                    slot = p;
        }
        if (found != 1)
        {
            TaceLog("[phone] ABORTED - the phone move stand-in has %d vtable slots, expected 1. Not patched.", found);
            return;
        }

        gDoNothingProcess = reinterpret_cast<TaskProcessFn>(uintptr_t(process));
        injector::WriteMemory<uint32_t>(slot, uint32_t(uintptr_t(&DoNothingProcessHook)), true);
        TaceLog("[phone] OK - answering a call keeps the player's momentum");
    }

    // ---- trace: the player's speed around a phone call (Trace = phone) -----

    using RequestedSpeedFn = float(__thiscall *)(void *ped, int a2, int a3);
    RequestedSpeedFn gRequestedSpeed = nullptr;

    bool PhoneInHand(uint8_t *ped)
    {
        const uint8_t *object = Field<uint8_t *>(ped, kPedWeaponObject);
        if (object == nullptr)
            return false;
        using ModelFn = int(__thiscall *)(void *);
        const ModelFn phoneModel = (*reinterpret_cast<ModelFn **>(ped))[kPhoneModelVfunc / 4];
        return Field<int16_t>(object, 0x2E) == phoneModel(ped);
    }

    // Observation only: the speed goes back to the game unchanged.
    float __fastcall RequestedSpeedHook(uint8_t *ped, void *, int a2, int a3)
    {
        const float speed = gRequestedSpeed(ped, a2, a3);
        if (!IsPlayer(ped))
            return speed;
        const uint8_t *wanted = Field<uint8_t *>(ped, kPedPlayerInfo) + kInfoWanted;

        const bool  inHand    = PhoneInHand(ped);
        const int   moveState = Field<int>(ped, kPedMoveState);
        const float stamina   = Field<float>(wanted, kSprintStamina);
        const float level     = Field<float>(wanted, kSprintLevel);
        const bool  usedUp    = (Field<uint32_t>(wanted, kSprintFlags) & 0x1000) != 0;
        const bool  disabled  = Field<uint8_t>(wanted, kDisableSprint) != 0;

        // Log changes, plus five lines a second while the phone is out.
        static float lastSpeed = -1.0f;
        static bool  lastInHand = false;
        static int   lastMoveState = -1;
        static DWORD lastTick = 0;
        const DWORD now = GetTickCount();
        const bool changed = std::fabs(speed - lastSpeed) >= 0.25f || inHand != lastInHand || moveState != lastMoveState;
        if (changed || (inHand && now - lastTick >= 200))
        {
            TaceLog("[phone] speed asked %.2f | phone in hand %d | move state %d | sprint %.2f/%.2f%s%s",
                    speed, inHand, moveState, level, stamina, usedUp ? " | USED UP" : "",
                    disabled ? " | SPRINT DISABLED" : "");
            lastSpeed = speed;
            lastInHand = inHand;
            lastMoveState = moveState;
            lastTick = now;
        }
        return speed;
    }
}

void Phone_Init()
{
    const bool run = TaceIniBool("PHONE", "RunWithPhone", true);
    gTrace = TaceTraceEnabled("phone");
    if (!run)
        TaceLog("[phone] RunWithPhone = 0 - walking with the phone out, as vanilla");
    if (!run && !gTrace)
        return;

    // mov eax,[edx+12Ch] ; mov ecx,esi ; call eax      <- the ped's phone model
    // cmp ebx,eax ; jnz ; mov bl,1 ; jmp ; xor bl,bl   <- bl = phone in hand
    // ... call <requested speed> ; fstp ; test bl,bl ; mov al,[<multiplayer override>]
    auto pattern = find_pattern("8B 82 2C 01 00 00 8B CE FF D0 3B D8 75 04 B3 01 EB 02 32 DB "
                                "8B 4C 24 18 51 6A 00 8B CE E8 ? ? ? ? D9 5C 24 18 84 DB A0");
    if (pattern.empty())
    {
        TaceLog("[phone] phone walk limit: signature not found, not patched");
    }
    else
    {
        if (run)
        {
            uint8_t *inHand = pattern.get_first<uint8_t>(15);   // the 1 of mov bl,1
            if (*inHand != 1)
            {
                TaceLog("[phone] ABORTED - the phone-in-hand flag reads %u, expected 1. Not patched.", *inHand);
            }
            else
            {
                injector::WriteMemory<uint8_t>(inHand, 0, true);
                TaceLog("[phone] OK - walk, run and sprint with the phone out");
            }
        }

        if (gTrace)
        {
            uint8_t *call = pattern.get_first<uint8_t>(29);   // call <requested speed>
            gRequestedSpeed = reinterpret_cast<RequestedSpeedFn>(call + 5 + *reinterpret_cast<int32_t *>(call + 1));
            injector::MakeCALL(call, RequestedSpeedHook, true);
            TaceLog("[phone] trace armed - the player's requested speed is logged while the phone is out");
        }
    }

    if (run)
    {
        KeepMovingIntoCalls();
        KeepMovementThroughPhoneTask();
    }
}
