#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cmath>
#include <cstdint>
#include <intrin.h>

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

    // ---- phone in cover ----------------------------------------------------
    //
    // Cover put the phone away, and kept it from coming out. Not the engine: the
    // phone scripts (spcellphone*) check IS_PLAYER_FREE_FOR_AMBIENT_TASK every
    // frame - "PHONE CHECK - player is not free for an ambient task and is not
    // in a car" in their own debug text - and cover reads as busy. The native
    // walks the ped's task-info list (intelligence +0x2E0) and has one caller,
    // its wrapper. For phone checks alone (the phone scripts', InPhoneCheck's),
    // a player whose only running task tree is his on-foot one, in cover, now
    // reads as free. (The phone-in-hand pose while browsing comes from
    // CTaskComplexPlayerIdles, which does not run in cover. Calls are below.)

    constexpr int    kTypePlayerInCover = 1046;    // CTaskComplexPlayerInCover
    constexpr size_t kIntelTaskInfo     = 0x2E0;   // the task-info list the native walks
    constexpr size_t kIntelSecondary    = 0x58;    // CPedTasks (+0x44) +0x14: 6 secondary task slots
    constexpr int    kTypeNewUseCover   = 1054;    // CTaskComplexNewUseCover, cover's own state machine
    constexpr size_t kUseCoverState     = 0x38;    // its state; 22 = leave
    constexpr size_t kPlayerPed         = 0x58C;   // CPlayer -> ped

    bool gPhoneInCover     = false;
    bool gPhoneIntoVehicle = false;
    bool gCoverInCalls     = false;   // take cover during a call
    bool gVehiclesInCalls  = false;   // get into a vehicle during a call

    using FreeForAmbientFn = bool(__cdecl *)(int player);
    using PlayerByNumFn    = uint8_t *(__cdecl *)(int player);
    using RunningThreadFn  = void *(__cdecl *)();
    using ScriptNameFn     = const char *(__thiscall *)(void *thread);
    FreeForAmbientFn gFreeForAmbient = nullptr;
    PlayerByNumFn    gPlayerByNum    = nullptr;
    RunningThreadFn  gRunningThread  = nullptr;
    ScriptNameFn     gScriptName     = nullptr;

    uint8_t *CallTarget(uint8_t *call)
    {
        return call + 5 + *reinterpret_cast<int32_t *>(call + 1);
    }

    template<typename F>
    void ForEachExecSection(F visit)
    {
        auto *mod = reinterpret_cast<uint8_t *>(GetModuleHandleA(nullptr));
        auto *nt  = reinterpret_cast<IMAGE_NT_HEADERS *>(mod + reinterpret_cast<IMAGE_DOS_HEADER *>(mod)->e_lfanew);
        const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
            if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) && sec->Misc.VirtualSize >= 5)
                visit(mod + sec->VirtualAddress, size_t(sec->Misc.VirtualSize));
    }

    // Every `call rel32` to target in the game's code: returns how many, keeps
    // the first max.
    // How many call sites of one function the callers below can record. Each of
    // them patches every site it finds, so a count outside what the known builds
    // hold is reported rather than assumed.
    constexpr int kMaxEntrySites = 8;

    int CallersOf(const uint8_t *target, uint8_t **sites, int max)
    {
        int count = 0;
        ForEachExecSection([&](uint8_t *begin, size_t size) {
            for (uint8_t *p = begin, *end = begin + size - 5; p <= end; p++)
                if (*p == 0xE8 && CallTarget(p) == target)
                {
                    if (count < max)
                        sites[count] = p;
                    count++;
                }
        });
        return count;
    }

    bool IsPhoneScript(const char *name)
    {
        static const char prefix[] = "spcellphone";
        for (size_t i = 0; i + 1 < sizeof(prefix); i++)
            if (name[i] == '\0' || (name[i] | 0x20) != prefix[i])
                return false;
        return true;
    }

    // In cover and nothing outranks it: every task slot above the default one
    // (CTaskComplexPlayerOnFoot) empty, and CTaskComplexPlayerInCover in that.
    bool OnlyInCover(uint8_t *ped)
    {
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (intel == nullptr)
            return false;
        for (int slot = 0; slot < 4; slot++)
            if (Field<void *>(intel, kIntelPrimary + 4 * slot) != nullptr)
                return false;
        for (const void *t = Field<void *>(intel, kIntelPrimary + 4 * 4); t != nullptr; t = Field<void *>(t, kTaskSubTask))
            if (TaskType(t) == kTypePlayerInCover)
                return true;
        return false;
    }

    // On foot and nothing outranks it: his default task (CTaskComplexPlayerOnFoot)
    // is the only one running. A stock call puts its task above it, which is why
    // he could neither take cover nor get into a vehicle until it ended; with
    // CoverInCalls or VehiclesInCalls a call from here runs beside it, as in
    // cover (whichever is off stays held back, HoldEntriesDuringCalls).
    constexpr int    kTypePlayerOnFoot  = 4;       // CTaskComplexPlayerOnFoot
    constexpr size_t kPedFlagsInVehicle = 0x26C;   // & 4: in a vehicle (what the phone set picker tests)

    bool OnFootOnly(const uint8_t *ped)
    {
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (intel == nullptr || (Field<uint8_t>(ped, kPedFlagsInVehicle) & 4) != 0)
            return false;
        for (int slot = 0; slot < 4; slot++)
            if (Field<void *>(intel, kIntelPrimary + 4 * slot) != nullptr)
                return false;
        const void *top = Field<void *>(intel, kIntelPrimary + 4 * 4);
        return top != nullptr && TaskType(top) == kTypePlayerOnFoot;
    }

    // The same question closed the phone every time he got into a vehicle: "not
    // free and not in a car" holds all the way through getting in (the idle task
    // has stopped, he is not seated yet). Getting out he is in the car until he
    // is out, so the phone stayed. With PhoneIntoVehicle he reads as free while
    // CTaskComplexNewGetInVehicle runs.
    constexpr int kTypeGetInVehicle = 734;   // CTaskComplexNewGetInVehicle

    bool EnteringVehicle(const uint8_t *ped)
    {
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (intel == nullptr)
            return false;
        for (int slot = 0; slot < 5; slot++)
            for (const void *t = Field<void *>(intel, kIntelPrimary + 4 * slot); t != nullptr;
                 t = Field<void *>(t, kTaskSubTask))
                if (TaskType(t) == kTypeGetInVehicle)
                    return true;
        return false;
    }

    // CTaskComplexNewUseCover's state, or -1 when it is not running
    int CoverState(const uint8_t *ped)
    {
        int state = -1;
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        for (const void *t = intel != nullptr ? Field<void *>(intel, kIntelPrimary + 4 * 4) : nullptr; t != nullptr;
             t = Field<void *>(t, kTaskSubTask))
            if (TaskType(t) == kTypeNewUseCover)
                state = Field<int>(t, kUseCoverState);
        return state;
    }

    // "slots - - - - 8>1046>... | info 1054/2 ..." for the trace
    void DescribeTasks(uint8_t *ped, char *buf, size_t size)
    {
        size_t used = 0;
        auto add = [&](const char *format, int a, unsigned b) {
            if (used + 1 >= size)
                return;
            const int n = snprintf(buf + used, size - used, format, a, b);
            if (n > 0)
                used = (std::min)(size - 1, used + size_t(n));
        };
        buf[0] = '\0';
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (intel == nullptr)
            return;
        add("slots", 0, 0);
        for (int slot = 0; slot < 5; slot++)
        {
            const void *t = Field<void *>(intel, kIntelPrimary + 4 * slot);
            add(t != nullptr ? " " : " -", 0, 0);
            for (int depth = 0; t != nullptr && depth < 8; t = Field<void *>(t, kTaskSubTask), depth++)
                add(depth != 0 ? ">%d" : "%d", TaskType(t), 0);
        }
        add(" | side", 0, 0);
        for (int slot = 0; slot < 6; slot++)
        {
            const void *t = Field<void *>(intel, kIntelSecondary + 4 * slot);
            if (t != nullptr)
                add(" %d:", slot, 0);
            for (int depth = 0; t != nullptr && depth < 8; t = Field<void *>(t, kTaskSubTask), depth++)
                add(depth != 0 ? ">%d" : "%d", TaskType(t), 0);
        }
        add(" | info", 0, 0);
        const uint8_t *info = Field<uint8_t *>(intel, kIntelTaskInfo);
        for (int i = 0; info != nullptr && i < 16; info = Field<uint8_t *>(info, 0x0C), i++)
            add(" %d/%u", Field<int>(info, 0x04), (Field<uint32_t>(info, 0x08) >> 1) & 7);
    }

    void CheckSideCall(uint8_t *ped);         // calls in cover, below
    void TextPoseInCover(uint8_t *ped);       // the texting pose in cover, below

    // The story, friend and date scripts run the same phone check as the phone's
    // own scripts before they call the player - in base IV 71 of the 117 scripts
    // asking IS_PLAYER_FREE_FOR_AMBIENT_TASK carry it - so in cover their calls
    // waited until he left it. In every copy the check asks NETWORK_HAVE_SUMMONS
    // 310 bytecode bytes before it asks whether he is free; the other 46 (vendors,
    // ATMs, pool, taxis...) never do. So a thread that has just asked
    // NETWORK_HAVE_SUMMONS is running a phone check, and gets the phone scripts'
    // answer. The mark is used up by the next free-for-ambient question.
    using SummonsFn = bool(__cdecl *)();
    SummonsFn   gSummons       = nullptr;
    const void *gSummonsThread = nullptr;
    DWORD       gSummonsAt     = 0;

    bool __cdecl SummonsHook()
    {
        gSummonsThread = gRunningThread();
        gSummonsAt     = GetTickCount();
        return gSummons();
    }

    bool InPhoneCheck(const void *thread)
    {
        const bool yes = thread != nullptr && thread == gSummonsThread && GetTickCount() - gSummonsAt <= 50;
        gSummonsThread = nullptr;
        return yes;
    }

    bool __cdecl FreeForAmbientHook(int player)
    {
        const bool game = gFreeForAmbient(player);
        const uint8_t *playerInfo = gPlayerByNum(player);
        uint8_t *ped = playerInfo != nullptr ? Field<uint8_t *>(playerInfo, kPlayerPed) : nullptr;
        if (ped != nullptr)
        {
            CheckSideCall(ped);   // the phone scripts ask every frame
            TextPoseInCover(ped);
        }
        void *thread = gRunningThread();
        const bool check = InPhoneCheck(thread);   // uses the mark up either way
        if (game && !gTrace)
            return true;

        const char *script = thread != nullptr ? gScriptName(thread) : nullptr;
        if (ped == nullptr || script == nullptr || !(check || IsPhoneScript(script)))
            return game;

        const bool cover    = OnlyInCover(ped);
        const bool entering = gPhoneIntoVehicle && EnteringVehicle(ped);
        const bool answer   = game || (gPhoneInCover && cover) || entering;

        if (gTrace)
        {
            // Changes only - the phone scripts ask every frame.
            static int last = -1;
            const int state = int(game) | int(cover) << 1 | int(answer) << 2 | int(entering) << 3 | int(check) << 4;
            if (state != last)
            {
                last = state;
                char tasks[400];
                DescribeTasks(ped, tasks, sizeof(tasks));
                TaceLog("[phone] %s%s: free for an ambient task? game %s, in cover %d, getting in a vehicle %d -> %s | %s",
                        script, check && !IsPhoneScript(script) ? " (phone check)" : "", game ? "yes" : "no", cover,
                        entering, answer ? "yes" : "no", tasks);
            }
        }
        return answer;
    }

    void KeepPhoneInCover()
    {
        // IS_PLAYER_FREE_FOR_AMBIENT_TASK: push player ; call CPlayer::getPlayerByNum ;
        // mov eax,[eax+58Ch] ; mov ecx,[eax+224h] ; mov edi,[ecx+2E0h] ...
        auto freeCheck = find_pattern("55 8B 6C 24 08 56 57 55 E8 ? ? ? ? 8B 80 8C 05 00 00 8B 88 24 02 00 00 "
                                      "8B B9 E0 02 00 00 81 C1 E0 02 00 00 8B D7 83 C4 04 85 D2 74 2B");
        // _assignScriptComandToPed: ... call GtaThread::getRunningThread ; cmp byte [eax+9Eh],0
        auto assign = find_pattern("8B 44 24 04 83 EC 18 85 C0 0F 84 ? ? ? ? 8B 0D ? ? ? ? 56 57 50 E8 ? ? ? ? "
                                   "8B F0 33 FF E8 ? ? ? ? 80 B8 9E 00 00 00 00");
        // rage::scrThread::getScriptName - its program's name, by the hash at +8
        auto name = find_pattern("56 8B 71 08 E8 ? ? ? ? 85 C0 74 09 E8 ? ? ? ? 8B 00 5E C3");
        if (freeCheck.empty() || assign.empty() || name.empty())
        {
            TaceLog("[phone] phone in cover: signature not found, not patched");
            return;
        }

        // Its one caller is the native's wrapper, n_IS_PLAYER_FREE_FOR_AMBIENT_TASK.
        uint8_t *impl = freeCheck.get_first<uint8_t>(0);
        uint8_t *site = nullptr;
        const int sites = CallersOf(impl, &site, 1);
        if (sites != 1)
        {
            TaceLog("[phone] ABORTED - IS_PLAYER_FREE_FOR_AMBIENT_TASK has %d callers, expected 1. Not patched.", sites);
            return;
        }

        gFreeForAmbient = reinterpret_cast<FreeForAmbientFn>(impl);
        gPlayerByNum    = reinterpret_cast<PlayerByNumFn>(CallTarget(freeCheck.get_first<uint8_t>(8)));
        gRunningThread  = reinterpret_cast<RunningThreadFn>(CallTarget(assign.get_first<uint8_t>(33)));
        gScriptName     = reinterpret_cast<ScriptNameFn>(name.get_first<void>(0));
        injector::MakeCALL(site, FreeForAmbientHook, true);

        // NETWORK_HAVE_SUMMONS - registered as push <native> ; push 48726B45h (its hash) ; call <register>.
        // The native: call <impl> ; mov ecx,[esp+4] ; mov edx,[ecx] ; movzx eax,al ; mov [edx],eax ; ret
        auto summons = find_pattern("68 ? ? ? ? 68 45 6B 72 48 E8");
        uint8_t *native = summons.empty() ? nullptr : *summons.get_first<uint8_t *>(1);
        static const uint8_t tail[] = { 0x8B, 0x4C, 0x24, 0x04, 0x8B, 0x11, 0x0F, 0xB6, 0xC0, 0x89, 0x02, 0xC3 };
        bool shaped = native != nullptr && native[0] == 0xE8;
        for (size_t i = 0; shaped && i < sizeof(tail); i++)
            shaped = native[5 + i] == tail[i];
        if (shaped)
        {
            gSummons = reinterpret_cast<SummonsFn>(CallTarget(native));
            injector::MakeCALL(native, SummonsHook, true);
            TaceLog("[phone] OK - story, friend and date calls come through in cover too (their phone check is recognised)");
        }
        else
        {
            TaceLog("[phone] calls to the player in cover: NETWORK_HAVE_SUMMONS not found - only the phone's own scripts see cover as free");
        }
        if (gPhoneInCover)
            TaceLog("[phone] OK - the phone stays up in cover");
        if (gPhoneIntoVehicle)
            TaceLog("[phone] OK - the phone stays open getting into a vehicle");
        if (gTrace)
            TaceLog("[phone] trace armed - the phone scripts' free-for-ambient-task checks are logged");
    }

    // ---- the phone key in cover -------------------------------------------
    //
    // Pressing the phone key (control 21) in cover was itself an exit: the
    // player branch of CTaskComplexNewUseCover's "leave?" check (EFLC
    // sub_ADA360, request 22) falls through to "leave" when it is just pressed
    // and he is not peeking - the stock game stood him up to use the phone
    // (Trace = phone: "cover state 22 | just pressed: 21 ..." at every try).
    // With the phone allowed in cover, that press no longer counts there.

    bool __fastcall PhoneKeyInCoverHook(const uint8_t *control)
    {
        if (gTrace && uint8_t(control[4] ^ control[6]) > 0x7F && uint8_t(control[4] ^ control[7]) <= 0x7F)
            TaceLog("[phone] phone key in cover: stayed in cover");
        return false;
    }

    void KeepCoverOnPhoneKey()
    {
        // mov ebx,[edi+38h] (cover state) ; cmp ebx,5 (peeking) ; jz ; mov ecx,<pad> ; add ecx,27E8h ;
        // call <just pressed> ; test al,al ; jz ; ... xor dl,[eax+280Ch]   <- control 21, then 23 held
        auto check = find_pattern("8B 5F 38 83 FB 05 74 ? 8B 4C 24 ? 81 C1 E8 27 00 00 E8 ? ? ? ? 84 C0 74 ? "
                                  "8B 44 24 ? 8A 90 0E 28 00 00 32 90 0C 28 00 00 80 FA 7F");
        if (check.empty())
        {
            TaceLog("[phone] phone key in cover: signature not found, not patched");
            return;
        }
        uint8_t *call = check.get_first<uint8_t>(18);
        if (*call != 0xE8)
        {
            TaceLog("[phone] ABORTED - the phone-key check is not a call here. Not patched.");
            return;
        }
        injector::MakeCALL(call, PhoneKeyInCoverHook, true);
        TaceLog("[phone] OK - the phone key no longer takes the player out of cover");
    }

    // ---- calls in cover ----------------------------------------------------
    //
    // A call's task (TASK_USE_MOBILE_PHONE -> CTaskComplexUseMobilePhoneAndMovement)
    // takes the primary task slot, above the on-foot tree cover lives in, so a
    // call stood the player up (Trace = phone: "leaving cover - made abortable"
    // at every call start). In cover, the phone task itself
    // (CTaskComplexUseMobilePhone) now runs in secondary slot 4 instead - the
    // slot TASK_PLAY_ANIM_SECONDARY uses; the task manager runs complex
    // secondary tasks like primary ones - and cover keeps the primary tree.
    // The calling script (spcellphonecalling) only sees the phone through three
    // natives, each taught about the secondary slot:
    //   - GET_SCRIPT_TASK_STATUS(player, 53): 7 or 2 means the phone task is
    //     over. Answers 1 (performing) while ours runs, 7 once it has gone.
    //   - GET_MOBILE_PHONE_TASK_SUB_TASK: the script waits for 1 (phone at the
    //     ear); the native searched the primary and move slots only.
    //   - TASK_USE_MOBILE_PHONE(player, 0): hangs up by setting the phone task's
    //     finish flag, and only looked for it in the primary slot.
    // While it runs, the phone animations (cellphone ids 10-13) play on his
    // head, neck and right arm only (bone mask 10, below) and in blend group 4
    // instead of 3. The group is the third field of an animation's definition
    // ({id, flags, blend group}), and starting an animation blends out every
    // other one in its group (EFLC sub_9D8340) - most cover animations are
    // group 3 too, so the phone and cover blended each other out. Group 4 is
    // the overlay group - door opening, drive-by fire, hit flinches, the
    // rifle's wall-block idle.

    constexpr int      kCmdUsePhone = 53;         // TASK_USE_MOBILE_PHONE's script command
    constexpr int      kPhoneSlot   = 4;          // the secondary slot TASK_PLAY_ANIM_SECONDARY uses
    constexpr size_t   kPhoneFinish = 0x29;       // CTaskComplexUseMobilePhone: put the phone away

    using TaskUsePhoneFn = int(__cdecl *)(unsigned ped, int use);
    using ScriptStatusFn = int(__cdecl *)(uint8_t *ped, int command);
    using FindTaskFn     = void *(__thiscall *)(void *intel, unsigned type);
    using AtHandleFn     = uint8_t *(__thiscall *)(void *pool, unsigned handle);
    using AllocateFn     = void *(__thiscall *)(void *pool);
    using PhoneCtorFn    = void *(__thiscall *)(void *task, int duration);
    using SetSecondaryFn = void(__thiscall *)(void *tasks, void *task, int slot);
    using IsDuckingFn    = bool(__thiscall *)(const void *ped);
    using AbortFn        = bool(__thiscall *)(void *task, void *ped, int priority, void *event);
    using AssignTaskFn   = void(__thiscall *)(void *tasks, void *task, unsigned slot, unsigned flag);
    IsDuckingFn    gIsDucking     = nullptr;   // CPed::isDucking
    AssignTaskFn   gAssignTask    = nullptr;   // CTaskManager::assignTask
    TaskUsePhoneFn gTaskUsePhone  = nullptr;
    ScriptStatusFn gScriptStatus  = nullptr;
    FindTaskFn     gFindPhoneTask = nullptr;
    AtHandleFn     gAtHandle      = nullptr;
    AllocateFn     gAllocate      = nullptr;
    PhoneCtorFn    gPhoneCtor     = nullptr;
    SetSecondaryFn gSetSecondary  = nullptr;
    void         **gPedPool       = nullptr;   // &CPed::ms_pPool
    void         **gTaskPool      = nullptr;   // &CTask::ms_pPool

    uint32_t *gPhoneAnimFlags[10]      = {};   // cellphone anims 10-14, groups 7 and 8
    uint32_t  gPhoneAnimStock[10]      = {};
    uint32_t *gPhoneAnimBlend[10]      = {};   // their blend groups
    uint32_t  gPhoneAnimBlendStock[10] = {};
    int       gPhoneAnims              = 0;

    enum class SideCall { None, Running, Over };
    SideCall gSideCall = SideCall::None;
    bool     gTextPose = false;   // the texting pose is up in cover (below)
    bool     gCallInPrimary = false;   // moved to primary slot 3 in a vehicle (MoveCallIntoVehicle)
    void    *gParkedCall    = nullptr; // paused for vehicle animations, in no slot (ParkCallForVehicleAnims)
    constexpr int kScriptSlot = 3;     // the primary slot a script's task goes into

    void *SecondaryTask(const uint8_t *intel, int type)
    {
        if (intel == nullptr)
            return nullptr;
        for (int slot = 0; slot < 6; slot++)
            for (void *t = Field<void *>(intel, kIntelSecondary + 4 * slot); t != nullptr; t = Field<void *>(t, kTaskSubTask))
                if (TaskType(t) == type)
                    return t;
        return nullptr;
    }

    void *SidePhone(const uint8_t *ped)
    {
        if (gParkedCall != nullptr)
            return gParkedCall;
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (void *phone = SecondaryTask(intel, kTypeUsePhone))
            return phone;
        if (gCallInPrimary && intel != nullptr)
            for (void *t = Field<void *>(intel, kIntelPrimary + 4 * kScriptSlot); t != nullptr; t = Field<void *>(t, kTaskSubTask))
                if (TaskType(t) == kTypeUsePhone)
                    return t;
        return nullptr;
    }

    constexpr uint32_t kPhoneBlendGroup = 4;   // the overlay group; cover's poses are 3 (and 2)

    // The low 4 bits of an animation's flags pick its bone mask (EFLC
    // sub_9D65D0 gives it a crFrameFilterBoneMask of that value) - an index
    // into the BONEMASK_* list, not a set of bits: 1 UPPERONLY (the cover
    // weapon idles), 8 HEAD_NECK_AND_ARMS (the stock standing phone set), 9
    // HEAD_NECK_AND_L_ARM, 10 HEAD_NECK_AND_R_ARM (the in-car phone set and
    // CellPHONE_text), 11 LOD_LO. OR-ing flags into it had turned 8 into 9 -
    // the left arm, so the phone never reached his ear in high cover - then
    // into 11, which moved his hips: sitting in mid-air in low cover. A call in
    // cover gets 10, the in-car phone's mask - its left hand stays on the
    // wheel, here on the cover.
    constexpr uint32_t kBoneMaskBits = 0xF;
    constexpr uint32_t kHeadNeckRArm = 10;

    void UpperBodyPhoneAnims(bool on)
    {
        for (int i = 0; i < gPhoneAnims; i++)
        {
            injector::WriteMemory<uint32_t>(gPhoneAnimFlags[i],
                                            on ? (gPhoneAnimStock[i] & ~kBoneMaskBits) | kHeadNeckRArm : gPhoneAnimStock[i],
                                            true);
            injector::WriteMemory<uint32_t>(gPhoneAnimBlend[i], on ? kPhoneBlendGroup : gPhoneAnimBlendStock[i], true);
        }
    }

    // Every live animation on the ped, as " id:blend group:flags w<weight> p<phase>"
    // - what the phone and cover are really playing. Ped +0x78 -> CAnimBlender,
    // +0x1A28 -> first node; node +0x8C next, +0x48 == 1 live, +4 the player:
    // +4 flags, +8 blend group, +0x0C anim id, +0x34 weight, +0x4C phase.
    void DescribeAnims(const uint8_t *ped, char *buf, size_t size)
    {
        size_t used = 0;
        buf[0] = '\0';
        const uint8_t *blender = Field<uint8_t *>(ped, 0x78);
        const uint8_t *node = blender != nullptr ? Field<uint8_t *>(blender, 0x1A28) : nullptr;
        for (int n = 0; node != nullptr && n < 32 && used + 48 < size; node = Field<uint8_t *>(node, 0x8C), n++)
        {
            if (Field<uint16_t>(node, 0x48) != 1)
                continue;
            const uint8_t *anim = node + 4;
            if (Field<void *>(anim, 0x40) == nullptr)
                continue;
            const float weight = (std::max)(-9.0f, (std::min)(9.0f, Field<float>(anim, 0x34)));
            const float phase  = (std::max)(-9.0f, (std::min)(9.0f, Field<float>(anim, 0x4C)));
            const int n2 = snprintf(buf + used, size - used, " %d:%u:%X w%.2f p%.2f", Field<int>(anim, 0x0C),
                                    Field<uint32_t>(anim, 0x08), Field<uint32_t>(anim, 0x04), weight, phase);
            if (n2 > 0)
                used = (std::min)(size - 1, used + size_t(n2));
        }
    }

    float PedZ(const uint8_t *ped)
    {
        const uint8_t *matrix = Field<uint8_t *>(ped, 0x20);
        return matrix != nullptr ? Field<float>(matrix, 0x38) : 0.0f;
    }

    void MoveCallIntoVehicle(uint8_t *ped, void *phone);   // a call that goes on into a vehicle, below
    void KeepPhoneInHand(uint8_t *ped, const void *phone);  // a jacking took the phone, below
    void ParkCallForVehicleAnims(uint8_t *ped, void *phone); // the call pauses for vehicle animations, below
    void EndStrayTextPose(uint8_t *ped, const void *idleSub); // CellPHONE_text left playing, below

    void CheckSideCall(uint8_t *ped)
    {
        if (gSideCall != SideCall::Running)
            return;
        void *phone = SidePhone(ped);
        if (gTrace)
        {
            // Each step of the call (1602 phone in, 1601 at the ear, 1603 phone
            // out), each change in crouching, and the first 1.5 s of every step
            // every 150 ms - with his height and every animation playing
            static int lastStep = -1, lastDucking = -1, lastCover = -2;
            static DWORD stepStart = 0, lastSample = 0;
            const void *step = phone != nullptr ? Field<void *>(phone, kTaskSubTask) : nullptr;
            const int type = step != nullptr ? TaskType(step) : 0;
            const int ducking = gIsDucking != nullptr ? int(gIsDucking(ped)) : -1;
            const int cover = CoverState(ped);
            const DWORD now = GetTickCount();
            if (type != lastStep)
                stepStart = now;
            if (type != lastStep || ducking != lastDucking || cover != lastCover
                || (now - stepStart < 1500 && now - lastSample >= 150))
            {
                const bool newStep = type != lastStep;
                lastStep = type;
                lastDucking = ducking;
                lastCover = cover;
                lastSample = now;
                char anims[480];
                DescribeAnims(ped, anims, sizeof(anims));
                TaceLog("[phone] call in cover: step %d | ducking %d | cover state %d | z %.2f | anims%s",
                        type, ducking, cover, PedZ(ped), anims);
                if (newStep)
                {
                    char tasks[400];
                    DescribeTasks(ped, tasks, sizeof(tasks));
                    TaceLog("[phone] call in cover: step %d | %s", type, tasks);
                }
            }
        }
        if (phone != nullptr)
        {
            EndStrayTextPose(ped, nullptr);   // no CellPHONE_text under the call, on foot or in cover
            ParkCallForVehicleAnims(ped, phone);
            if (gParkedCall == nullptr)
            {
                MoveCallIntoVehicle(ped, phone);
                KeepPhoneInHand(ped, phone);
            }
            return;
        }
        gSideCall = SideCall::Over;
        gCallInPrimary = false;
        gParkedCall = nullptr;
        UpperBodyPhoneAnims(gTextPose);
        if (gTrace)
            TaceLog("[phone] call in cover: the phone task is over");
    }

    bool StartSideCall(uint8_t *ped)
    {
        void *task = gAllocate(*gTaskPool);
        if (task == nullptr)
            return false;
        gPhoneCtor(task, -1);        // untimed, like the script's own
        UpperBodyPhoneAnims(true);   // before it starts CellPHONE_in
        gSetSecondary(Field<uint8_t *>(ped, kPedIntelligence) + kIntelPrimary, task, kPhoneSlot);
        if (SidePhone(ped) == nullptr)
        {
            UpperBodyPhoneAnims(gTextPose);
            TaceLog("[phone] call in cover: the phone task did not take - the call stands him up as before");
            return false;
        }
        gSideCall = SideCall::Running;
        gCallInPrimary = false;
        gParkedCall = nullptr;
        if (gTrace)
            TaceLog("[phone] call in cover: the phone task runs beside %s (secondary slot %d)",
                    OnlyInCover(ped) ? "cover" : "the on-foot tree", kPhoneSlot);
        return true;
    }

    int __cdecl TaskUsePhoneHook(unsigned handle, int use)
    {
        uint8_t *ped = gAtHandle(*gPedPool, handle);
        const bool player = ped != nullptr && IsPlayer(ped);
        if ((use & 0xFF) != 0 && player)
        {
            if (SidePhone(ped) != nullptr)
                return 0;   // already on the phone beside cover
            if ((OnlyInCover(ped) || ((gCoverInCalls || gVehiclesInCalls) && OnFootOnly(ped))) && StartSideCall(ped))
                return 0;
            gSideCall = SideCall::None;   // the game's own phone task has command 53 again
            gCallInPrimary = false;
            gParkedCall = nullptr;
        }
        const int result = gTaskUsePhone(handle, use);
        if ((use & 0xFF) == 0 && player)
            if (auto *phone = static_cast<uint8_t *>(SidePhone(ped)))
            {
                phone[kPhoneFinish] = 1;   // the game's own hang-up, EFLC sub_A452F0
                if (gTrace)
                    TaceLog("[phone] call in cover: hung up");
            }
        return result;
    }

    int __cdecl ScriptStatusHook(uint8_t *ped, int command)
    {
        if (command != kCmdUsePhone || gSideCall == SideCall::None || ped == nullptr || !IsPlayer(ped))
            return gScriptStatus(ped, command);
        CheckSideCall(ped);
        return gSideCall == SideCall::Running ? 1 : 7;   // performing / finished
    }

    void *__fastcall FindPhoneTaskHook(void *intel, void *, unsigned type)
    {
        void *task = gFindPhoneTask(intel, type);
        if (task == nullptr && gSideCall == SideCall::Running)
            task = SecondaryTask(static_cast<uint8_t *>(intel), int(type));
        if (task == nullptr && gParkedCall != nullptr && int(type) == kTypeUsePhone)
            task = gParkedCall;   // paused for vehicle animations
        return task;
    }

    // A stand-in subtask whose getType() is PhoneIn's: shown to the game's own
    // createNextSubTask, it builds a fresh PhoneChat, as it does after PhoneIn.
    constexpr int kTypePhoneChat = 1601;
    constexpr int kTypePhoneIn   = 1602;

    int __fastcall PhoneInType(void *, void *)
    {
        return kTypePhoneIn;
    }
    void *gPhoneInVtable[4] = { nullptr, nullptr, nullptr, reinterpret_cast<void *>(&PhoneInType) };
    void *gPhoneInStandIn   = gPhoneInVtable;   // an object is its vtable pointer

    using NextSubTaskFn = void *(__thiscall *)(void *task, uint8_t *ped);
    NextSubTaskFn gPhoneNext = nullptr;

    // In cover the at-ear animation gets cut short (Trace = phone: 1601 -> 1603
    // with no hang-up), which ended the phone task and made the script start
    // the call over. While the call is on, the at-ear step starts again instead.
    void *__fastcall PhoneNextHook(uint8_t *task, void *, uint8_t *ped)
    {
        void *&sub = *reinterpret_cast<void **>(task + kTaskSubTask);
        if (gSideCall != SideCall::Running || sub == nullptr || TaskType(sub) != kTypePhoneChat
            || task[kPhoneFinish] != 0 || !IsPlayer(ped) || task != SidePhone(ped))
            return gPhoneNext(task, ped);

        void *finished = sub;
        sub = &gPhoneInStandIn;
        void *chat = gPhoneNext(task, ped);
        sub = finished;   // the task manager disposes of the real one
        if (gTrace)
            TaceLog("[phone] call in cover: the at-ear animation was cut short - started again");
        return chat;
    }

    // ---- a call that goes on into a vehicle --------------------------------
    //
    // Getting into a vehicle mid-call, the call went on beside the driving task
    // (CTaskComplexPlayerDrive), whose in-car idles (CTaskSimplePlayRandomAmbients)
    // put their props in his hand as weapon 46 - the phone's own slot. Run
    // beside the call they were left holding a dead animation, and the game
    // crashed on it as the call ended (EFLC sub_9333C0, read of 0x24). A stock
    // call in a vehicle sits in primary slot 3, above the driving task, which it
    // pauses. Once he is in, the call moves there: assignTask with no task only
    // makes the tasks from slot 3 down abortable, as for any new task, then the
    // phone task goes into slot 3 as it is (assigning it would start the call
    // over). Its at-ear step starts again, in the in-car set. With the engine
    // off it waits: the key turn or hotwire (CTaskSimpleStartCar, the driving
    // task's first step then) must finish first, or the paused driving task
    // never starts the car.
    constexpr int kTypeStartCar = 835;   // CTaskSimpleStartCar

    bool StartingCar(const uint8_t *ped)
    {
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        for (const void *t = intel != nullptr ? Field<void *>(intel, kIntelPrimary + 4 * 4) : nullptr; t != nullptr;
             t = Field<void *>(t, kTaskSubTask))
            if (TaskType(t) == kTypeStartCar)
                return true;
        return false;
    }

    // ---- the call pauses for vehicle animations ----------------------------
    //
    // Layered over them, the call's arm pose fought every animation of getting
    // in: opening the door, jacking, breaking in, climbing onto a bike, the
    // helmet, the key turn or hotwire. For those the call pauses - its step is
    // made abortable (the phone animation blends out) and the phone task leaves
    // its slot, so nothing runs it. The call itself goes on: the scripts still
    // see it (SidePhone, FindPhoneTaskHook) and a hang-up still lands on it.
    // Once they are over the task goes back and its at-ear step starts again
    // (PhoneNextHook) - in a vehicle in the in-car set, above the driving task
    // (MoveCallIntoVehicle). Walking up to the door does not count.
    constexpr int kTypeGoToCarDoor   = 800;   // CTaskComplexGoToCarDoorAndStandStill
    constexpr int kTypeExitVehicle   = 738;   // CTaskComplexNewExitVehicle
    constexpr int kTypePutOnHelmet   = 325;   // CTaskSimplePutOnHelmet
    constexpr int kTypeTakeOffHelmet = 326;   // CTaskSimpleTakeOffHelmet

    bool VehicleAnimsBusy(const uint8_t *ped)
    {
        const uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (intel == nullptr)
            return false;
        for (int slot = 0; slot < 11; slot++)   // the 5 primary slots, then the 6 secondary ones
        {
            bool gettingIn = false, onTheWay = false;
            const size_t at = slot < 5 ? kIntelPrimary + 4 * slot : kIntelSecondary + 4 * (slot - 5);
            for (const void *t = Field<void *>(intel, at); t != nullptr; t = Field<void *>(t, kTaskSubTask))
            {
                const int type = TaskType(t);
                if (type == kTypeGetInVehicle)
                    gettingIn = true;
                else if (type == kTypeGoToCarDoor)
                    onTheWay = true;
                else if (type == kTypeExitVehicle || type == kTypeStartCar || type == kTypePutOnHelmet
                         || type == kTypeTakeOffHelmet)
                    return true;
            }
            if (gettingIn && !onTheWay)
                return true;
        }
        return false;
    }

    void ParkCallForVehicleAnims(uint8_t *ped, void *phone)
    {
        uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (intel == nullptr)
            return;
        void **secondary = reinterpret_cast<void **>(intel + kIntelSecondary);
        const bool busy  = VehicleAnimsBusy(ped);
        char tasks[400];
        if (gParkedCall == nullptr)
        {
            void *step = Field<void *>(phone, kTaskSubTask);
            const int type = step != nullptr ? TaskType(step) : 0;
            if (!busy || secondary[kPhoneSlot] != phone || (type != kTypePhoneChat && type != kTypePhoneIn))
                return;   // PhoneOut: the call is ending anyway
            const AbortFn abort = (*reinterpret_cast<AbortFn **>(step))[5];
            if (!abort(step, ped, 1, nullptr))
                abort(step, ped, 2, nullptr);
            secondary[kPhoneSlot] = nullptr;
            gParkedCall = phone;
            if (gTrace)
            {
                DescribeTasks(ped, tasks, sizeof(tasks));
                TaceLog("[phone] call in cover: vehicle animations - the call pauses | %s", tasks);
            }
            return;
        }
        if (busy || secondary[kPhoneSlot] != nullptr)
            return;
        secondary[kPhoneSlot] = gParkedCall;
        gParkedCall = nullptr;
        if (gTrace)
        {
            DescribeTasks(ped, tasks, sizeof(tasks));
            TaceLog("[phone] call in cover: vehicle animations over - the call goes on | %s", tasks);
        }
    }

    void MoveCallIntoVehicle(uint8_t *ped, void *phone)
    {
        if (gAssignTask == nullptr || gCallInPrimary || (Field<uint8_t>(ped, kPedFlagsInVehicle) & 4) == 0)
            return;
        uint8_t *intel   = Field<uint8_t *>(ped, kPedIntelligence);
        void **primary   = reinterpret_cast<void **>(intel + kIntelPrimary);
        void **secondary = reinterpret_cast<void **>(intel + kIntelSecondary);
        for (int slot = 0; slot < 4; slot++)
            if (primary[slot] != nullptr)
                return;   // something outranks the driving task: wait
        if (primary[4] == nullptr || TaskType(primary[4]) == kTypePlayerOnFoot || secondary[kPhoneSlot] != phone)
            return;       // still getting in
        if (StartingCar(ped))
        {
            static const void *logged = nullptr;
            if (gTrace && logged != phone)
            {
                logged = phone;
                TaceLog("[phone] call in cover: in the vehicle - waiting for him to start the car");
            }
            return;
        }
        gAssignTask(intel + kIntelPrimary, nullptr, kScriptSlot, 1);
        if (primary[kScriptSlot] != nullptr)
            return;
        secondary[kPhoneSlot] = nullptr;
        primary[kScriptSlot]  = phone;
        gCallInPrimary = true;
        if (gTrace)
            TaceLog("[phone] call in cover: in the vehicle - the call moves above the driving task, as a stock call there");
        void *step = Field<void *>(phone, kTaskSubTask);
        if (step != nullptr && TaskType(step) == kTypePhoneChat)
        {
            const AbortFn abort = (*reinterpret_cast<AbortFn **>(step))[5];   // PhoneNextHook starts it again
            if (!abort(step, ped, 1, nullptr))
                abort(step, ped, 2, nullptr);
        }
    }

    // The one pointer to fn outside the game's code - its vtable slot. Null
    // unless there is exactly one.
    uint32_t *OnlyDataSlot(const void *fn, int &found)
    {
        const uint32_t value = uint32_t(uintptr_t(fn));
        auto *mod = reinterpret_cast<uint8_t *>(GetModuleHandleA(nullptr));
        auto *nt  = reinterpret_cast<IMAGE_NT_HEADERS *>(mod + reinterpret_cast<IMAGE_DOS_HEADER *>(mod)->e_lfanew);
        const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        uint32_t *slot = nullptr;
        found = 0;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;
            auto *p   = reinterpret_cast<uint32_t *>(mod + sec->VirtualAddress);
            auto *end = reinterpret_cast<uint32_t *>(mod + sec->VirtualAddress + (sec->Misc.VirtualSize & ~3u));
            for (; p < end; p++)
                if (*p == value && found++ == 0)
                    slot = p;
        }
        return found == 1 ? slot : nullptr;
    }

    // The cover code's "where along the cover?" helper (EFLC sub_AC3CB0, three
    // callers, all in CTaskComplexNewUseCover's update) reads the ped's cover
    // point with no null check. As a call in cover ended, the cover point was
    // gone by the time it ran and the game crashed there (read of 0x10). With
    // no cover point it now answers "no"; the update's next pass finds none and
    // leaves cover the way it always does.
    constexpr size_t kPedCoverPoint = 0xD78;

    using CoverPointHelperFn = bool(__thiscall *)(void *task, uint8_t *ped, void *pos, void *dir);
    CoverPointHelperFn gCoverPointHelper = nullptr;

    bool __fastcall CoverPointHelperGuard(void *task, void *, uint8_t *ped, void *pos, void *dir)
    {
        if (Field<void *>(ped, kPedCoverPoint) != nullptr)
            return gCoverPointHelper(task, ped, pos, dir);
        if (gTrace)
            TaceLog("[phone] cover: the cover point went missing mid-update - answered no instead of crashing");
        return false;
    }

    void KeepCoverPointGuard()
    {
        // push ebp ; mov ebp,esp ; and esp,-10h ; sub esp,14h ; push ebx ; push esi ; mov esi,[ebp+8] ; ...
        // mov eax,[esi+0D78h] ; mov ecx,[eax+10h]      <- the cover point, unchecked
        auto helper = find_pattern("55 8B EC 83 E4 F0 83 EC 14 53 56 8B 75 08 8B 46 20 F3 0F 10 40 30 F3 0F 10 48 34 "
                                   "83 C0 30 8B 86 78 0D 00 00 8B 48 10 57");
        if (helper.empty())
        {
            TaceLog("[phone] cover point guard: signature not found, not patched");
            return;
        }
        uint8_t *fn = helper.get_first<uint8_t>(0);
        uint8_t *sites[4] = {};
        const int count = CallersOf(fn, sites, 4);
        if (count < 1 || count > 4)
        {
            TaceLog("[phone] ABORTED - the cover point helper has %d callers, expected 3. Guard not patched.", count);
            return;
        }
        gCoverPointHelper = reinterpret_cast<CoverPointHelperFn>(fn);
        for (int i = 0; i < count; i++)
            injector::MakeCALL(sites[i], CoverPointHelperGuard, true);
        TaceLog("[phone] OK - cover survives losing its cover point mid-update (%d calls guarded)", count);
    }

    // The phone task picks its set from CPed::isDucking at each step (EFLC
    // sub_A45300): standing (group 7), or group 8 - the in-car set, seated hips
    // and legs. In low cover he is ducking, so a call there rose him to the
    // seat pose to answer and sat him in mid-air to hang up (Trace = phone:
    // "ducking 1"). A call in cover always gets the standing set; flag 0x2
    // already keeps it off the cover pose, as in high cover.
    using PhoneSetFn = int(__cdecl *)(uint8_t *ped);
    PhoneSetFn gPhoneSet = nullptr;

    int __cdecl PhoneSetHook(uint8_t *ped)
    {
        const int game = gPhoneSet(ped);
        if (game != 8 || !IsPlayer(ped) || (Field<uint8_t>(ped, kPedFlagsInVehicle) & 4) != 0
            || (gSideCall != SideCall::Running && !OnlyInCover(ped)))
            return game;   // in a vehicle the in-car set stays
        if (gTrace)
            TaceLog("[phone] call in cover: the standing phone set instead of the in-car one");
        return 7;
    }

    void KeepCallsInCover()
    {
        // TASK_USE_MOBILE_PHONE: ... mov ecx,[CTask::ms_pPool] ; call atPool::allocate ; ...
        // push 35h ; push esi ; push eax ; mov [esi],<AndMovement vtable>
        auto use = find_pattern("E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 38 44 24 08 56 74 ? 8B 0D ? ? ? ? E8 ? ? ? ? "
                                "8B F0 85 F6 74 ? 8B CE E8 ? ? ? ? 8B 44 24 08 6A 35 56 50 C7 06");
        // GET_MOBILE_PHONE_TASK_SUB_TASK: ... mov ecx,[CPed::ms_pPool] ; push ; call CPool::atHandle ; ...
        // push 640h ; mov ecx,eax ; call CPedIntelligence::findPrimaryOrMoveSubTaskByID
        auto sub = find_pattern("E8 ? ? ? ? 84 C0 74 03 32 C0 C3 8B 44 24 04 8B 0D ? ? ? ? 56 50 E8 ? ? ? ? "
                                "8B 74 24 0C C7 06 00 00 00 00 8B 80 24 02 00 00 68 40 06 00 00 8B C8 E8");
        // GET_SCRIPT_TASK_STATUS: ... call CPed::getScriptTaskStatus ; add esp,8 ; cmp eax,-1 ; ... mov eax,7
        auto status = find_pattern("8B 44 24 04 8B 0D ? ? ? ? 50 E8 ? ? ? ? 8B 4C 24 08 51 50 E8 ? ? ? ? "
                                   "83 C4 08 83 F8 FF 75 0C 8B 54 24 0C B8 07 00 00 00");
        // CPedTasks::setTaskSecondary(task, slot)
        auto secondary = find_pattern("53 8B 5C 24 08 56 57 8B 7C 24 14 8B F1 8B 4C BE 14 3B CB 74 ? 85 C9");
        // CTaskComplexUseMobilePhoneAndMovement::createFirstSubTask: ... jmp CTaskComplexUseMobilePhone::ctor
        auto andMovement = find_pattern("8B 44 24 04 F6 80 6C 02 00 00 04 56 8B F1 8B 0D ? ? ? ? 74 ? E8 ? ? ? ? "
                                        "85 C0 74 ? 8B 4E 14 5E 89 4C 24 04 8B C8 E9");
        if (use.empty() || sub.empty() || status.empty() || secondary.empty() || andMovement.empty())
        {
            TaceLog("[phone] calls in cover: signature not found, not patched");
            return;
        }

        uint8_t *useFn    = use.get_first<uint8_t>(0);
        uint8_t *findCall = sub.get_first<uint8_t>(52);
        uint8_t *statCall = status.get_first<uint8_t>(22);
        uint8_t *useSite  = nullptr;
        if (CallersOf(useFn, &useSite, 1) != 1 || *findCall != 0xE8 || *statCall != 0xE8
            || *andMovement.get_first<uint8_t>(41) != 0xE9)
        {
            TaceLog("[phone] ABORTED - the phone natives are not laid out as expected. Calls in cover not patched.");
            return;
        }

        // The cellphone groups' anim definitions: push <table> ; push <names> ; push 5 (anims) ... push 7 / 8
        for (const char *sig : { "6A 00 6A 05 6A 01 6A 01 68 ? ? ? ? 68 ? ? ? ? 6A 05 68 ? ? ? ? 68 ? ? ? ? 6A 07 8B CE E8",
                                 "6A 00 6A 05 6A 01 6A 01 68 ? ? ? ? 68 ? ? ? ? 6A 05 68 ? ? ? ? 68 ? ? ? ? 6A 08 8B CE E8" })
        {
            auto group = find_pattern(sig);
            if (group.empty())
                continue;
            auto *table = *group.get_first<uint32_t *>(9);   // {id, flags, type} per anim
            const int count = *group.get_first<uint8_t>(19);
            for (int i = 0; i < count && gPhoneAnims < 10; i++)
                if (table[3 * i] >= 10 && table[3 * i] <= 14)   // CellPHONE_in, Cell_Text_to_Ear, CellPHONE_out, _talk, _text
                {
                    gPhoneAnimFlags[gPhoneAnims]        = &table[3 * i + 1];
                    gPhoneAnimStock[gPhoneAnims]        = table[3 * i + 1];
                    gPhoneAnimBlend[gPhoneAnims]        = &table[3 * i + 2];
                    gPhoneAnimBlendStock[gPhoneAnims++] = table[3 * i + 2];
                }
        }
        if (gPhoneAnims != 10)
            TaceLog("[phone] calls in cover: %d of 10 phone animations found - the rest keep their own bone mask", gPhoneAnims);

        gTaskUsePhone  = reinterpret_cast<TaskUsePhoneFn>(useFn);
        gTaskPool      = *use.get_first<void **>(22);
        gAllocate      = reinterpret_cast<AllocateFn>(CallTarget(use.get_first<uint8_t>(26)));
        gPedPool       = *sub.get_first<void **>(18);
        gAtHandle      = reinterpret_cast<AtHandleFn>(CallTarget(sub.get_first<uint8_t>(24)));
        gFindPhoneTask = reinterpret_cast<FindTaskFn>(CallTarget(findCall));
        gScriptStatus  = reinterpret_cast<ScriptStatusFn>(CallTarget(statCall));
        gSetSecondary  = reinterpret_cast<SetSecondaryFn>(secondary.get_first<void>(0));
        gPhoneCtor     = reinterpret_cast<PhoneCtorFn>(CallTarget(andMovement.get_first<uint8_t>(41)));
        injector::MakeCALL(useSite, TaskUsePhoneHook, true);
        injector::MakeCALL(findCall, FindPhoneTaskHook, true);
        injector::MakeCALL(statCall, ScriptStatusHook, true);
        // CTaskComplexUseMobilePhone::createNextSubTask: push esi ; mov esi,ecx ; mov ecx,[esi+8] ; ...
        // call edx ; cmp eax,642h (PhoneIn) ; jg ; jz ; cmp eax,0CAh ; jz ; cmp eax,641h (PhoneChat)
        auto next = find_pattern("56 8B F1 8B 4E 08 8B 01 8B 50 0C 57 33 FF FF D2 3D 42 06 00 00 0F 8F ? ? ? ? "
                                 "0F 84 ? ? ? ? 3D CA 00 00 00 74 ? 3D 41 06 00 00");
        int nextSlots = 0;
        uint32_t *nextSlot = next.empty() ? nullptr : OnlyDataSlot(next.get_first<void>(0), nextSlots);
        if (nextSlot != nullptr)
        {
            gPhoneNext = reinterpret_cast<NextSubTaskFn>(next.get_first<void>(0));
            injector::WriteMemory<uint32_t>(nextSlot, uint32_t(uintptr_t(&PhoneNextHook)), true);
        }
        else
        {
            TaceLog("[phone] calls in cover: the phone task's next step not found (%d slots) - a cut-short call is not restarted",
                    nextSlots);
        }
        // The phone set picker (EFLC sub_A45300): mov ecx,[esp+4] ; test byte [ecx+26Ch],4 ; jnz ;
        // call CPed::isDucking ; test al,al ; mov eax,7 (standing) ; jz ; mov eax,8 (in-car) ; ret
        auto picker = find_pattern("8B 4C 24 04 F6 81 6C 02 00 00 04 75 0E E8 ? ? ? ? 84 C0 B8 07 00 00 00 74 05 B8 08 00 00 00 C3");
        if (!picker.empty())
        {
            uint8_t *fn = picker.get_first<uint8_t>(0);
            uint8_t *sites[kMaxEntrySites] = {};
            const int count = CallersOf(fn, sites, kMaxEntrySites);
            gPhoneSet  = reinterpret_cast<PhoneSetFn>(fn);
            gIsDucking = reinterpret_cast<IsDuckingFn>(CallTarget(fn + 13));
            for (int i = 0; i < count && i < kMaxEntrySites; i++)
                injector::MakeCALL(sites[i], PhoneSetHook, true);
            if (count != 6)
                TaceLog("[phone] calls in cover: the phone set picker has %d callers, expected 6", count);
        }
        else
        {
            TaceLog("[phone] calls in cover: the phone set picker not found - a call in low cover uses the in-car set");
        }
        // CTaskManager::assignTask(task, slot, flag): sub esp,18h ; push ebx ; push ebp ; mov ebp,[esp+28h] (slot) ;
        // ... cmp [esi+3Ch],4 ; jnz ; cmp ebp,4 ; jnz ; cmp [esi+10h],0 ; ...
        auto assign = find_pattern("83 EC 18 53 55 8B 6C 24 28 56 57 8B ? ? ? ? 83 7E 3C 04 75 0B 83 FD 04 75 06 83 7E 10 00 "
                                   "75 1F 8B 46 38 8B 48 6C 85 C9 74 33 80 79 0E 00 74 2D 8B C1 85 C0 74 41 E8");
        if (!assign.empty())
            gAssignTask = reinterpret_cast<AssignTaskFn>(assign.get_first<void>(0));
        else
            TaceLog("[phone] calls in cover: assignTask not found - a call carried into a vehicle stays beside the driving task");
        TaceLog("[phone] OK - a call taken in cover keeps the player in cover (phone animations on bone mask %u - head, "
                "neck and right arm - and blend group %u)", kHeadNeckRArm, kPhoneBlendGroup);
        if (gCoverInCalls || gVehiclesInCalls)
            TaceLog("[phone] OK - during a call on foot he can still %s", gCoverInCalls && gVehiclesInCalls
                    ? "take cover or get into a vehicle" : gCoverInCalls ? "take cover" : "get into a vehicle");
    }

    // ---- the texting pose in cover -----------------------------------------
    //
    // On foot an open phone is held up in front of him: CTaskComplexPlayerIdles
    // plays CellPHONE_text (anim 14, already on bone mask 10) and puts the phone
    // model in his hand while the phone scripts have it open
    // (SCRIPT_IS_USING_MOBILE_PHONE, and not moving offscreen). That task does
    // not run in cover, so there his hand stayed empty. In cover the pose now
    // runs in secondary slot 4 in blend group 4, like a call's animations, and
    // the phone goes into his hand the way the idle task does it. A call started
    // from it takes the same slot and goes to the ear through Cell_Text_to_Ear.

    constexpr int    kTypeRunAnim   = 400;     // CTaskSimpleRunAnim
    constexpr int    kAnimPhoneText = 14;      // CellPHONE_text
    constexpr int    kStandingSet   = 7;       // the cellphone group on foot
    constexpr int    kPhoneWeapon   = 46;      // OBJECT - what the phone is held as
    constexpr size_t kPedWeapons    = 0x2B0;   // CPedWeapons
    constexpr size_t kObjectFlags   = 0x210;   // CObject: 0x4000000 set on the held phone

    using RunAnimCtorFn   = void *(__thiscall *)(void *task, int set, int anim, float blend, int unused, float rate, float phase);
    using HasResourceFn   = bool(__cdecl *)(int model, uint32_t fileType);
    using RequestObjectFn = bool(__cdecl *)(int model, uint32_t fileType, uint32_t flags);
    using GiveWeaponFn    = void(__thiscall *)(void *weapons, int weapon, int ammo);
    using HoldObjectFn    = int(__thiscall *)(void *weapons, void *ped, int model, int unused);
    using DropPhoneFn     = void(__stdcall *)(void *ped);
    RunAnimCtorFn   gRunAnimCtor    = nullptr;
    HasResourceFn   gHasResource    = nullptr;
    RequestObjectFn gRequestObject  = nullptr;
    GiveWeaponFn    gGiveWeapon     = nullptr;
    HoldObjectFn    gHoldObject     = nullptr;
    DropPhoneFn     gDropPhone      = nullptr;
    const uint8_t  *gPhoneOpen      = nullptr;   // SCRIPT_IS_USING_MOBILE_PHONE
    const uint8_t  *gPhoneOffscreen = nullptr;   // g_bScriptMovingMobilePhoneOffscreen
    const uint32_t *gWdrFileType    = nullptr;

    int PhoneModel(uint8_t *ped)
    {
        using ModelFn = int(__thiscall *)(void *);
        return (*reinterpret_cast<ModelFn **>(ped))[kPhoneModelVfunc / 4](ped);
    }

    bool HoldingPhone(uint8_t *ped)
    {
        const uint8_t *held = Field<uint8_t *>(ped, kPedWeaponObject);
        return held != nullptr && Field<int16_t>(held, 0x2E) == PhoneModel(ped);
    }

    // The phone into his hand, as CTaskComplexPlayerIdles does it
    void HoldPhone(uint8_t *ped)
    {
        const int model = PhoneModel(ped);
        if (model == -1 || HoldingPhone(ped))
            return;
        if (!gHasResource(model, *gWdrFileType))
        {
            gRequestObject(model, *gWdrFileType, 8);
            return;
        }
        gGiveWeapon(ped + kPedWeapons, kPhoneWeapon, 1);
        if (gHoldObject(ped + kPedWeapons, ped, model, 0) != 0)
            if (uint8_t *object = Field<uint8_t *>(ped, kPedWeaponObject))
                *reinterpret_cast<uint32_t *>(object + kObjectFlags) |= 0x4000000;
    }

    // Jacking a driver or breaking into a car mid-call took the phone out of
    // his hand for good: the call's own task gives it only while the phone-in
    // animation plays (EFLC CTaskComplexUseMobilePhone::controlSubTask). Once
    // his hands are free again - in, and past the key turn or hotwire - an
    // at-ear step with an empty hand gets the phone back, the way that task
    // gives it.
    void KeepPhoneInHand(uint8_t *ped, const void *phone)
    {
        if (gGiveWeapon == nullptr || gHoldObject == nullptr || gHasResource == nullptr || gRequestObject == nullptr
            || gWdrFileType == nullptr)
            return;
        const void *step = Field<void *>(phone, kTaskSubTask);
        if (step == nullptr || TaskType(step) != kTypePhoneChat || EnteringVehicle(ped) || StartingCar(ped)
            || HoldingPhone(ped))
            return;
        HoldPhone(ped);
        static const void *logged = nullptr;
        if (gTrace && logged != phone && HoldingPhone(ped))
        {
            logged = phone;
            TaceLog("[phone] call in cover: the phone had gone from his hand - given back");
        }
    }

    // Blend the pose out and free the slot
    void EndTextPose(void *slot, uint8_t *ped, uint8_t *intel)
    {
        const AbortFn abort = (*reinterpret_cast<AbortFn **>(slot))[5];   // makeAbortable blends the pose out
        if (!abort(slot, ped, 1, nullptr))
            abort(slot, ped, 2, nullptr);
        gSetSecondary(intel + kIntelPrimary, nullptr, kPhoneSlot);
    }

    // Trace = phone: each cover state change with the phone up - what moving along cover does to it
    void TraceCoverWithPhone(uint8_t *ped)
    {
        static int last = -2;
        const int state = CoverState(ped);
        if (state == last)
            return;
        last = state;
        const uint8_t *point = Field<uint8_t *>(ped, kPedCoverPoint);
        const int slot   = Field<int>(ped, 0x2C8);
        const int weapon = slot >= 0 && slot < 16 ? Field<int>(ped, kPedWeapons + 12 * (slot + 5)) : -1;
        char anims[480];
        DescribeAnims(ped, anims, sizeof(anims));
        TaceLog("[phone] cover with the phone up: state %d | ducking %d | cover point %08X | weapon %d (slot %d) | pose %d | anims%s",
                state, gIsDucking != nullptr ? int(gIsDucking(ped)) : -1, point != nullptr ? Field<uint32_t>(point, 0) : 0,
                weapon, slot, int(gTextPose), anims);
    }

    void TextPoseInCover(uint8_t *ped)
    {
        if (gRunAnimCtor == nullptr || !IsPlayer(ped))
            return;
        uint8_t *intel = Field<uint8_t *>(ped, kPedIntelligence);
        if (intel == nullptr)
            return;
        void *slot = Field<void *>(intel, kIntelSecondary + 4 * kPhoneSlot);
        const bool ours = slot != nullptr && TaskType(slot) == kTypeRunAnim;
        const bool open = *gPhoneOpen != 0 && *gPhoneOffscreen == 0;
        if (gTrace && open && OnlyInCover(ped))
            TraceCoverWithPhone(ped);

        if (open && gSideCall != SideCall::Running && OnlyInCover(ped))
        {
            // Only once he has settled into cover (CTaskComplexNewUseCover running): during the
            // slide or dive into it the pose bent him over the phone. A pose already up waits too;
            // the phone stays in his hand.
            if (CoverState(ped) < 0)
            {
                if (ours && gTextPose)
                {
                    EndTextPose(slot, ped, intel);
                    if (gTrace)
                        TaceLog("[phone] texting pose in cover: waiting for him to settle into cover");
                }
                return;
            }
            if (slot == nullptr)   // not up yet, paused, or it ran out
            {
                void *task = gAllocate(*gTaskPool);
                if (task == nullptr)
                    return;
                gRunAnimCtor(task, kStandingSet, kAnimPhoneText, 4.0f, 0, 1.0f, 0.0f);
                UpperBodyPhoneAnims(true);   // blend group 4 before it starts
                gSetSecondary(intel + kIntelPrimary, task, kPhoneSlot);
                if (gTrace)
                    TaceLog(gTextPose ? "[phone] texting pose in cover: up again" : "[phone] texting pose in cover: phone held up");
                gTextPose = true;
            }
            if (gTextPose)
                HoldPhone(ped);
            return;
        }
        if (!gTextPose)
            return;

        // Phone closed, cover left, or a call has taken the slot
        if (ours)
            EndTextPose(slot, ped, intel);
        if (gSideCall != SideCall::Running && HoldingPhone(ped))
            gDropPhone(ped);   // and the weapon he had comes back
        gTextPose = false;
        UpperBodyPhoneAnims(gSideCall == SideCall::Running);
        if (gTrace)
            TaceLog("[phone] texting pose in cover: put down");
    }

    void KeepTextPoseInCover()
    {
        if (gAllocate == nullptr || gSetSecondary == nullptr)
        {
            TaceLog("[phone] texting pose in cover: needs calls in cover, not patched");
            return;
        }
        // CTaskComplexPlayerIdles::controlSubTask: ... cmp byte [<phone open>],0 ; jz ;
        // cmp byte [<phone moving offscreen>],0 ; jnz ; mov bl,1 ; jmp ; xor bl,bl
        auto flags = find_pattern("85 C9 0F 84 ? ? ? ? 80 3D ? ? ? ? 00 74 0D 80 3D ? ? ? ? 00 75 04 B3 01 EB 02 32 DB");
        // ... mov ecx,[<wdr file type>] ; ... call <phone model> ; push eax ; call <hasResourceLoaded> ; ...
        // push 8 ; push ecx ; ... call <phone model> ; push eax ; call <CFileTypeMgr::requestObject>
        auto model = find_pattern("8B 0D ? ? ? ? 8B 16 8B 82 2C 01 00 00 51 8B CE FF D0 50 E8 ? ? ? ? 83 C4 08 84 C0 0F 85 ? ? ? ? "
                                  "8B 0D ? ? ? ? 8B 16 8B 82 2C 01 00 00 6A 08 51 8B CE FF D0 50 E8");
        // ... push 0Eh (CellPHONE_text) ; push esi ; call <phone set> ; add esp,4 ; push eax ; mov ecx,edi ;
        // call CTaskSimpleRunAnim ctor - twice, in the idle task and in the phone task; one ctor
        auto text = hook::pattern("D9 05 ? ? ? ? 6A 00 51 D9 1C 24 6A 0E 56 E8 ? ? ? ? 83 C4 04 50 8B CF E8");
        // push 1 ; lea edi,[esi+2B0h] ; push 2Eh ; mov ecx,edi ; call <give weapon> ; ... call <hold object>
        auto give = find_pattern("6A 01 8D BE B0 02 00 00 6A 2E 8B CF E8 ? ? ? ? 8B 16 8B 82 2C 01 00 00 6A 00 8B CE FF D0 50 56 8B CF E8");
        // EFLC sub_A452D0: mov ecx,[esp+4] ; add ecx,2B0h ; call <put the phone away> ; ret 4
        auto drop = find_pattern("8B 4C 24 04 81 C1 B0 02 00 00 E8 ? ? ? ? C2 04 00");
        if (flags.empty() || model.empty() || text.empty() || give.empty() || drop.empty())
        {
            TaceLog("[phone] texting pose in cover: signature not found, not patched");
            return;
        }

        uint8_t *ctor = CallTarget(text.get(0).get<uint8_t>(26));
        for (size_t i = 1; i < text.size(); i++)
            if (CallTarget(text.get(i).get<uint8_t>(26)) != ctor)
            {
                TaceLog("[phone] ABORTED - the texting pose's animation calls disagree. Not patched.");
                return;
            }

        gPhoneOpen      = *flags.get_first<uint8_t *>(10);
        gPhoneOffscreen = *flags.get_first<uint8_t *>(19);
        gWdrFileType    = *model.get_first<uint32_t *>(2);
        gHasResource    = reinterpret_cast<HasResourceFn>(CallTarget(model.get_first<uint8_t>(20)));
        gRequestObject  = reinterpret_cast<RequestObjectFn>(CallTarget(model.get_first<uint8_t>(58)));
        gGiveWeapon     = reinterpret_cast<GiveWeaponFn>(CallTarget(give.get_first<uint8_t>(12)));
        gHoldObject     = reinterpret_cast<HoldObjectFn>(CallTarget(give.get_first<uint8_t>(35)));
        gDropPhone      = reinterpret_cast<DropPhoneFn>(drop.get_first<void>(0));
        gRunAnimCtor    = reinterpret_cast<RunAnimCtorFn>(ctor);
        TaceLog("[phone] OK - an open phone is held up in cover");
    }

    // ---- no aiming or throwing from cover with the phone up ---------------
    //
    // The phone is held as the OBJECT weapon (fire type PROJECTILE), so with it
    // up in cover the cover code's own actions still went ahead: peeking out,
    // and blind fire - which threw the phone, again and again. On foot the game
    // puts the phone away on fire (CTaskComplexPlayerGun); cover has no such
    // check. CTaskComplexNewUseCover asks one question before every action
    // (EFLC sub_ADA360(ped, request)); while the phone is up it now answers no
    // to 5 peek, 7 reload, 8 / 11 / 21 fire and aim, 20 weapon switch - without
    // asking the game, whose yes switches weapons on its own. Moving along
    // cover (16, 17, 18) and leaving it (22) still work.

    constexpr uint32_t kCoverActionsWithPhone = 1u << 5 | 1u << 7 | 1u << 8 | 1u << 11 | 1u << 20 | 1u << 21;

    using CoverActionFn = bool(__thiscall *)(void *task, uint8_t *ped, int request, void *a, void *b, void *c);
    CoverActionFn gCoverAction = nullptr;

    bool __fastcall CoverActionHook(void *task, void *, uint8_t *ped, int request, void *a, void *b, void *c)
    {
        const bool phoneUp = IsPlayer(ped) && (gTextPose || gSideCall == SideCall::Running || HoldingPhone(ped));
        const bool held    = phoneUp && request >= 0 && request < 32 && (kCoverActionsWithPhone >> request & 1);
        const bool answer  = held ? false : gCoverAction(task, ped, request, a, b, c);

        if (gTrace && phoneUp && request >= 0 && request < 32)
        {
            // Each request's answer as it changes while the phone is up
            static uint32_t seen = 0, yes = 0;
            const uint32_t bit = 1u << request;
            if (!(seen & bit) || ((yes & bit) != 0) != answer)
            {
                seen |= bit;
                yes = answer ? yes | bit : yes & ~bit;
                TaceLog("[phone] cover with the phone up: request %d -> %s%s | state %d", request, answer ? "yes" : "no",
                        held ? " (held back)" : "", CoverState(ped));
            }
        }
        return answer;
    }

    void KeepCoverActionsOffPhone()
    {
        // CTaskComplexNewUseCover's "may I?" (EFLC sub_ADA360): push ebp ; mov ebp,esp ; and esp,-10h ;
        // sub esp,64h ; push ebx ; push esi ; mov esi,[ebp+8] ; cmp dword [esi+2C8h],7 ; ...
        auto check = find_pattern("55 8B EC 83 E4 F0 83 EC 64 53 56 8B 75 08 83 BE C8 02 00 00 07 57 0F 94 C0 84 C0 "
                                  "8B F9 88 44 24 19 75 34");
        if (check.empty())
        {
            TaceLog("[phone] cover actions with the phone: signature not found, not patched");
            return;
        }
        uint8_t *fn = check.get_first<uint8_t>(0);
        uint8_t *sites[64] = {};
        const int count = CallersOf(fn, sites, 64);
        if (count < 1 || count > 64)
        {
            TaceLog("[phone] ABORTED - the cover action check has %d callers. Not patched.", count);
            return;
        }
        gCoverAction = reinterpret_cast<CoverActionFn>(fn);
        for (int i = 0; i < count; i++)
            injector::MakeCALL(sites[i], CoverActionHook, true);
        TaceLog("[phone] OK - no peeking, firing or throwing from cover with the phone up (%d calls)", count);
    }

    // ---- a call from cover goes on after leaving it ------------------------
    //
    // Leave cover mid-call and the on-foot tree comes back with
    // CTaskComplexPlayerIdles, whose phone handling then ran beside the call's
    // own: its texting pose blended the at-ear step out (the phone dropped to
    // his chin), and it takes the phone out of his hand whenever it is not
    // showing it (gone before the hang-up). A vanilla call never meets it - the
    // call's task sits above the on-foot tree. While a call from cover is on,
    // the idle task's update keeps what it has (its move task goes on), and its
    // abort leaves the phone where it is.

    using IdlesControlFn = void *(__thiscall *)(void *task, uint8_t *ped);
    using IdlesDropFn    = void(__thiscall *)(void *weapons);
    IdlesControlFn gIdlesControl = nullptr;
    IdlesControlFn gIdlesFirst   = nullptr;   // its createFirstSubTask: ControlMovement(MovePlayer, PlayRandomAmbients)
    IdlesDropFn    gIdlesDrop    = nullptr;
    constexpr int  kTypeControlMovement = 285;   // CTaskComplexControlMovement
    constexpr size_t kPedAnimBlender = 0x78;
    using BlendRateFn = void(__thiscall *)(uint8_t *anim, float rate);
    BlendRateFn    gBlendRate    = nullptr;   // an anim's blend in / out rate - what RunAnim::makeAbortable blends out with

    // The idle task's texting pose: ControlMovement(MovePlayer, RunAnim CellPHONE_text)
    bool IsTextPose(const void *sub)
    {
        const void *leaf = sub != nullptr && TaskType(sub) == kTypeControlMovement ? Field<void *>(sub, kTaskSubTask) : nullptr;
        return leaf != nullptr && TaskType(leaf) == kTypeRunAnim;
    }

    // A call from the phone held up on foot: the texting pose goes, swapped for
    // the idle task's ordinary subtask the way the idle task swaps it itself (a
    // stock call's animations are blend group 3 like the pose and blend it out;
    // a side call's are group 4). Otherwise the idle task keeps what it has.
    void *SideCallIdleSubTask(uint8_t *task, uint8_t *ped)
    {
        void *sub = Field<void *>(task, kTaskSubTask);
        if (gIdlesFirst == nullptr || !IsTextPose(sub))
            return sub;
        const AbortFn abort = (*reinterpret_cast<AbortFn **>(sub))[5];
        if (!abort(sub, ped, 1, nullptr) && !abort(sub, ped, 2, nullptr))
            return sub;
        if (gTrace)
            TaceLog("[phone] call on foot: the texting pose is swapped for the idle task's own subtask");
        return gIdlesFirst(task, ped);
    }

    // Ending the pose task was not enough: CellPHONE_text itself played on at
    // full weight under the whole call (Trace = phone: "14:3 w1.00" at every
    // step, the swap above logged at its start), then showed, empty-handed,
    // after the hang-up until another animation in its blend group replaced it.
    // With no pose task left to own it - a call on, or the phone closed - it is
    // blended out the way RunAnim::makeAbortable does it, and again if anything
    // raises it back. CellPHONE_text = anim 14 on bone mask 10 (only the phone's
    // anims use it) in blend group 3; the pose in cover is group 4. Under a call
    // group 4 goes too: the pose in cover ended when the call took its slot, so
    // one still playing is left over - the idle task's pose had picked up the
    // cover pose's fading anim after leaving cover - and it took half the arm
    // from the call's own animations (the phone at his chin). Called by the
    // call's own per-frame check (CheckSideCall) too, so cover gets it.
    void EndStrayTextPose(uint8_t *ped, const void *idleSub)
    {
        static const uint8_t *faded = nullptr;
        static float fadedWeight = 0.0f;
        static int   raised = 0;
        if (gBlendRate == nullptr || gPhoneOpen == nullptr || gPhoneOffscreen == nullptr || IsTextPose(idleSub)
            || (gSideCall != SideCall::Running && *gPhoneOpen != 0 && *gPhoneOffscreen == 0))
            return;   // the idle task's own pose, or the phone open with no call: it belongs
        const bool call = gSideCall == SideCall::Running;
        if (call)
        {
            const void *phone = SidePhone(ped);
            const void *step  = phone != nullptr ? Field<void *>(phone, kTaskSubTask) : nullptr;
            if (step != nullptr && TaskType(step) == kTypeRunAnim)
                return;   // the phone task's own wait pose while the phone model streams in
        }
        const uint8_t *blender = Field<uint8_t *>(ped, kPedAnimBlender);
        uint8_t *node = blender != nullptr ? Field<uint8_t *>(blender, 0x1A28) : nullptr;
        for (int n = 0; node != nullptr && n < 64; node = Field<uint8_t *>(node, 0x8C), n++)
        {
            uint8_t *anim = node + 4;
            if (Field<uint16_t>(node, 0x48) != 1 || Field<void *>(anim, 0x40) == nullptr || Field<int>(anim, 0x0C) != kAnimPhoneText
                || (Field<uint32_t>(anim, 0x04) & kBoneMaskBits) != kHeadNeckRArm)
                continue;
            const uint32_t group = Field<uint32_t>(anim, 0x08);
            if (group != 3 && !(call && group == kPhoneBlendGroup && !gTextPose))
                continue;   // group 4 outside a call is the pose in cover
            const float weight = Field<float>(anim, 0x34);
            const bool  again  = anim == faded && weight > fadedWeight + 0.001f;
            if (anim == faded && !again)
            {
                fadedWeight = weight;   // fading out
                continue;
            }
            if (weight <= 0.0f)
                continue;
            gBlendRate(anim, -4.0f);
            if (gTrace && (!again || raised++ < 10))
                TaceLog("[phone] CellPHONE_text left playing with no pose task (w%.2f%s) - blended out", weight,
                        again ? ", raised again" : "");
            faded = anim;
            fadedWeight = weight;
        }
    }

    void *__fastcall IdlesControlHook(uint8_t *task, void *, uint8_t *ped)
    {
        if (!IsPlayer(ped))
            return gIdlesControl(task, ped);
        void *sub = gSideCall == SideCall::Running ? SideCallIdleSubTask(task, ped) : gIdlesControl(task, ped);
        EndStrayTextPose(ped, sub);
        return sub;
    }

    void __fastcall IdlesDropHook(uint8_t *weapons)
    {
        if (gSideCall == SideCall::Running && IsPlayer(weapons - kPedWeapons))
            return;
        gIdlesDrop(weapons);
    }

    // While the phone is open, the on-foot player task (1.0.8.0 0xA623F0, one
    // vtable slot) finds CellPHONE_text on him - its blender's anim 14, any set -
    // and holds it at full weight while he moves. It stays running in cover and
    // under a call beside it, where it held a leftover pose against the call's
    // animations; a stock call's task above the on-foot tree kept it from
    // running. During a call it finds nothing.
    using FindAnimFn = uint8_t *(__thiscall *)(void *blender, int anim);
    FindAnimFn gFindAnim = nullptr;

    uint8_t *__fastcall MovingPhoneAnimHook(void *blender, void *, int anim)
    {
        return gSideCall == SideCall::Running ? nullptr : gFindAnim(blender, anim);
    }

    void KeepCallsThroughLeavingCover()
    {
        // CTaskComplexPlayerIdles::controlSubTask: sub esp,0Ch ; push ebx/ebp/esi/edi ; mov ebp,ecx ;
        // call _isNetworkGameRunning ; ... call [edx+0Ch] (its subtask's type) ; cmp eax,285
        auto control = find_pattern("83 EC 0C 53 55 56 57 8B E9 E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 8B 4D 08 88 44 24 13 "
                                    "8B 01 8B 50 0C FF D2 3D 1D 01 00 00");
        // CTaskComplexPlayerIdles::makeAbortable: ... cmp eax,965 ; jz ; cmp eax,1600 ; jz ;
        // lea ecx,[edi+2B0h] ; call <put the phone away>
        auto drop = find_pattern("FF D2 3D C5 03 00 00 74 12 3D 40 06 00 00 74 0B 8D 8F B0 02 00 00 E8");
        if (control.empty() || drop.empty())
        {
            TaceLog("[phone] calls after leaving cover: signature not found, not patched");
            return;
        }
        int slots = 0;
        uint32_t *slot = OnlyDataSlot(control.get_first<void>(0), slots);
        uint8_t *dropCall = drop.get_first<uint8_t>(22);
        if (slot == nullptr || *dropCall != 0xE8)
        {
            TaceLog("[phone] ABORTED - the idle task is not laid out as expected (%d slots). Not patched.", slots);
            return;
        }
        gIdlesControl = reinterpret_cast<IdlesControlFn>(control.get_first<void>(0));
        gIdlesDrop    = reinterpret_cast<IdlesDropFn>(CallTarget(dropCall));
        // createNextSubTask and createFirstSubTask, the two slots before - one function (EFLC sub_A04BB0)
        if (slot[-1] == slot[-2])
            gIdlesFirst = reinterpret_cast<IdlesControlFn>(uintptr_t(slot[-1]));
        else
            TaceLog("[phone] calls from the phone held up: the idle task's first subtask not found - its texting pose may show after the call");
        // An anim's blend rate: movss xmm1,[esp+4] ; xorps xmm0,xmm0 ; comiss xmm1,xmm0 ; jbe ; ... comiss xmm0,[ecx+58h]
        auto blendRate = find_pattern("F3 0F 10 4C 24 04 0F 57 C0 0F 2F C8 76 ? F3 0F 10 05 ? ? ? ? 0F 2F 41 58 77");
        if (!blendRate.empty())
            gBlendRate = reinterpret_cast<BlendRateFn>(blendRate.get_first<void>(0));
        else
            TaceLog("[phone] calls from the phone held up: the anim blend rate not found - CellPHONE_text may stay up after a call");
        // The moving phone hold: cmp byte [<phone open>],0 ; jz ; cmp byte [<offscreen>],0 ; jnz ;
        // mov eax,[ebx+0A90h] ; ... mov ecx,[ebx+78h] (the blender) ; push 0Eh (CellPHONE_text) ; ... call <find anim>
        auto hold = find_pattern("80 3D ? ? ? ? 00 0F 84 ? ? ? ? 80 3D ? ? ? ? 00 0F 85 ? ? ? ? 8B 83 90 0A 00 00 8B 48 04 "
                                 "8B 50 08 89 4C 24 1C 8B 4B 78 6A 0E 89 54 24 24 E8");
        if (!hold.empty() && *hold.get_first<uint8_t>(51) == 0xE8)
        {
            gFindAnim = reinterpret_cast<FindAnimFn>(CallTarget(hold.get_first<uint8_t>(51)));
            injector::MakeCALL(hold.get_first<uint8_t>(51), MovingPhoneAnimHook, true);
        }
        else
        {
            TaceLog("[phone] calls on foot: the moving phone hold not found - it may take half the arm from a call");
        }
        injector::WriteMemory<uint32_t>(slot, uint32_t(uintptr_t(&IdlesControlHook)), true);
        injector::MakeCALL(dropCall, IdlesDropHook, true);
        TaceLog("[phone] OK - a call from cover goes on the same after leaving cover");
    }

    // ---- cover or vehicles held back during a call -------------------------
    //
    // A call on foot runs beside CTaskComplexPlayerOnFoot when CoverInCalls or
    // VehiclesInCalls is on, and that task starts both: its cover entry (EFLC
    // sub_A043E0 - the cover button, 5 callers) and its vehicle entry (EFLC
    // sub_A04AB0, 2 callers) each return the task to start, or null. For the
    // one left off, the entry answers null while a call is on - what the stock
    // call's task above the on-foot tree amounted to. Already in cover or in a
    // vehicle, nothing changes.

    using CoverEntryFn   = void *(__thiscall *)(void *task, uint8_t *ped, int a, int b, int c);
    using VehicleEntryFn = void *(__thiscall *)(void *task, int a, void *vehicle, uint8_t *ped);
    CoverEntryFn   gCoverEntry   = nullptr;
    VehicleEntryFn gVehicleEntry = nullptr;

    void *__fastcall CoverEntryHook(void *task, void *, uint8_t *ped, int a, int b, int c)
    {
        if (gSideCall != SideCall::Running || !IsPlayer(ped) || OnlyInCover(ped))
            return gCoverEntry(task, ped, a, b, c);
        static const void *logged = nullptr;
        if (gTrace && logged != SidePhone(ped))
        {
            logged = SidePhone(ped);
            TaceLog("[phone] call on foot: taking cover is held back until it ends (CoverInCalls = 0)");
        }
        return nullptr;
    }

    void *__fastcall VehicleEntryHook(void *task, void *, int a, void *vehicle, uint8_t *ped)
    {
        if (gSideCall != SideCall::Running || !IsPlayer(ped) || (Field<uint8_t>(ped, kPedFlagsInVehicle) & 4) != 0)
            return gVehicleEntry(task, a, vehicle, ped);
        static const void *logged = nullptr;
        if (gTrace && logged != SidePhone(ped))
        {
            logged = SidePhone(ped);
            TaceLog("[phone] call on foot: getting into a vehicle is held back until it ends (VehiclesInCalls = 0)");
        }
        return nullptr;
    }

    void HoldEntriesDuringCalls(bool cover, bool vehicles)
    {
        if (cover)
        {
            // push ebp ; mov ebp,esp ; and esp,-10h ; sub esp,134h ; push ebx ; push esi ; mov esi,[ebp+8] (ped) ;
            // push edi ; mov edi,ecx ; mov ecx,esi ; call <the player's pad> ; mov cl,[eax+285Ch]  <- control 28, cover
            auto entry = find_pattern("55 8B EC 83 E4 F0 81 EC 34 01 00 00 53 56 8B 75 08 57 8B F9 8B CE E8 ? ? ? ? "
                                      "8A 88 5C 28 00 00 8A 90 5E 28 00 00 05 58 28 00 00");
            uint8_t *sites[kMaxEntrySites] = {};
            const int count = entry.empty() ? 0 : CallersOf(entry.get_first<uint8_t>(0), sites, kMaxEntrySites);
            if (entry.empty())
                TaceLog("[phone] cover during calls: signature not found, not held back");
            else if (count < 1 || count > kMaxEntrySites)
                TaceLog("[phone] ABORTED - the cover entry has %d call sites, expected 1-%d (5 on 1.0.8.0). "
                        "Cover not held back during calls.", count, kMaxEntrySites);
            else
            {
                gCoverEntry = reinterpret_cast<CoverEntryFn>(entry.get_first<void>(0));
                for (int i = 0; i < count; i++)
                    injector::MakeCALL(sites[i], CoverEntryHook, true);
                TaceLog("[phone] OK - CoverInCalls = 0: no taking cover during a call (%d calls)", count);
            }
        }
        if (vehicles)
        {
            // mov eax,[esp+0Ch] (ped) ; mov eax,[eax+0AC0h] ; push esi ; mov esi,[esp+0Ch] (vehicle) ; cmp esi,eax ;
            // mov ecx,2 ; jnz ; test eax,eax ; jz ; mov edx,[eax+28h] ; and edx,3C0h
            auto entry = find_pattern("8B 44 24 0C 8B 80 C0 0A 00 00 56 8B 74 24 0C 3B F0 B9 02 00 00 00 75 ? 85 C0 74 ? "
                                      "8B 50 28 81 E2 C0 03 00 00");
            uint8_t *sites[kMaxEntrySites] = {};
            const int count = entry.empty() ? 0 : CallersOf(entry.get_first<uint8_t>(0), sites, kMaxEntrySites);
            if (entry.empty())
                TaceLog("[phone] vehicles during calls: signature not found, not held back");
            else if (count < 1 || count > kMaxEntrySites)
                TaceLog("[phone] ABORTED - the vehicle entry has %d call sites, expected 1-%d (2 on 1.0.8.0). "
                        "Vehicles not held back during calls.", count, kMaxEntrySites);
            else
            {
                gVehicleEntry = reinterpret_cast<VehicleEntryFn>(entry.get_first<void>(0));
                for (int i = 0; i < count; i++)
                    injector::MakeCALL(sites[i], VehicleEntryHook, true);
                TaceLog("[phone] OK - VehiclesInCalls = 0: no getting into a vehicle during a call (%d calls)", count);
            }
        }
    }

    // ---- trace: what takes the player out of cover (Trace = phone) --------
    //
    // CTaskComplexPlayerInCover::controlSubTask never switches subtask (it runs
    // the cover update and keeps what it has), so cover ends in one of two
    // places, both calling its leave-cover cleanup (EFLC sub_A01240): its
    // createNextSubTask (its subtask finished) or its makeAbortable (something
    // outranked it). Each exit is logged with the call chain that got there.

    constexpr size_t kInfoCoverFlags = 0x554;   // CPlayerInfo: bit 0 = may use cover

    using LeaveCoverFn = void(__thiscall *)(void *cover, uint8_t *ped);
    LeaveCoverFn gLeaveCover = nullptr;
    uintptr_t    gModule = 0, gTextBegin = 0, gTextEnd = 0;

    // The controls that fired that frame, read the way the game does (EFLC
    // sub_49EBB0): 16 bytes per control id from CPad +9880, "just pressed" =
    // the high bit of +4 differs from +6 and matches +7. Cover is id 28.
    constexpr size_t kPadControls     = 9880;
    constexpr int    kPadControlCount = 190;

    using PedPadFn = const uint8_t *(__thiscall *)(const void *ped);
    PedPadFn gPedPad = nullptr;   // the player's CPad, the one cover reads (EFLC sub_A15320)

    bool JustPressed(const uint8_t *pad, int id)
    {
        const uint8_t *c = pad + kPadControls + 16 * id;
        return uint8_t(c[4] ^ c[6]) > 0x7F && uint8_t(c[4] ^ c[7]) <= 0x7F;
    }

    // Stack words pointing just past a call in the game's code, as 1.0.8.0 VAs
    // (base 0x400000) for IDA. The game's frames are FPO, so scan, don't walk.
    void CallChain(char *buf, size_t size)
    {
        size_t used = 0;
        buf[0] = '\0';
        const auto *sp  = static_cast<const uintptr_t *>(_AddressOfReturnAddress());
        const auto *top = reinterpret_cast<const uintptr_t *>(reinterpret_cast<NT_TIB *>(NtCurrentTeb())->StackBase);
        for (int words = 0, found = 0; sp < top && words < 1024 && found < 12; sp++, words++)
        {
            const uintptr_t ret = *sp;
            if (ret < gTextBegin + 7 || ret >= gTextEnd)
                continue;
            const auto *c = reinterpret_cast<const uint8_t *>(ret);
            const bool call = c[-5] == 0xE8                                  // call rel32
                           || (c[-6] == 0xFF && (c[-5] & 0x38) == 0x10)     // call [disp32] / [reg+disp32]
                           || (c[-3] == 0xFF && (c[-2] & 0xF8) == 0x50)     // call [reg+disp8]
                           || (c[-2] == 0xFF && (c[-1] & 0xF8) == 0xD0);    // call reg
            if (!call || used + 10 >= size)
                continue;
            used += snprintf(buf + used, size - used, " %08X", unsigned(ret - gModule + 0x400000));
            found++;
        }
    }

    void __fastcall LeaveCoverHook(void *cover, void *, uint8_t *ped)
    {
        if (IsPlayer(ped))
        {
            // createNextSubTask's call sits just past the cleanup, makeAbortable's far off
            const uintptr_t site = uintptr_t(_ReturnAddress()) - 5;
            const bool finished = site - reinterpret_cast<uintptr_t>(gLeaveCover) < 0x100;
            char tasks[400], chain[128], pressed[96] = "";
            DescribeTasks(ped, tasks, sizeof(tasks));
            CallChain(chain, sizeof(chain));

            size_t used = 0;
            if (const uint8_t *pad = gPedPad != nullptr ? gPedPad(ped) : nullptr)
                for (int id = 0; id < kPadControlCount && used + 5 < sizeof(pressed); id++)
                    if (JustPressed(pad, id))
                        used += snprintf(pressed + used, sizeof(pressed) - used, " %d", id);
            const int state = CoverState(ped);

            TaceLog("[phone] leaving cover - %s | cover state %d | just pressed:%s | may use cover %u | %s | chain%s",
                    finished ? "its subtask finished" : "made abortable", state, pressed[0] ? pressed : " none",
                    Field<uint32_t>(Field<uint8_t *>(ped, kPedPlayerInfo), kInfoCoverFlags) & 1, tasks, chain);
        }
        gLeaveCover(cover, ped);
    }

    // Who releases the player's cover point - the crash above read it after it
    // had gone. CPed::releaseCoverPoint (EFLC sub_8E7F70) has 60 callers, so it
    // is detoured: its first 9 bytes (push esi ; mov esi,ecx ;
    // mov ecx,[esi+0D78h] - no relative operands) move to a trampoline.
    using ReleaseCoverPointFn = void(__thiscall *)(uint8_t *ped);
    ReleaseCoverPointFn gReleaseCoverPoint = nullptr;   // the trampoline

    void __fastcall ReleaseCoverPointHook(uint8_t *ped)
    {
        // Only during a call in cover - moving along cover releases one every step
        if (gSideCall == SideCall::Running && IsPlayer(ped) && Field<void *>(ped, kPedCoverPoint) != nullptr)
        {
            char chain[128];
            CallChain(chain, sizeof(chain));
            TaceLog("[phone] call in cover: cover point released | chain%s", chain);
        }
        gReleaseCoverPoint(ped);
    }

    void TraceLeavingCover()
    {
        // push esi ; mov esi,[esp+8] ; push edi ; mov edi,ecx ; mov ecx,esi ; call ; mov ecx,esi ;
        // call ; mov eax,[esi+228h] ... and dword [eax+3D0h],~8      <- EFLC sub_A01240
        auto leave = find_pattern("56 8B 74 24 08 57 8B F9 8B CE E8 ? ? ? ? 8B CE E8 ? ? ? ? 8B 86 28 02 00 00 "
                                  "85 C0 74 05 83 C0 60 EB 02 33 C0 83 A0 D0 03 00 00 F7");
        if (leave.empty())
        {
            TaceLog("[phone] leaving-cover trace: signature not found, not armed");
            return;
        }
        uint8_t *fn = leave.get_first<uint8_t>(0);
        uint8_t *sites[2] = {};
        const int count = CallersOf(fn, sites, 2);
        if (count != 2)
        {
            TaceLog("[phone] leaving-cover trace: %d callers, expected 2 - not armed", count);
            return;
        }

        gModule = uintptr_t(GetModuleHandleA(nullptr));
        ForEachExecSection([](uint8_t *begin, size_t size) {
            if (gTextBegin == 0)
            {
                gTextBegin = uintptr_t(begin);
                gTextEnd   = gTextBegin + size;
            }
        });
        // sub_A15320: cmp byte [ecx+218h],0 ; jnz ; cmp byte [ecx+219h],0 ; jz ; jmp <pad> ; xor eax,eax ; ret
        auto pad = find_pattern("80 B9 18 02 00 00 00 75 0E 80 B9 19 02 00 00 00 74 05 E9 ? ? ? ? 33 C0 C3");
        if (!pad.empty())
            gPedPad = reinterpret_cast<PedPadFn>(pad.get_first<void>(0));
        else
            TaceLog("[phone] leaving-cover trace: the player's pad not found - controls not logged");
        // CPed::releaseCoverPoint: push esi ; mov esi,ecx ; mov ecx,[esi+0D78h] ; test ecx,ecx ; jz ;
        // push esi ; call ; xorps xmm0,xmm0 ; mov dword [esi+0D78h],0
        auto release = find_pattern("56 8B F1 8B 8E 78 0D 00 00 85 C9 74 2B 56 E8 ? ? ? ? 0F 57 C0 C7 86 78 0D 00 00 00 00 00 00");
        auto *tramp = release.empty() ? nullptr
                    : static_cast<uint8_t *>(VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (tramp != nullptr)
        {
            uint8_t *rel = release.get_first<uint8_t>(0);
            for (int i = 0; i < 9; i++)
                tramp[i] = rel[i];
            tramp[9] = 0xE9;   // jmp back past the moved bytes
            *reinterpret_cast<int32_t *>(tramp + 10) = int32_t((rel + 9) - (tramp + 14));
            gReleaseCoverPoint = reinterpret_cast<ReleaseCoverPointFn>(tramp);
            injector::MakeJMP(rel, ReleaseCoverPointHook, true);
        }
        else
        {
            TaceLog("[phone] leaving-cover trace: the cover point release not found - releases not logged");
        }
        gLeaveCover = reinterpret_cast<LeaveCoverFn>(fn);
        for (uint8_t *site : sites)
            injector::MakeCALL(site, LeaveCoverHook, true);
        TaceLog("[phone] trace armed - every exit from cover is logged with its call chain");
    }

    // ---- trace: what keeps CellPHONE_text on the player (Trace = phone) ----
    //
    // After a call from the phone held up, CellPHONE_text (anim 14, blend group 3)
    // played on at full weight under the whole call - even with the idle task's
    // pose swapped out - and showed once the call's animations stopped. Its phase
    // runs on unbroken, so something keeps raising it. Logged with the direct
    // caller and call chain, once per caller before / during / after a call:
    // every start of a cellphone-set anim 14 on the player (the anim start RunAnim
    // uses, 1.0.8.0 0x8E43B0) and every blend change on it (0xA33E80). Both are
    // detoured - the first 8 / 6 bytes have no relative operands.
    using AnimStartFn = uint8_t *(__thiscall *)(void *blender, int set, int anim, float blend, int fallback);
    using AnimBlendFn = void(__thiscall *)(uint8_t *anim, float rate);
    AnimStartFn gAnimStart = nullptr;   // trampolines
    AnimBlendFn gAnimBlend = nullptr;
    int         gAnimLines = 0;
    constexpr int kAnimLineCap = 150;

    // Once per caller and kind (0 start, 1 blend in, 2 blend out) in each stretch - before, during, after a call
    bool FirstInStretch(uintptr_t caller, int kind)
    {
        static uintptr_t seen[64];
        static int       count   = 0;
        static SideCall  stretch = SideCall::None;
        if (gSideCall != stretch)
        {
            stretch = gSideCall;
            count = 0;
        }
        const uintptr_t key = caller | uintptr_t(kind) << 30;
        for (int i = 0; i < count; i++)
            if (seen[i] == key)
                return false;
        if (count < 64)
            seen[count++] = key;
        return true;
    }

    uint8_t *PlayerPed()
    {
        const uint8_t *info = gPlayerByNum != nullptr ? gPlayerByNum(0) : nullptr;
        return info != nullptr ? Field<uint8_t *>(info, kPlayerPed) : nullptr;
    }

    bool OnPlayer(const uint8_t *anim)
    {
        const uint8_t *ped = PlayerPed();
        const uint8_t *blender = ped != nullptr ? Field<uint8_t *>(ped, kPedAnimBlender) : nullptr;
        const uint8_t *node = blender != nullptr ? Field<uint8_t *>(blender, 0x1A28) : nullptr;
        for (int n = 0; node != nullptr && n < 64; node = Field<uint8_t *>(node, 0x8C), n++)
            if (node + 4 == anim)
                return true;
        return false;
    }

    uint8_t *__fastcall AnimStartHook(void *blender, void *, int set, int anim, float blend, int fallback)
    {
        const uintptr_t caller = uintptr_t(_ReturnAddress());
        uint8_t *started = gAnimStart(blender, set, anim, blend, fallback);
        const uint8_t *ped = anim == kAnimPhoneText && (set == 7 || set == 8) ? PlayerPed() : nullptr;
        if (ped != nullptr && blender == Field<void *>(ped, kPedAnimBlender) && gAnimLines < kAnimLineCap
            && FirstInStretch(caller, 0))
        {
            gAnimLines++;
            char chain[128];
            CallChain(chain, sizeof(chain));
            TaceLog("[phone] CellPHONE_text started on the player from %08X | set %d blend %.1f | side call %d | w%.2f | chain%s",
                    unsigned(caller - gModule + 0x400000), set, blend, int(gSideCall),
                    started != nullptr ? Field<float>(started, 0x34) : -1.0f, chain);
        }
        return started;
    }

    void __fastcall AnimBlendHook(uint8_t *anim, void *, float rate)
    {
        const uintptr_t caller = uintptr_t(_ReturnAddress());
        if (Field<int>(anim, 0x0C) == kAnimPhoneText && (Field<uint32_t>(anim, 0x08) == 3 || Field<uint32_t>(anim, 0x08) == 4)
            && gAnimLines < kAnimLineCap && OnPlayer(anim) && FirstInStretch(caller, rate > 0.0f ? 1 : 2))
        {
            gAnimLines++;
            char chain[128];
            CallChain(chain, sizeof(chain));
            TaceLog("[phone] CellPHONE_text blend on the player -> %.1f from %08X | group %u w%.2f | side call %d | chain%s", rate,
                    unsigned(caller - gModule + 0x400000), Field<uint32_t>(anim, 0x08), Field<float>(anim, 0x34),
                    int(gSideCall), chain);
        }
        gAnimBlend(anim, rate);
    }

    // fn's first len bytes (no relative operands) in executable memory, then a jmp back past them
    uint8_t *Trampoline(uint8_t *fn, int len)
    {
        auto *tramp = static_cast<uint8_t *>(VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (tramp == nullptr)
            return nullptr;
        for (int i = 0; i < len; i++)
            tramp[i] = fn[i];
        tramp[len] = 0xE9;
        *reinterpret_cast<int32_t *>(tramp + len + 1) = int32_t((fn + len) - (tramp + len + 5));
        return tramp;
    }

    void TraceAnimStarts()
    {
        // sub esp,0Ch ; push ebx ; mov ebx,[esp+18h] ; ... mov ebp,ecx (the blender) ; call <find the anim>
        auto start = find_pattern("83 EC 0C 53 8B 5C 24 18 55 56 57 8B 7C 24 20 53 57 8B E9 E8 ? ? ? ? 8B F0 83 C4 08 85 F6 75 ? "
                                  "8B 7C 24 2C 83 FF FF");
        // movss xmm1,[esp+4] (rate) ; xorps xmm0,xmm0 ; comiss xmm1,xmm0 ; jbe ; movss xmm0,[..] ; comiss xmm0,[ecx+58h]
        auto blend = find_pattern("F3 0F 10 4C 24 04 0F 57 C0 0F 2F C8 76 ? F3 0F 10 05 ? ? ? ? 0F 2F 41 58 77");
        if (start.empty() || blend.empty() || gPlayerByNum == nullptr)
        {
            TaceLog("[phone] CellPHONE_text trace: signature not found, not armed");
            return;
        }
        if (gTextBegin == 0)
        {
            gModule = uintptr_t(GetModuleHandleA(nullptr));
            ForEachExecSection([](uint8_t *begin, size_t size) {
                if (gTextBegin == 0)
                {
                    gTextBegin = uintptr_t(begin);
                    gTextEnd   = gTextBegin + size;
                }
            });
        }
        gAnimStart = reinterpret_cast<AnimStartFn>(Trampoline(start.get_first<uint8_t>(0), 8));
        gAnimBlend = reinterpret_cast<AnimBlendFn>(Trampoline(blend.get_first<uint8_t>(0), 6));
        if (gAnimStart == nullptr || gAnimBlend == nullptr)
            return;
        injector::MakeJMP(start.get_first<void>(0), AnimStartHook, true);
        injector::MakeJMP(blend.get_first<void>(0), AnimBlendHook, true);
        TaceLog("[phone] trace armed - CellPHONE_text starts and blend changes on the player are logged (first %d)", kAnimLineCap);
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
    gPhoneInCover     = TaceIniBool("PHONE", "PhoneInCover", true);
    gPhoneIntoVehicle = TaceIniBool("PHONE", "PhoneIntoVehicle", true);
    const bool both   = TaceIniBool("PHONE", "CoverAndVehiclesInCalls", true);   // the one key they were before
    gCoverInCalls     = TaceIniBool("PHONE", "CoverInCalls", both);
    gVehiclesInCalls  = TaceIniBool("PHONE", "VehiclesInCalls", both);
    gTrace = TaceTraceEnabled("phone");
    if ((gCoverInCalls || gVehiclesInCalls) && !gPhoneInCover)
        TaceLog("[phone] CoverInCalls and VehiclesInCalls need PhoneInCover = 1 - a call still blocks cover and vehicles");
    if (!run)
        TaceLog("[phone] RunWithPhone = 0 - walking with the phone out, as vanilla");
    if (!gPhoneInCover)
        TaceLog("[phone] PhoneInCover = 0 - cover puts the phone away, as vanilla");
    if (!gPhoneIntoVehicle)
        TaceLog("[phone] PhoneIntoVehicle = 0 - getting into a vehicle closes the phone, as vanilla");
    if (!run && !gTrace && !gPhoneInCover && !gPhoneIntoVehicle)
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

    if (gPhoneInCover || gPhoneIntoVehicle || gTrace)
        KeepPhoneInCover();
    if (gPhoneInCover)
    {
        KeepCoverOnPhoneKey();
        KeepCallsInCover();
        KeepTextPoseInCover();
        KeepCoverActionsOffPhone();
        KeepCallsThroughLeavingCover();
        KeepCoverPointGuard();
        HoldEntriesDuringCalls(!gCoverInCalls, !gVehiclesInCalls);
    }
    if (gTrace)
    {
        TraceLeavingCover();
        TraceAnimStarts();
    }
}
