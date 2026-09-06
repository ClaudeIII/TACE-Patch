#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cstdint>
#include <cstdio>

#include "Config.h"
#include "Log.h"
#include "GateTable.h"

// ============================================================================
// Episode gate profiler.
//
// Static analysis gets you the mechanism of a gate and, where Claudio has named
// the function, the feature. For the rest it cannot tell you what the branch is
// FOR. This does it the other way round: perform an action in game and watch
// which gates the game evaluated, and which of them refused the episodic path.
//
// A gate is `cmp [episode], N` (or a load of it) followed by a jump. Every one
// of them is at least 5 bytes, so the instruction is replaced with a CALL to a
// per-gate stub:
//
//     pushad / pushfd            save everything
//     push  <index> ; call log   report this gate
//     popfd / popad              restore everything
//     <the original instruction> re-executed here, so flags and registers end
//     ret                        up exactly as the game left them
//
// CONTROL FLOW IS NOT TOUCHED. The game's own jump runs next, on flags this
// stub produced, and branches wherever it always would have. The profiler only
// watches - it can never change which path the game takes.
//
// The original bytes are copied into the stub AT RUNTIME rather than baked in,
// because the address operand inside them is ASLR-relocated by the loader.
// ============================================================================

namespace
{
    struct Gate
    {
        uintptr_t      at;
        uint32_t       staticVa;   // the address in docs/episode-gates.txt
        const GateEntry *entry;
        uint32_t       hits;
        bool           forced;     // TacePatch NOPed the jump - always episodic
        bool           announced;
    };

    Gate     *gGates      = nullptr;
    size_t    gCount      = 0;
    uint8_t  *gStubs      = nullptr;
    int32_t  *gEpisode    = nullptr;
    bool      gActive     = false;
    int       gMarkKey    = VK_F10;
    volatile LONG gMarking = 0;

    // Reset by the mark key. A gate reports again after a mark, which is what
    // makes "press the key, do the thing, read what appeared" work.
    void ResetSeen()
    {
        for (size_t i = 0; i < gCount; i++)
            gGates[i].announced = false;
    }

    // Called from every stub. Deliberately does almost nothing: this can run in
    // a per-frame path, so past the first sighting a gate only counts.
    void __cdecl GateHit(size_t index)
    {
        if (index >= gCount)
            return;
        Gate &g = gGates[index];
        g.hits++;
        if (g.announced)
            return;
        g.announced = true;

        const int now = gEpisode ? *gEpisode : -1;
        const int want = g.entry->episode;
        static const char *kEp[] = {"base IV", "TLAD", "TBoGT", "episode 3"};
        const char *nowName = (now >= 0 && now < 4) ? kEp[now] : "?";

        // Addresses are reported as the STATIC 1.0.8.0 address, not the ASLR
        // one, so they can be looked up in docs/episode-gates.txt directly.
        if (g.forced)
        {
            // The comparison still runs and still says "wrong episode", but
            // TacePatch has NOPed the jump that acts on it, so the episodic
            // path is taken anyway. Reporting this as LOCKED OUT would be
            // exactly backwards.
            TACE_OK("[gate] %08X %-40s FORCED OPEN by TacePatch (would want episode %d, is %d)",
                    g.staticVa, g.entry->label, want, now);
        }
        else if (want < 0)
        {
            TACE_INFO("[gate] %08X %-40s reached  (episode is %d, %s)",
                      g.staticVa, g.entry->label, now, nowName);
        }
        else if (want == now)
        {
            TACE_OK("[gate] %08X %-40s TAKEN    (needs episode %d, is %d)",
                    g.staticVa, g.entry->label, want, now);
        }
        else
        {
            TACE_WARN("[gate] %08X %-40s LOCKED OUT (needs episode %d, is %d %s)",
                      g.staticVa, g.entry->label, want, now, nowName);
        }
    }

    // Watches the mark key. A thread rather than a game hook so it works even
    // while the game is busy, and costs nothing when idle.
    DWORD WINAPI MarkThread(LPVOID)
    {
        bool down = false;
        for (;;)
        {
            const bool now = (GetAsyncKeyState(gMarkKey) & 0x8000) != 0;
            if (now && !down)
            {
                uint32_t fired = 0;
                for (size_t i = 0; i < gCount; i++)
                    if (gGates[i].hits) fired++;
                TACE_INFO("[gate] ---- mark ---- %u of %zu gates have fired so far;"
                          " clearing, do the action now", fired, gCount);
                ResetSeen();
            }
            down = now;
            Sleep(40);
        }
    }

    uint8_t *EmitStub(uint8_t *p, size_t index, const uint8_t *original, size_t len)
    {
        uint8_t *start = p;
        *p++ = 0x60;                                        // pushad
        *p++ = 0x9C;                                        // pushfd
        *p++ = 0x68; *(uint32_t *)p = (uint32_t)index; p += 4;   // push index
        *p++ = 0xE8;                                        // call GateHit
        *(int32_t *)p = (int32_t)((uintptr_t)&GateHit - ((uintptr_t)p + 4)); p += 4;
        *p++ = 0x83; *p++ = 0xC4; *p++ = 0x04;              // add esp, 4
        *p++ = 0x9D;                                        // popfd
        *p++ = 0x61;                                        // popad
        memcpy(p, original, len); p += len;                 // the real instruction
        *p++ = 0xC3;                                        // ret
        (void)start;
        return p;
    }
}

void GateProfile_Init()
{
    if (!TaceIniBool("DEBUG", "GateProfile", false))
        return;

    const uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
    gMarkKey = TaceIniInt("DEBUG", "GateProfileKey", VK_F10);

    // Where the episode value lives. Every one of these instructions carries it
    // as an absolute operand - at offset 1 for `A1`, offset 2 for the rest -
    // and the loader has already relocated it, so reading it out of the game's
    // own code is what gives the ASLR-correct address.
    //
    // Taken by majority vote rather than from the first row: one bad row cannot
    // then poison the check that every other row is measured against.
    {
        struct { int32_t *addr; int votes; } tally[8] = {};
        int used = 0;
        for (size_t i = 0; i < kGateCount && i < 64; i++)
        {
            const uint8_t *at = (const uint8_t *)(base + kGates[i].rva);
            if (IsBadReadPtr(at, 8) || *at != kGates[i].opcode)
                continue;
            int32_t *cand = (*at == 0xA1) ? *(int32_t **)(at + 1) : *(int32_t **)(at + 2);
            int slot = -1;
            for (int t = 0; t < used; t++)
                if (tally[t].addr == cand) slot = t;
            if (slot < 0 && used < 8) { tally[used].addr = cand; tally[used].votes = 0; slot = used++; }
            if (slot >= 0) tally[slot].votes++;
        }
        int best = 0;
        for (int t = 1; t < used; t++)
            if (tally[t].votes > tally[best].votes) best = t;
        if (used) gEpisode = tally[best].addr;
    }

    if (gEpisode == nullptr || IsBadReadPtr(gEpisode, 4))
    {
        TACE_ERR("[gate] could not resolve the episode global from the gate table"
                 " - profiler disabled, nothing patched");
        return;
    }

    gGates = (Gate *)calloc(kGateCount, sizeof(Gate));
    gStubs = (uint8_t *)VirtualAlloc(nullptr, kGateCount * 48,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!gGates || !gStubs)
    {
        TACE_ERR("[gate] could not allocate profiler memory - disabled");
        return;
    }

    uint8_t *pen = gStubs;
    size_t installed = 0, mismatched = 0, forced = 0;
    for (size_t i = 0; i < kGateCount; i++)
    {
        const GateEntry &e = kGates[i];
        uint8_t *at = (uint8_t *)(base + e.rva);

        // Never patch on the strength of an address alone. Two checks, and the
        // site is left completely untouched unless both pass:
        //   1. the opcode is the instruction the table describes
        //   2. it really is reading the episode global
        // The second is what makes a wrong build safe rather than catastrophic:
        // an address that happens to hold a `cmp` still gets skipped unless it
        // is comparing the very value every other gate compares.
        if (IsBadReadPtr(at, e.length))
        {
            mismatched++;
            continue;
        }
        if (*at != e.opcode)
        {
            mismatched++;
            continue;
        }
        const int32_t *operand = (*at == 0xA1) ? *(int32_t **)(at + 1) : *(int32_t **)(at + 2);
        if (operand != gEpisode)
        {
            mismatched++;
            continue;
        }

        gGates[gCount].at = (uintptr_t)at;
        gGates[gCount].staticVa = e.rva + 0x400000;
        gGates[gCount].entry = &e;

        // Read the finished state of the jump this gate controls. TacePatch's
        // episodic patches NOP it, and a NOPed jump means the episodic path is
        // taken whatever the comparison says. This is why the profiler has to
        // initialise after every other patch has been applied.
        const uint8_t *jump = at + e.length;
        gGates[gCount].forced = (jump[0] == 0x90 && jump[1] == 0x90);
        if (gGates[gCount].forced)
            forced++;

        uint8_t *stub = pen;
        pen = EmitStub(pen, gCount, at, e.length);

        DWORD old = 0;
        VirtualProtect(at, e.length, PAGE_EXECUTE_READWRITE, &old);
        at[0] = 0xE8;
        *(int32_t *)(at + 1) = (int32_t)((uintptr_t)stub - ((uintptr_t)at + 5));
        for (size_t b = 5; b < e.length; b++)
            at[b] = 0x90;
        VirtualProtect(at, e.length, old, &old);
        FlushInstructionCache(GetCurrentProcess(), at, e.length);

        gCount++;
        installed++;
    }

    gActive = installed > 0;
    TACE_INFO("[gate] profiler armed: %zu of %zu gates instrumented%s",
              installed, kGateCount,
              mismatched ? "" : " (every one verified)");
    if (mismatched)
        TACE_WARN("[gate] %zu gate(s) did not hold the expected opcode and were left alone"
                  " - this is not the build the table was generated from", mismatched);
    TACE_INFO("[gate] episode value at %p, currently %d", (void *)gEpisode,
              gEpisode ? *gEpisode : -1);
    TACE_INFO("[gate] press VK 0x%02X to mark: it clears what has been reported, so"
              " perform an action and only the gates it touched appear", gMarkKey);

    CreateThread(nullptr, 0, MarkThread, nullptr, 0, nullptr);
}
