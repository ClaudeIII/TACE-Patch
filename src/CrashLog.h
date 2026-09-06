#pragma once

#include <cstddef>
#include <cstdint>

// ============================================================================
// Crash logger.
//
// When GTA IV dies, the question that costs the most time is always the same:
// was it us? Answering it by hand means loading a .dmp, finding the module
// bases, and scanning the faulting stack for pointers into each .asi. This
// writes that answer into a text file at the moment of the crash instead.
//
// Design notes, because a crash handler is not ordinary code:
//
//  * NOTHING here allocates. The process may well have died holding the heap
//    lock - the crash logger that calls malloc() is the crash logger that
//    deadlocks and produces no log at all, exactly when you needed one. All
//    output goes through a static buffer and WriteFile(); no CRT stdio, no
//    std::string, no new.
//  * The module list comes from walking the PEB loader data directly, not
//    CreateToolhelp32Snapshot - the snapshot API allocates and takes locks.
//  * dbghelp.dll is loaded during Init, never at crash time: LoadLibrary in a
//    faulting process can deadlock on the loader lock.
//  * Every read of game memory goes through a __try/__except helper, so a bad
//    pointer in the crash log path cannot cause a second crash.
//
// Coexistence: TacePatch does not steal crash reporting from ZolikaPatch or
// anything else. It hooks SetUnhandledExceptionFilter so it can stay the first
// handler to run - otherwise whoever loads last wins and terminates the
// process before we see anything - then explicitly calls the handlers it
// displaced, so their dumps still get written. See CrashLog_Init.
// ============================================================================

// Installs the handler. Call as early as possible in DLL_PROCESS_ATTACH, so a
// crash inside TacePatch's own init is covered too.
void CrashLog_Init();

// Records the whole-mod patch tally for the "TacePatch state" section, so the
// log can say whether the mod was healthy when the game died.
void CrashLog_SetPatchStats(int applied, int already, int missing, int ambiguous);

// Records the name of a patch whose signature did not match. Names are copied
// into fixed storage (a crash log cannot chase std::string pointers) and the
// list is capped; the overflow is counted, not stored.
void CrashLog_NoteFailedPatch(const char *what);

// Free-form one-line note carried into the crash log - use it for state that
// would otherwise be invisible post-mortem ("gate profiler armed", the current
// episode, and so on). Fixed slots, last writer per key wins.
void CrashLog_SetNote(const char *key, const char *value);

// True once the handler is installed.
bool CrashLog_Active();
