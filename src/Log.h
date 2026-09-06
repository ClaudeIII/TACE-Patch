#pragma once

#include <windows.h>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "Config.h"

// TacePatch logging.
//
// Two sinks behind one call:
//   * TacePatch.log next to the .asi - the post-mortem record. The limit
//     adjusters patch code and pointers before the game has finished starting,
//     so a crash leaves no other trace of which signature matched and which
//     silently didn't.
//   * an optional console window - the live view. Watching a patch land, a ped
//     get its loadout or a pain bank stream in *as it happens*, on a second
//     monitor, is a different job from reading a file afterwards, and it is the
//     only way to tell "this never ran" apart from "this ran and did nothing".
//
// The console is opt-in ([DEBUG] Console = 1); with it off the file behaves as
// it always has.

enum TaceLogLevel
{
    kTaceTrace = 0,   // per-event spam: one line per ped, per sound, per roll
    kTaceInfo,        // ordinary progress
    kTaceGood,        // something was successfully changed
    kTaceWarn,        // skipped, clamped, ignored - the mod still runs
    kTaceError,       // a feature could not be applied at all
    kTaceLevelCount
};

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

struct TaceLogState
{
    bool             ready       = false;
    bool             configured  = false;
    CRITICAL_SECTION lock{};

    FILE            *file        = nullptr;
    HANDLE           console     = INVALID_HANDLE_VALUE;
    bool             vt          = false;   // console understands ANSI colour
    bool             colours     = true;
    bool             timestamps  = true;
    int              minLevel    = kTaceInfo;
    bool             unlimited   = false;   // lift the per-feature trace budgets

    ULONGLONG        start       = 0;
    char             lastLine[512]{};
    int              repeat      = 0;
    int              counts[kTaceLevelCount]{};
};

inline TaceLogState &TaceLogState_()
{
    static TaceLogState s;
    return s;
}

inline const std::string &TaceLogPath()
{
    static const std::string path = []
    {
        char buf[MAX_PATH]{};
        HMODULE module = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(&TaceLogPath), &module);
        GetModuleFileNameA(module, buf, MAX_PATH);

        std::string p = buf;
        const size_t dot = p.find_last_of('.');
        if (dot != std::string::npos)
            p = p.substr(0, dot);
        return p + ".log";
    }();
    return path;
}

// ---------------------------------------------------------------------------
// console
// ---------------------------------------------------------------------------

// Ctrl+C, Ctrl+Break and the window's close button all terminate the *host
// process* by default - they would take the game down with them. Swallow every
// one; this console is a viewer, not a controller.
inline BOOL WINAPI TaceConsoleCtrlHandler(DWORD)
{
    return TRUE;
}

inline void TaceConsoleOpen(TaceLogState &s)
{
    // ERROR_ACCESS_DENIED just means the process already owns a console
    // (a loader that made one, or a second .asi that got here first).
    if (!AllocConsole() && GetLastError() != ERROR_ACCESS_DENIED)
        return;

    s.console = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, 0, nullptr);
    if (s.console == INVALID_HANDLE_VALUE)
        return;

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(TaceConsoleCtrlHandler, TRUE);

    DWORD mode = 0;
    if (GetConsoleMode(s.console, &mode))
        s.vt = SetConsoleMode(s.console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;

    // QuickEdit is on by default, and a stray click in the window puts the
    // console into selection mode, which BLOCKS the next write - freezing
    // whichever game thread happens to log next. Turn it off.
    const HANDLE in = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING, 0, nullptr);
    if (in != INVALID_HANDLE_VALUE)
    {
        DWORD inMode = 0;
        if (GetConsoleMode(in, &inMode))
            SetConsoleMode(in, (inMode & ~ENABLE_QUICK_EDIT_MODE) | ENABLE_EXTENDED_FLAGS);
        CloseHandle(in);
    }

    const std::string title = TaceIniString("DEBUG", "ConsoleTitle", "TacePatch");
    SetConsoleTitleA(title.empty() ? "TacePatch" : title.c_str());

    const SHORT cols       = static_cast<SHORT>(TaceIniInt("DEBUG", "ConsoleColumns", 132));
    const SHORT rows       = static_cast<SHORT>(TaceIniInt("DEBUG", "ConsoleRows", 44));
    const SHORT scrollback = static_cast<SHORT>(TaceIniInt("DEBUG", "ConsoleScrollback", 9000));

    // Shrink the window before resizing the buffer: the buffer may never be
    // smaller than the window, so doing these in the other order fails silently.
    SMALL_RECT tiny{0, 0, 1, 1};
    SetConsoleWindowInfo(s.console, TRUE, &tiny);
    COORD buffer{cols, scrollback > rows ? scrollback : rows};
    SetConsoleScreenBufferSize(s.console, buffer);
    SMALL_RECT want{0, 0, static_cast<SHORT>(cols - 1), static_cast<SHORT>(rows - 1)};
    SetConsoleWindowInfo(s.console, TRUE, &want);

    if (const HWND hwnd = GetConsoleWindow())
    {
        // Closing the console closes the game with it, so take the X away
        // rather than let a misclick end a test run.
        if (const HMENU menu = GetSystemMenu(hwnd, FALSE))
        {
            DeleteMenu(menu, SC_CLOSE, MF_BYCOMMAND);
            DrawMenuBar(hwnd);
        }

        // "ConsolePos = 2560,0" throws it onto the second monitor. Blank leaves
        // it wherever Windows put it.
        const std::string pos = TaceIniString("DEBUG", "ConsolePos", "");
        if (!pos.empty())
        {
            int x = 0, y = 0;
            if (sscanf(pos.c_str(), "%d , %d", &x, &y) == 2)
                SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }
}

// ---------------------------------------------------------------------------
// colour
// ---------------------------------------------------------------------------

inline const char *TaceLevelColour(int level)
{
    switch (level)
    {
    case kTaceTrace: return "\x1b[38;5;244m";
    case kTaceGood:  return "\x1b[38;5;114m";
    case kTaceWarn:  return "\x1b[38;5;214m";
    case kTaceError: return "\x1b[38;5;203m";
    default:         return "\x1b[38;5;252m";
    }
}

inline const char *TaceLevelMark(int level)
{
    switch (level)
    {
    case kTaceTrace: return "  ";
    case kTaceGood:  return "+ ";
    case kTaceWarn:  return "! ";
    case kTaceError: return "x ";
    default:         return "- ";
    }
}

// One stable colour per subsystem tag, so [gangs] is always the same shade and
// the eye can filter the stream without reading it.
inline const char *TaceTagColour(const char *tag, size_t len)
{
    static const char *kPalette[] = {
        "\x1b[38;5;81m",   // cyan
        "\x1b[38;5;150m",  // sage
        "\x1b[38;5;180m",  // tan
        "\x1b[38;5;175m",  // rose
        "\x1b[38;5;110m",  // steel
        "\x1b[38;5;222m",  // gold
    };
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++)
        h = (h ^ static_cast<uint8_t>(tag[i])) * 16777619u;
    return kPalette[h % (sizeof(kPalette) / sizeof(kPalette[0]))];
}

// Severity for the call sites that predate the levels. The wording in this
// codebase is consistent enough to classify on, and a wrong guess only costs a
// colour - the text is identical either way. New code should use TACE_OK /
// TACE_WARN / TACE_ERR / TACE_TRACE rather than rely on this.
inline int TaceGuessLevel(const char *msg)
{
    static const char *kError[] = {"ABORTED", "not found", "feature disabled", "cannot", "failed"};
    static const char *kWarn[]  = {"SKIPPED", "skipped", "not patched", "ignored", "clamping",
                                   "did not", "out of range", "no signature matched", "below the stock"};
    static const char *kGood[]  = {"OK -", "applied", "armed:", "wrapped", " -> "};

    for (const char *k : kError)
        if (strstr(msg, k))
            return kTaceError;
    for (const char *k : kWarn)
        if (strstr(msg, k))
            return kTaceWarn;
    for (const char *k : kGood)
        if (strstr(msg, k))
            return kTaceGood;
    return kTaceInfo;
}

// ---------------------------------------------------------------------------
// core
// ---------------------------------------------------------------------------

// Falls back to plain append-to-file if TaceLog_Init() never ran, so a stray
// early call still records something instead of crashing on a null lock.
inline void TaceLogEnsure(TaceLogState &s)
{
    if (s.ready)
        return;
    InitializeCriticalSection(&s.lock);
    s.start = GetTickCount64();
    s.file  = fopen(TaceLogPath().c_str(), "a");
    s.ready = true;
}

// Emits the "^ repeated N more times" line that closes a collapsed run. The
// console shows the count live on one line; the file only learns of it here.
inline void TaceFlushRepeat(TaceLogState &s)
{
    if (s.repeat <= 0)
        return;
    if (s.file)
    {
        fprintf(s.file, "               ^ repeated %d more time%s\n", s.repeat, s.repeat == 1 ? "" : "s");
        fflush(s.file);
    }
    s.repeat = 0;
}

inline void TaceLogWriteV(int level, const char *fmt, va_list args)
{
    TaceLogState &s = TaceLogState_();
    TaceLogEnsure(s);

    if (level < s.minLevel)
        return;

    char msg[1024];
    if (vsnprintf(msg, sizeof(msg), fmt, args) < 0)
        return;

    EnterCriticalSection(&s.lock);

    if (level >= 0 && level < kTaceLevelCount)
        s.counts[level]++;

    const double secs = (GetTickCount64() - s.start) / 1000.0;

    // "[tag] rest" is split so the tag can be colour-coded and column-aligned
    // instead of sitting inline in the text.
    const char *tag    = nullptr;
    size_t      tagLen = 0;
    const char *body   = msg;
    if (msg[0] == '[')
    {
        if (const char *close = strchr(msg, ']'))
        {
            tag    = msg + 1;
            tagLen = static_cast<size_t>(close - msg) - 1;
            body   = close + 1;
            while (*body == ' ')
                body++;
        }
    }

    // --- console -----------------------------------------------------------
    // An identical consecutive line is rewritten in place with a running count
    // instead of scrolling the window - a hooked picker that fires once per ped
    // is unreadable otherwise. Needs VT (cursor-up) to overwrite.
    bool collapsed = false;
    if (s.console != INVALID_HANDLE_VALUE)
    {
        const bool same = s.vt && strcmp(msg, s.lastLine) == 0 && strlen(msg) < 200;

        char tagBuf[16]{};
        if (tag)
            memcpy(tagBuf, tag, tagLen < sizeof(tagBuf) - 1 ? tagLen : sizeof(tagBuf) - 1);

        char count[32]{};
        if (same)
            snprintf(count, sizeof(count), "  (x%d)", s.repeat + 2);

        char line[1400];
        if (s.colours && s.vt)
            snprintf(line, sizeof(line), "%s\x1b[38;5;240m%8.3f  %s%-9s %s%s%s\x1b[38;5;240m%s\x1b[0m\x1b[K\n",
                     same ? "\x1b[A\r" : "",
                     secs,
                     tag ? TaceTagColour(tag, tagLen) : "", tagBuf,
                     TaceLevelColour(level), TaceLevelMark(level), body,
                     count);
        else
            snprintf(line, sizeof(line), "%s%8.3f  %-9s %s%s%s\n",
                     same ? "\r" : "",
                     secs, tagBuf, TaceLevelMark(level), body, count);

        DWORD written = 0;
        WriteConsoleA(s.console, line, static_cast<DWORD>(strlen(line)), &written, nullptr);

        if (same)
        {
            s.repeat++;
            collapsed = true;   // deliberately not written to the file again
        }
    }

    if (!collapsed)
    {
        TaceFlushRepeat(s);
        strncpy(s.lastLine, msg, sizeof(s.lastLine) - 1);
        s.lastLine[sizeof(s.lastLine) - 1] = '\0';

        // --- file ----------------------------------------------------------
        if (s.file)
        {
            if (s.timestamps)
                fprintf(s.file, "[%8.3f] %s%s\n", secs, TaceLevelMark(level), msg);
            else
                fprintf(s.file, "%s\n", msg);
            fflush(s.file);   // the next line may be the last one before a crash
        }
    }

    LeaveCriticalSection(&s.lock);
}

inline void TaceLogAt(int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    TaceLogWriteV(level, fmt, args);
    va_end(args);
}

// Unchanged signature, so every existing call site keeps working; the severity
// is inferred from the wording.
inline void TaceLog(const char *fmt, ...)
{
    char peek[1024];
    va_list probe;
    va_start(probe, fmt);
    vsnprintf(peek, sizeof(peek), fmt, probe);
    va_end(probe);

    va_list args;
    va_start(args, fmt);
    TaceLogWriteV(TaceGuessLevel(peek), fmt, args);
    va_end(args);
}

#define TACE_TRACE(...) TaceLogAt(kTaceTrace, __VA_ARGS__)
#define TACE_INFO(...)  TaceLogAt(kTaceInfo,  __VA_ARGS__)
#define TACE_OK(...)    TaceLogAt(kTaceGood,  __VA_ARGS__)
#define TACE_WARN(...)  TaceLogAt(kTaceWarn,  __VA_ARGS__)
#define TACE_ERR(...)   TaceLogAt(kTaceError, __VA_ARGS__)

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

// Call once, first thing in DllMain, before any feature initialises.
inline void TaceLog_Init()
{
    TaceLogState &s = TaceLogState_();
    if (s.configured)
        return;

    // The ini is read before the file is opened - AppendLog decides whether
    // this run starts a fresh one.
    const bool wantFile    = TaceIniBool("DEBUG", "LogFile", true);
    const bool append      = TaceIniBool("DEBUG", "AppendLog", false);
    const bool wantConsole = TaceIniBool("DEBUG", "Console", false);

    if (!s.ready)
    {
        InitializeCriticalSection(&s.lock);
        s.start = GetTickCount64();
        s.ready = true;
    }
    if (s.file)
    {
        fclose(s.file);
        s.file = nullptr;
    }
    if (wantFile)
        s.file = fopen(TaceLogPath().c_str(), append ? "a" : "w");

    s.colours    = TaceIniBool("DEBUG", "ConsoleColours", true);
    s.timestamps = TaceIniBool("DEBUG", "Timestamps", true);
    s.unlimited  = TaceIniBool("DEBUG", "UnlimitedTrace", false);
    s.configured = true;

    // Default is trace, i.e. no filtering: the per-feature Debug keys already
    // decide whether the noisy per-event lines are produced at all. Level is
    // here to turn a busy run down to just the outcomes.
    const std::string level = TaceIniString("DEBUG", "Level", "trace");
    if      (level == "error")           s.minLevel = kTaceError;
    else if (level == "warn")            s.minLevel = kTaceWarn;
    else if (level == "info")            s.minLevel = kTaceInfo;
    else                                 s.minLevel = kTaceTrace;

    if (wantConsole)
        TaceConsoleOpen(s);

    SYSTEMTIME t{};
    GetLocalTime(&t);
    char exe[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);

    TACE_INFO("[tace] ===========================================================");
    TACE_INFO("[tace] TacePatch  -  %04d-%02d-%02d %02d:%02d:%02d",
              t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    TACE_INFO("[tace] host %s", exe);
    TACE_INFO("[tace] GTAIV.exe base %p (ASLR - add this to any 1.0.8.0 VA)",
              (void *)GetModuleHandleA(nullptr));
    if (s.console != INVALID_HANDLE_VALUE)
        TACE_INFO("[tace] console attached%s, level %s", s.vt ? ", colour" : "", level.c_str());
    TACE_INFO("[tace] ===========================================================");
}

// Call once after every feature has initialised. Answers "did any of this
// actually take?" at a glance instead of by reading sixty lines.
inline void TaceLog_Summary()
{
    TaceLogState &s = TaceLogState_();
    TaceLogEnsure(s);

    EnterCriticalSection(&s.lock);
    TaceFlushRepeat(s);
    const int good = s.counts[kTaceGood], warn = s.counts[kTaceWarn], err = s.counts[kTaceError];
    LeaveCriticalSection(&s.lock);

    TaceLogAt(err ? kTaceError : (warn ? kTaceWarn : kTaceGood),
              "[tace] startup complete: %d change(s) applied, %d skipped, %d failed",
              good, warn, err);

    if (s.console != INVALID_HANDLE_VALUE)
    {
        char title[128];
        snprintf(title, sizeof(title), "TacePatch  -  %d applied, %d skipped, %d failed", good, warn, err);
        SetConsoleTitleA(title);
    }
}

// Per-event tracing is capped so the log file cannot balloon over a long
// session. A console has no such problem - it scrolls - so [DEBUG]
// UnlimitedTrace lifts the cap for anyone watching it live.
inline int TaceTraceBudget(int normal)
{
    return TaceLogState_().unlimited ? 0x7FFFFFFF : normal;
}

// Which subsystems emit their per-event lines, from one place:
//
//     [DEBUG] Trace = gangs, cops        // or "all", or blank for none
//
// The names are the same tags the console prints, so what you read in the
// window is what you type here. `legacySection` is the older per-feature
// "Debug = 1" spelling, still honoured so an existing ini keeps working.
//
// This decides whether the noisy lines are PRODUCED; [DEBUG] Level decides how
// much of what is produced gets through to the sinks.
inline bool TaceTraceEnabled(const char *name, const char *legacySection = nullptr)
{
    static const std::string list = []
    {
        std::string s = TaceIniString("DEBUG", "Trace", "");
        for (char &c : s)
            c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        return s;
    }();

    size_t at = 0;
    while (at < list.size())
    {
        while (at < list.size() && (list[at] == ' ' || list[at] == ',' || list[at] == '\t'))
            at++;
        size_t end = list.find_first_of(", \t", at);
        if (end == std::string::npos)
            end = list.size();
        const std::string token = list.substr(at, end - at);
        if (token == "all" || token == name)
            return true;
        at = end;
    }

    return legacySection != nullptr && TaceIniBool(legacySection, "Debug", false);
}

inline bool TaceConsoleActive()
{
    return TaceLogState_().console != INVALID_HANDLE_VALUE;
}
