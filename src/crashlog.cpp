#define _CRT_SECURE_NO_WARNINGS

#include "CrashLog.h"

#include <windows.h>
#include <dbghelp.h>

#include <cstdio>
#include <cstring>

#include "Config.h"
#include "Log.h"

// ============================================================================
// Everything in this file runs, or may run, inside an exception filter in a
// process that has already gone wrong. The rules are in CrashLog.h; the short
// version is that nothing below the "crash time" banner allocates, takes a
// documented lock, or calls the CRT.
//
// Formatting uses wsprintfA rather than snprintf on purpose: it lives in
// user32, does not touch the CRT locale and does not allocate. Its output is
// capped at 1024 bytes per call, which every format string here respects.
// ============================================================================

#pragma comment(lib, "user32.lib")

namespace
{

// ---------------------------------------------------------------------------
// Configuration, read once at init.
// ---------------------------------------------------------------------------

struct CrashConfig
{
    bool enabled     = true;
    bool miniDump    = true;
    bool fullDump    = false;  // MiniDumpWithFullMemory - big files, rarely needed
    bool trackFiles  = true;   // IAT hooks for last-file / last-library
    bool chain       = true;   // call the handlers we displaced
    bool veh         = true;   // also watch via a vectored handler
    bool vehMiniDump = false;  // .dmp for first-chance reports too
    int  maxLogs     = 8;      // reports per run, so a swallowed-exception loop cannot spam
    int  stackWords  = 128;    // dwords of annotated stack to print
    int  scanWords   = 4096;   // dwords of stack scanned for return addresses
    char dir[MAX_PATH]{};
};

CrashConfig gCfg;
bool        gActive = false;

// ---------------------------------------------------------------------------
// Safe memory access. A bad pointer inside the crash path must not produce a
// second crash - it must produce the word "unreadable" in the log.
// ---------------------------------------------------------------------------

#pragma warning(push)
#pragma warning(disable : 4509)  // SEH used in a function with a destructor

bool SafeRead(const void *src, void *dst, size_t n)
{
    __try
    {
        memcpy(dst, src, n);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

#pragma warning(pop)

bool SafeReadU32(uintptr_t addr, uint32_t *out)
{
    return SafeRead(reinterpret_cast<const void *>(addr), out, sizeof(uint32_t));
}

// Page classification, via VirtualQuery - no allocation, no locks.
enum PageKind
{
    kPageBad = 0,
    kPageReadable,
    kPageExecutable,
    kPageStack,
};

PageKind ClassifyPage(uintptr_t addr, MEMORY_BASIC_INFORMATION *mbiOut = nullptr)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
        return kPageBad;
    if (mbiOut)
        *mbiOut = mbi;

    if (mbi.State != MEM_COMMIT)
        return kPageBad;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return kPageBad;

    if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        return kPageExecutable;
    if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY))
        return kPageReadable;

    return kPageBad;
}

// ---------------------------------------------------------------------------
// Module table, built by walking the PEB loader list.
//
// CreateToolhelp32Snapshot (which is what FLA's handler uses) allocates and
// takes the loader lock; both are things a crashed process may not survive.
// The PEB walk is a linked-list traversal of memory that is already mapped.
// ---------------------------------------------------------------------------

struct TaceUnicodeString
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct TaceLdrEntry
{
    LIST_ENTRY        InLoadOrderLinks;
    LIST_ENTRY        InMemoryOrderLinks;
    LIST_ENTRY        InInitializationOrderLinks;
    PVOID             DllBase;
    PVOID             EntryPoint;
    ULONG             SizeOfImage;
    TaceUnicodeString FullDllName;
    TaceUnicodeString BaseDllName;
};

constexpr int kMaxModules = 256;

struct ModuleRec
{
    uintptr_t base;
    uintptr_t size;
    char      name[64];
    char      path[MAX_PATH];
    int       stackHits;  // filled in by the stack scan
};

ModuleRec gModules[kMaxModules];
int       gModuleCount = 0;

void WideToAscii(const wchar_t *src, USHORT lenBytes, char *dst, size_t dstSize)
{
    size_t n = lenBytes / sizeof(wchar_t);
    if (n > dstSize - 1)
        n = dstSize - 1;

    size_t o = 0;
    for (size_t i = 0; i < n; i++)
    {
        wchar_t c = 0;
        if (!SafeRead(src + i, &c, sizeof(c)))
            break;
        dst[o++] = (c > 0 && c < 127) ? static_cast<char>(c) : '?';
    }
    dst[o] = '\0';
}

void BuildModuleTable()
{
    gModuleCount = 0;

    // fs:[0x30] -> PEB, PEB+0x0C -> PEB_LDR_DATA, +0x0C -> InLoadOrderModuleList
    uintptr_t peb = 0;
#ifdef _M_IX86
    peb = __readfsdword(0x30);
#endif
    if (!peb)
        return;

    uintptr_t ldr = 0;
    if (!SafeReadU32(peb + 0x0C, reinterpret_cast<uint32_t *>(&ldr)) || !ldr)
        return;

    LIST_ENTRY *head = reinterpret_cast<LIST_ENTRY *>(ldr + 0x0C);
    LIST_ENTRY  headCopy{};
    if (!SafeRead(head, &headCopy, sizeof(headCopy)))
        return;

    LIST_ENTRY *cur = headCopy.Flink;
    for (int guard = 0; guard < kMaxModules && cur && cur != head; guard++)
    {
        TaceLdrEntry e{};
        if (!SafeRead(cur, &e, sizeof(e)))
            break;

        if (e.DllBase && e.SizeOfImage)
        {
            ModuleRec &m = gModules[gModuleCount];
            m.base      = reinterpret_cast<uintptr_t>(e.DllBase);
            m.size      = e.SizeOfImage;
            m.stackHits = 0;
            m.name[0]   = '\0';
            m.path[0]   = '\0';

            if (e.BaseDllName.Buffer)
                WideToAscii(e.BaseDllName.Buffer, e.BaseDllName.Length, m.name, sizeof(m.name));
            if (e.FullDllName.Buffer)
                WideToAscii(e.FullDllName.Buffer, e.FullDllName.Length, m.path, sizeof(m.path));
            if (!m.name[0])
                lstrcpynA(m.name, "?", sizeof(m.name));

            gModuleCount++;
        }

        cur = e.InLoadOrderLinks.Flink;
    }
}

const ModuleRec *ModuleForAddress(uintptr_t addr)
{
    for (int i = 0; i < gModuleCount; i++)
        if (addr >= gModules[i].base && addr < gModules[i].base + gModules[i].size)
            return &gModules[i];
    return nullptr;
}

// "GTAIV.exe+0x46B32A" / "unknown module"
void DescribeAddress(uintptr_t addr, char *out, size_t outSize)
{
    const ModuleRec *m = ModuleForAddress(addr);
    if (m)
        wsprintfA(out, "%s+0x%X", m->name, static_cast<unsigned>(addr - m->base));
    else
        lstrcpynA(out, "<no module>", static_cast<int>(outSize));
}

// ---------------------------------------------------------------------------
// Output buffer. One static allocation made at load time, written out in a
// single WriteFile at the end.
// ---------------------------------------------------------------------------

constexpr size_t kOutCap = 512 * 1024;

char   gOut[kOutCap];
size_t gOutLen = 0;

void Emit(const char *s)
{
    while (*s && gOutLen < kOutCap - 1)
        gOut[gOutLen++] = *s++;
    gOut[gOutLen] = '\0';
}

void Emitf(const char *fmt, ...)
{
    char    line[1024];
    va_list args;
    va_start(args, fmt);
    wvsprintfA(line, fmt, args);  // user32, no heap, no locale
    va_end(args);
    Emit(line);
}

void Rule(const char *title)
{
    Emitf("\r\n--- %s ", title);
    int pad = 60 - lstrlenA(title);
    for (int i = 0; i < pad; i++)
        Emit("-");
    Emit("\r\n");
}

// ---------------------------------------------------------------------------
// Mod state, recorded during startup so the crash log can report it.
// ---------------------------------------------------------------------------

constexpr int kMaxFailedPatches = 32;
constexpr int kMaxNotes         = 24;

struct ModState
{
    int  applied = -1, already = 0, missing = 0, ambiguous = 0;
    char failed[kMaxFailedPatches][96]{};
    int  failedCount = 0;
    int  failedOverflow = 0;

    char noteKey[kMaxNotes][48]{};
    char noteVal[kMaxNotes][160]{};
    int  noteCount = 0;
};

ModState gState;

// Last file / library seen by the game, captured by the IAT hooks below.
char gLastFileA[MAX_PATH] = "";
char gLastFileW[MAX_PATH] = "";
char gLastLibrary[MAX_PATH] = "";

// ---------------------------------------------------------------------------
// Exception names.
// ---------------------------------------------------------------------------

const char *ExceptionName(DWORD code)
{
    switch (code)
    {
    case EXCEPTION_ACCESS_VIOLATION:         return "ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "FLT_UNDERFLOW";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:              return "SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "STACK_OVERFLOW";
    case 0xE06D7363:                         return "C++ exception (MSVC)";
    case 0x406D1388:                         return "thread name (debugger)";
    default:                                 return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Call-stack reconstruction.
//
// x86 GTA IV is built with frame-pointer omission in plenty of places, so an
// EBP chain walk alone drops frames and a stack scan alone invents them. Doing
// both and labelling which is which is the honest answer: frames marked
// [frame] came off the EBP chain and are trustworthy; those marked [scan] are
// stack slots that point just past a call instruction, which is strong
// evidence but not proof - leftovers from earlier, deeper calls look identical.
// ---------------------------------------------------------------------------

// Does `ret` look like it is preceded by a call instruction?
bool LooksLikeReturnAddress(uintptr_t ret)
{
    // Module lookup first: it is a handful of comparisons against an
    // in-memory table where ClassifyPage is a syscall, and this runs once per
    // scanned stack word. An address in no loaded module is one we could not
    // name anyway.
    if (!ModuleForAddress(ret))
        return false;
    if (ClassifyPage(ret) != kPageExecutable)
        return false;

    uint8_t b[7];
    if (!SafeRead(reinterpret_cast<const void *>(ret - 7), b, sizeof(b)))
        return false;

    // b[i] holds the byte at ret-7+i, so ret-5 is b[2], ret-2 is b[5], etc.
    if (b[2] == 0xE8)                              return true;  // call rel32
    if (b[1] == 0xFF && (b[2] & 0x38) == 0x10)     return true;  // call [mem32]
    if (b[0] == 0xFF && (b[1] & 0x38) == 0x10)     return true;  // call [base+disp32]
    if (b[3] == 0xFF && (b[4] & 0x38) == 0x10)     return true;  // call [reg+disp8]
    if (b[4] == 0xFF && (b[5] & 0x38) == 0x10)     return true;  // call [reg]
    if (b[5] == 0xFF && (b[6] & 0x38) == 0x10)     return true;  // call reg
    if (b[1] == 0x9A)                              return true;  // far call

    return false;
}

struct StackBounds
{
    uintptr_t base = 0;   // lowest committed address
    uintptr_t limit = 0;  // one past the highest
    bool      valid = false;
};

StackBounds FindStackBounds(uintptr_t esp)
{
    StackBounds sb;

    MEMORY_BASIC_INFORMATION mbi{};
    if (ClassifyPage(esp, &mbi) == kPageBad)
        return sb;

    // The stack's committed region runs from the faulting ESP's region up to
    // the top of the allocation.
    sb.base  = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    sb.limit = sb.base + mbi.RegionSize;

    // Walk forward through adjacent committed pages of the same allocation.
    for (int guard = 0; guard < 64; guard++)
    {
        MEMORY_BASIC_INFORMATION next{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(sb.limit), &next, sizeof(next)) != sizeof(next))
            break;
        if (next.AllocationBase != mbi.AllocationBase || next.State != MEM_COMMIT)
            break;
        sb.limit += next.RegionSize;
    }

    sb.valid = sb.limit > esp;
    return sb;
}

void PrintCallStack(const CONTEXT *ctx, const StackBounds &sb)
{
    Rule("Call stack");
    Emit("  Frames marked [frame] came off the EBP chain and are reliable.\r\n"
         "  Frames marked [scan] are stack slots that point just after a call\r\n"
         "  instruction - strong evidence, but stale frames look the same.\r\n\r\n");

    char desc[MAX_PATH];
    int  index = 0;

    // #0 is always the faulting instruction itself.
    DescribeAddress(ctx->Eip, desc, sizeof(desc));
    Emitf("  #%-2d  0x%08X  %-40s  [fault]\r\n", index++, ctx->Eip, desc);

    // ---- EBP chain -------------------------------------------------------
    Emit("\r\n  Frame-pointer chain:\r\n");
    const int beforeFrames = index;
    uintptr_t ebp = ctx->Ebp;
    for (int depth = 0; depth < 64; depth++)
    {
        if (!sb.valid || ebp < sb.base || ebp + 8 > sb.limit || (ebp & 3))
            break;

        uint32_t nextEbp = 0, ret = 0;
        if (!SafeReadU32(ebp, &nextEbp) || !SafeReadU32(ebp + 4, &ret))
            break;
        if (!ret)
            break;

        if (ClassifyPage(ret) == kPageExecutable)
        {
            DescribeAddress(ret, desc, sizeof(desc));
            Emitf("  #%-2d  0x%08X  %-40s  [frame]\r\n", index++, ret, desc);
        }

        if (nextEbp <= ebp)  // chain must climb, or it is garbage
            break;
        ebp = nextEbp;
    }

    if (index == beforeFrames)
        Emit("    (none - the faulting frames omit the frame pointer)\r\n");

    // ---- stack scan ------------------------------------------------------
    //
    // Listed shallowest-first, so the entries nearest ESP are the innermost
    // calls. This is where FPO frames the chain above could not see turn up.
    Emit("\r\n  Stack scan, shallowest first:\r\n");
    const int beforeScan = index;

    int scanned = 0;
    for (uintptr_t p = ctx->Esp; p + 4 <= sb.limit && scanned < gCfg.scanWords; p += 4, scanned++)
    {
        uint32_t v = 0;
        if (!SafeReadU32(p, &v))
            continue;
        if (!LooksLikeReturnAddress(v))
            continue;

        DescribeAddress(v, desc, sizeof(desc));
        Emitf("  #%-2d  0x%08X  %-40s  [scan]  esp+0x%X\r\n",
              index++, v, desc, static_cast<unsigned>(p - ctx->Esp));

        if (index > 80)
        {
            Emit("  ... truncated\r\n");
            break;
        }
    }

    if (index == beforeScan)
        Emit("    (nothing on the stack looks like a return address)\r\n");
}

// ---------------------------------------------------------------------------
// The verdict.
//
// This is the section the whole file exists for. Counting, per module, how
// many pointers into it appear anywhere in the faulting stack is the same
// analysis that otherwise means opening the .dmp by hand - so do it here and
// print the conclusion in plain words.
// ---------------------------------------------------------------------------

void PrintVerdict(const CONTEXT *ctx, const StackBounds &sb, uintptr_t faultAddr)
{
    for (int i = 0; i < gModuleCount; i++)
        gModules[i].stackHits = 0;

    int scanned = 0;
    if (sb.valid)
    {
        for (uintptr_t p = ctx->Esp; p + 4 <= sb.limit && scanned < gCfg.scanWords; p += 4, scanned++)
        {
            uint32_t v = 0;
            if (!SafeReadU32(p, &v))
                continue;
            for (int i = 0; i < gModuleCount; i++)
            {
                if (v >= gModules[i].base && v < gModules[i].base + gModules[i].size)
                {
                    gModules[i].stackHits++;
                    break;
                }
            }
        }
    }

    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&PrintVerdict), &self);
    const ModuleRec *selfMod  = ModuleForAddress(reinterpret_cast<uintptr_t>(self));
    const ModuleRec *faultMod = ModuleForAddress(faultAddr);

    Rule("Verdict");

    if (faultMod)
        Emitf("  Faulting instruction is in %s.\r\n", faultMod->name);
    else
        Emit("  Faulting instruction is not inside any loaded module (bad jump?).\r\n");

    const int selfHits = selfMod ? selfMod->stackHits : 0;
    if (selfMod)
    {
        if (selfHits == 0 && faultMod != selfMod)
            Emitf("  NOT TACEPATCH: no pointers into %s appear anywhere in the\r\n"
                  "  faulting stack (%d words scanned).\r\n", selfMod->name, scanned);
        else
            Emitf("  *** %s APPEARS IN THE FAULTING STACK (%d pointer(s)). ***\r\n"
                  "  Treat TacePatch as a suspect and read the call stack below.\r\n",
                  selfMod->name, selfHits);
    }

    Emit("\r\n  Modules present in the faulting stack, by pointer count:\r\n");

    // Simple selection sort over a small table - no CRT qsort, no comparator
    // callback running in a crashed process.
    for (int shown = 0; shown < 12; shown++)
    {
        int best = -1;
        for (int i = 0; i < gModuleCount; i++)
        {
            if (gModules[i].stackHits <= 0)
                continue;
            if (best < 0 || gModules[i].stackHits > gModules[best].stackHits)
                best = i;
        }
        if (best < 0)
            break;

        Emitf("    %-28s %5d\r\n", gModules[best].name, gModules[best].stackHits);
        gModules[best].stackHits = -gModules[best].stackHits;  // mark as printed
    }

    for (int i = 0; i < gModuleCount; i++)
        if (gModules[i].stackHits < 0)
            gModules[i].stackHits = -gModules[i].stackHits;
}

// ---------------------------------------------------------------------------
// Register and stack dumps.
// ---------------------------------------------------------------------------

// Renders a float without the CRT: sign, integer part, four decimals. Enough
// to recognise a coordinate, a health value or a garbage bit pattern, which is
// all a crash log needs from a vector register.
void FormatFloat(float v, char *out)
{
    uint32_t bits;
    memcpy(&bits, &v, sizeof(bits));

    const uint32_t exponent = (bits >> 23) & 0xFF;
    if (exponent == 0xFF)
    {
        lstrcpynA(out, (bits & 0x7FFFFF) ? "nan" : ((bits >> 31) ? "-inf" : "inf"), 8);
        return;
    }

    // Anything outside this range says "not a real float" more clearly as raw
    // bits than as a wall of digits.
    float a = (bits >> 31) ? -v : v;
    if (a >= 1.0e9f)
    {
        wsprintfA(out, "0x%08X", bits);
        return;
    }

    const int   whole = static_cast<int>(a);
    const int   frac  = static_cast<int>((a - static_cast<float>(whole)) * 10000.0f + 0.5f);
    const char *sign  = (bits >> 31) && (whole || frac) ? "-" : "";
    wsprintfA(out, "%s%d.%04d", sign, whole, frac);
}

void PrintRegisters(const CONTEXT *ctx)
{
    char eipDesc[MAX_PATH];
    DescribeAddress(ctx->Eip, eipDesc, sizeof(eipDesc));

    Rule("Registers");
    Emitf("  EAX 0x%08X   EBX 0x%08X   ECX 0x%08X   EDX 0x%08X\r\n",
          ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx);
    Emitf("  ESI 0x%08X   EDI 0x%08X   EBP 0x%08X   ESP 0x%08X\r\n",
          ctx->Esi, ctx->Edi, ctx->Ebp, ctx->Esp);
    Emitf("  EIP 0x%08X   EFL 0x%08X   (%s)\r\n", ctx->Eip, ctx->EFlags, eipDesc);
    Emitf("  CS %04X  DS %04X  ES %04X  FS %04X  GS %04X  SS %04X\r\n",
          ctx->SegCs, ctx->SegDs, ctx->SegEs, ctx->SegFs, ctx->SegGs, ctx->SegSs);

    // The eight XMM registers live at offset 160 of ExtendedRegisters, 16
    // bytes each. (FLA's handler prints XMM0 eight times here - it never
    // advances the pointer by the register index.)
    if (ctx->ContextFlags & CONTEXT_EXTENDED_REGISTERS)
    {
        Emit("\r\n  XMM registers:\r\n");
        for (int i = 0; i < 8; i++)
        {
            const BYTE *x = ctx->ExtendedRegisters + 160 + i * 16;
            Emitf("    XMM%d ", i);
            for (int b = 0; b < 16; b++)
                Emitf("%02X ", x[b]);

            // Also read them as the four floats they almost always are in
            // a game's SSE code. Formatted by hand: the CRT's %f can take the
            // locale lock on first use, and that is not a risk worth running
            // in a process that has already died.
            float f[4];
            memcpy(f, x, sizeof(f));
            Emit(" |");
            for (int c = 0; c < 4; c++)
            {
                char fs[32];
                FormatFloat(f[c], fs);
                Emitf(" %s", fs);
            }
            Emit("\r\n");
        }
    }

    if (ctx->ContextFlags & CONTEXT_FLOATING_POINT)
    {
        Emitf("\r\n  FPU  CTRL %04X  STAT %04X  TAGS %04X\r\n",
              static_cast<unsigned>(ctx->FloatSave.ControlWord),
              static_cast<unsigned>(ctx->FloatSave.StatusWord),
              static_cast<unsigned>(ctx->FloatSave.TagWord));
        for (int i = 0; i < 8; i++)
        {
            const BYTE *st = ctx->FloatSave.RegisterArea + i * 10;
            Emitf("    ST%d ", i);
            for (int b = 0; b < 10; b++)
                Emitf("%02X ", st[b]);
            Emit("\r\n");
        }
    }
}

// Annotate one stack slot: what does this value look like?
void AnnotateValue(uint32_t v, char *out, size_t outSize)
{
    out[0] = '\0';

    const ModuleRec *m = ModuleForAddress(v);
    if (m)
    {
        const bool isCode = ClassifyPage(v) == kPageExecutable;
        wsprintfA(out, "-> %s+0x%X%s", m->name, static_cast<unsigned>(v - m->base),
                  isCode ? " (code)" : "");
        return;
    }

    const PageKind k = ClassifyPage(v);
    if (k == kPageBad)
        return;

    // A readable pointer - is it text? Printable ASCII is nearly always a
    // filename or a model name in this engine, and that is worth surfacing.
    char text[40];
    if (SafeRead(reinterpret_cast<const void *>(v), text, sizeof(text) - 1))
    {
        text[sizeof(text) - 1] = '\0';
        int printable = 0;
        while (printable < 32 && text[printable] >= 0x20 && text[printable] < 0x7F)
            printable++;
        if (printable >= 4 && text[printable] == '\0')
        {
            text[printable] = '\0';
            wsprintfA(out, "-> \"%s\"", text);
            return;
        }
    }

    lstrcpynA(out, "-> data", static_cast<int>(outSize));
}

void PrintStack(const CONTEXT *ctx, const StackBounds &sb)
{
    Rule("Stack (annotated)");

    if (!sb.valid)
    {
        Emit("  Stack bounds could not be determined.\r\n");
        return;
    }

    Emitf("  ESP = 0x%08X   committed region 0x%08X - 0x%08X\r\n\r\n",
          ctx->Esp, static_cast<unsigned>(sb.base), static_cast<unsigned>(sb.limit));

    uintptr_t p = ctx->Esp & ~3u;
    for (int i = 0; i < gCfg.stackWords && p + 4 <= sb.limit; i++, p += 4)
    {
        uint32_t v = 0;
        if (!SafeReadU32(p, &v))
        {
            Emitf("  +0x%03X  <unreadable>\r\n", static_cast<unsigned>(p - ctx->Esp));
            continue;
        }

        char note[128];
        AnnotateValue(v, note, sizeof(note));
        Emitf("  +0x%03X  0x%08X  %s\r\n", static_cast<unsigned>(p - ctx->Esp), v, note);
    }
}

void PrintModules()
{
    Rule("Modules");
    Emitf("  %d loaded.\r\n\r\n", gModuleCount);
    Emit("  Base       End        Size       Name\r\n");

    for (int i = 0; i < gModuleCount; i++)
    {
        const ModuleRec &m = gModules[i];
        Emitf("  0x%08X 0x%08X 0x%08X %s\r\n",
              static_cast<unsigned>(m.base),
              static_cast<unsigned>(m.base + m.size),
              static_cast<unsigned>(m.size),
              m.name);
    }

    Emit("\r\n  Full paths:\r\n");
    for (int i = 0; i < gModuleCount; i++)
        Emitf("    %s\r\n", gModules[i].path[0] ? gModules[i].path : gModules[i].name);
}

void PrintModState()
{
    Rule("TacePatch state");

    if (gState.applied < 0)
    {
        Emit("  Crashed before the patch pass finished - the mod was still\r\n"
             "  initialising when the game died.\r\n");
    }
    else
    {
        Emitf("  Patches: %d applied, %d already open, %d not found, %d ambiguous\r\n",
              gState.applied, gState.already, gState.missing, gState.ambiguous);

        if (gState.failedCount)
        {
            Emit("  Signatures that did not match:\r\n");
            for (int i = 0; i < gState.failedCount; i++)
                Emitf("    - %s\r\n", gState.failed[i]);
            if (gState.failedOverflow)
                Emitf("    ... and %d more\r\n", gState.failedOverflow);
        }
    }

    for (int i = 0; i < gState.noteCount; i++)
        Emitf("  %-22s %s\r\n", gState.noteKey[i], gState.noteVal[i]);
}

// ---------------------------------------------------------------------------
// Chained handlers.
//
// We must run first - a handler that terminates the process leaves nothing for
// anyone after it - but we must not be the only one to run, or ZolikaPatch's
// .dmp files stop appearing. So: stay top-level, then call the handlers we
// displaced ourselves, in the order they would have run.
//
// Staying top-level without patching code is done by re-asserting: a small
// watchdog re-installs our filter periodically and records whatever it finds
// in our place. Everything loads during startup, so this converges in seconds
// and costs an interlocked pointer swap per tick.
// ---------------------------------------------------------------------------

constexpr int kMaxChained = 8;

LPTOP_LEVEL_EXCEPTION_FILTER gChained[kMaxChained];
volatile LONG                gChainCount = 0;
LPTOP_LEVEL_EXCEPTION_FILTER gOurFilter = nullptr;
bool                         gFilterSticks = false;

void RememberDisplaced(LPTOP_LEVEL_EXCEPTION_FILTER f)
{
    if (!f || f == gOurFilter)
        return;
    for (LONG i = 0; i < gChainCount; i++)
        if (gChained[i] == f)
            return;
    const LONG slot = gChainCount;
    if (slot < kMaxChained)
    {
        gChained[slot] = f;
        InterlockedIncrement(&gChainCount);
    }
}

DWORD WINAPI ReassertThread(LPVOID)
{
    bool reportedSuppression = false;

    // Tight for the ASI load window, then a slow heartbeat.
    for (int tick = 0;; tick++)
    {
        Sleep(tick < 60 ? 500 : 5000);

        LPTOP_LEVEL_EXCEPTION_FILTER prev = SetUnhandledExceptionFilter(gOurFilter);
        if (prev == gOurFilter)
            continue;

        RememberDisplaced(prev);

        // A NULL previous filter means the slot was cleared rather than taken
        // by another mod, which is the suppression case - and it repeats every
        // single tick. Say it once.
        if (!prev)
        {
            if (!reportedSuppression)
            {
                reportedSuppression = true;
                TACE_WARN("[crash] the top-level filter keeps being cleared - "
                          "the vectored handler is what will catch crashes here");
            }
            continue;
        }

        TACE_TRACE("[crash] re-asserted the top-level filter (displaced by %p)", prev);
    }
}

// ---------------------------------------------------------------------------
// Minidump. dbghelp is resolved during Init - calling LoadLibrary from inside
// an exception filter can deadlock against the loader lock.
// ---------------------------------------------------------------------------

typedef BOOL(WINAPI *PFN_MiniDumpWriteDump)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                                            PMINIDUMP_EXCEPTION_INFORMATION,
                                            PMINIDUMP_USER_STREAM_INFORMATION,
                                            PMINIDUMP_CALLBACK_INFORMATION);

PFN_MiniDumpWriteDump gMiniDumpWriteDump = nullptr;

void WriteMiniDump(const char *path, EXCEPTION_POINTERS *ep)
{
    if (!gMiniDumpWriteDump)
        return;

    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return;

    MINIDUMP_EXCEPTION_INFORMATION mei{};
    mei.ThreadId          = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers    = FALSE;

    MINIDUMP_TYPE type = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory |
        MiniDumpWithProcessThreadData | MiniDumpWithUnloadedModules);

    if (gCfg.fullDump)
        type = static_cast<MINIDUMP_TYPE>(MiniDumpWithFullMemory | MiniDumpWithHandleData);

    gMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), h, type, &mei, nullptr, nullptr);
    CloseHandle(h);
}

// ---------------------------------------------------------------------------
// IAT hooks for last-file / last-library. A pointer swap in the import table
// rather than a code detour: nothing is written to executable memory, so it
// cannot collide with another mod's hook on the same function.
// ---------------------------------------------------------------------------

// Case-insensitive substring search. shlwapi's StrStrIA would do, but it is
// not worth a new import on the game's file-open path.
const char *StrStrIA_Lite(const char *haystack, const char *needle)
{
    for (; *haystack; haystack++)
    {
        const char *h = haystack;
        const char *n = needle;
        while (*n && *h && (*h | 0x20) == (*n | 0x20))
        {
            h++;
            n++;
        }
        if (!*n)
            return haystack;
    }
    return nullptr;
}

HANDLE(WINAPI *RealCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
HANDLE(WINAPI *RealCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
HMODULE(WINAPI *RealLoadLibraryA)(LPCSTR) = LoadLibraryA;
HMODULE(WINAPI *RealLoadLibraryExW)(LPCWSTR, HANDLE, DWORD) = LoadLibraryExW;

// TacePatch's own log and crash files go through CreateFile too, and ours are
// usually the most recent write - which would otherwise hide the game's last
// asset behind our own filename in every crash log. Matched against the
// module's real stem rather than the literal string "TacePatch", so a renamed
// .asi still recognises its own files.
char gSelfStem[64] = "";

bool IsOurOwnFile(const char *path)
{
    if (!path)
        return true;
    if (!gSelfStem[0])
        return false;

    const char *leaf = path;
    for (const char *c = path; *c; c++)
        if (*c == '\\' || *c == '/')
            leaf = c + 1;
    return StrStrIA_Lite(leaf, gSelfStem) != nullptr;
}

HANDLE WINAPI HookCreateFileA(LPCSTR name, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa,
                              DWORD c, DWORD f, HANDLE t)
{
    if (name && !IsOurOwnFile(name))
        lstrcpynA(gLastFileA, name, sizeof(gLastFileA));
    return RealCreateFileA(name, a, s, sa, c, f, t);
}

HANDLE WINAPI HookCreateFileW(LPCWSTR name, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa,
                              DWORD c, DWORD f, HANDLE t)
{
    if (name)
    {
        char narrow[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, name, -1, narrow, sizeof(narrow), nullptr, nullptr);
        if (!IsOurOwnFile(narrow))
            lstrcpynA(gLastFileW, narrow, sizeof(gLastFileW));
    }
    return RealCreateFileW(name, a, s, sa, c, f, t);
}

HMODULE WINAPI HookLoadLibraryA(LPCSTR name)
{
    if (name)
        lstrcpynA(gLastLibrary, name, sizeof(gLastLibrary));
    return RealLoadLibraryA(name);
}

HMODULE WINAPI HookLoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    if (name)
        WideCharToMultiByte(CP_ACP, 0, name, -1, gLastLibrary, sizeof(gLastLibrary), nullptr, nullptr);
    return RealLoadLibraryExW(name, file, flags);
}

// Swaps one IAT slot in `module`, returning the original through `original`.
// (declared above IsOurOwnFile's use site by the helper below)
bool PatchIatEntry(HMODULE module, const char *dll, const char *symbol,
                   void *replacement, void **original)
{
    auto *base = reinterpret_cast<BYTE *>(module);
    auto *dos  = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    const auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress)
        return false;

    auto *desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(base + dir.VirtualAddress);
    for (; desc->Name; desc++)
    {
        const char *name = reinterpret_cast<const char *>(base + desc->Name);
        if (lstrcmpiA(name, dll) != 0)
            continue;

        auto *thunk     = reinterpret_cast<IMAGE_THUNK_DATA *>(base + desc->FirstThunk);
        auto *nameThunk = reinterpret_cast<IMAGE_THUNK_DATA *>(
            base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));

        for (; thunk->u1.Function; thunk++, nameThunk++)
        {
            if (IMAGE_SNAP_BY_ORDINAL(nameThunk->u1.Ordinal))
                continue;

            auto *import = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(base + nameThunk->u1.AddressOfData);
            if (lstrcmpA(reinterpret_cast<const char *>(import->Name), symbol) != 0)
                continue;

            DWORD old = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(void *), PAGE_READWRITE, &old))
                return false;

            *original = reinterpret_cast<void *>(thunk->u1.Function);
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            VirtualProtect(&thunk->u1.Function, sizeof(void *), old, &old);
            return true;
        }
    }

    return false;
}

void InstallFileTracking()
{
    HMODULE exe = GetModuleHandleA(nullptr);
    int hooked = 0;

    // The import may be listed against either kernel32 or the API-set stub,
    // depending on how the binary was linked - try both spellings.
    static const char *kDlls[] = {"kernel32.dll", "api-ms-win-core-file-l1-1-0.dll",
                                  "api-ms-win-core-libraryloader-l1-1-0.dll"};

    for (const char *dll : kDlls)
    {
        if (PatchIatEntry(exe, dll, "CreateFileA", &HookCreateFileA, reinterpret_cast<void **>(&RealCreateFileA))) hooked++;
        if (PatchIatEntry(exe, dll, "CreateFileW", &HookCreateFileW, reinterpret_cast<void **>(&RealCreateFileW))) hooked++;
        if (PatchIatEntry(exe, dll, "LoadLibraryA", &HookLoadLibraryA, reinterpret_cast<void **>(&RealLoadLibraryA))) hooked++;
        if (PatchIatEntry(exe, dll, "LoadLibraryExW", &HookLoadLibraryExW, reinterpret_cast<void **>(&RealLoadLibraryExW))) hooked++;
    }

    TACE_TRACE("[crash] file tracking: %d import(s) hooked", hooked);
}

// ---------------------------------------------------------------------------
// The handler itself.
// ---------------------------------------------------------------------------

DWORD gStartTick = 0;

void BuildHeader(EXCEPTION_POINTERS *ep, const char *when, bool unhandled)
{
    const EXCEPTION_RECORD *er  = ep->ExceptionRecord;
    const CONTEXT          *ctx = ep->ContextRecord;

    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&BuildHeader), &self);

    Emit("================================================================\r\n");
    Emit(" TacePatch crash log\r\n");
    Emit("================================================================\r\n");
    Emitf(" Time             : %s\r\n", when);
    if (unhandled)
        Emit(" Trigger          : UNHANDLED - nothing handled this, it is what"
             " killed the process\r\n");
    else
        Emit(" Trigger          : FIRST-CHANCE - seen before any handler ran."
             " The game may\r\n"
             "                    still recover from this one; check whether"
             " it actually died.\r\n");

    const DWORD ms = GetTickCount() - gStartTick;
    Emitf(" Uptime           : %02d:%02d:%02d\r\n",
          ms / 3600000, (ms / 60000) % 60, (ms / 1000) % 60);
    Emitf(" Process / thread : %d / %d\r\n", GetCurrentProcessId(), GetCurrentThreadId());

    const ModuleRec *exe = ModuleForAddress(reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)));
    if (exe)
        Emitf(" Game module      : %s at 0x%08X\r\n", exe->name, static_cast<unsigned>(exe->base));

    const ModuleRec *me = ModuleForAddress(reinterpret_cast<uintptr_t>(self));
    if (me)
        Emitf(" TacePatch        : %s at 0x%08X - 0x%08X\r\n", me->name,
              static_cast<unsigned>(me->base), static_cast<unsigned>(me->base + me->size));

    Emitf(" Last file opened : %s\r\n", gLastFileW[0] ? gLastFileW : (gLastFileA[0] ? gLastFileA : "<not recorded>"));
    Emitf(" Last library     : %s\r\n", gLastLibrary[0] ? gLastLibrary : "<not recorded>");

    Rule("Exception");

    char addrDesc[MAX_PATH];
    DescribeAddress(reinterpret_cast<uintptr_t>(er->ExceptionAddress), addrDesc, sizeof(addrDesc));

    Emitf("  Code    : 0x%08X  %s\r\n", er->ExceptionCode, ExceptionName(er->ExceptionCode));
    Emitf("  Address : 0x%08X  %s\r\n",
          static_cast<unsigned>(reinterpret_cast<uintptr_t>(er->ExceptionAddress)), addrDesc);
    Emitf("  Flags   : 0x%08X%s\r\n", er->ExceptionFlags,
          (er->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? "  (non-continuable)" : "");

    if ((er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
         er->ExceptionCode == EXCEPTION_IN_PAGE_ERROR) &&
        er->NumberParameters >= 2)
    {
        // ExceptionInformation[0] is 0 read, 1 write, 8 DEP violation.
        // Anything else is undocumented and must not index a table.
        const ULONG_PTR op = er->ExceptionInformation[0];
        const char *opName = op == 0 ? "read of"
                           : op == 1 ? "write to"
                           : op == 8 ? "execute of"
                                     : "access of";
        Emitf("  Detail  : %s 0x%08X\r\n", opName,
              static_cast<unsigned>(er->ExceptionInformation[1]));

        if (er->ExceptionInformation[1] < 0x10000)
            Emit("            (near-null - almost always an unchecked pointer\r\n"
                 "            returned by a lookup that failed)\r\n");
    }

    // Bytes at the faulting instruction, so the opcode can be identified
    // without loading the dump.
    uint8_t code[16];
    if (SafeRead(reinterpret_cast<const void *>(ctx->Eip), code, sizeof(code)))
    {
        Emit("  Opcode  :");
        for (int i = 0; i < 16; i++)
            Emitf(" %02X", code[i]);
        Emit("\r\n");
    }
}

// How the report was reached. The distinction matters: a top-level filter
// only runs for an exception nothing handled, so it is definitely what killed
// the process. A vectored handler sees exceptions first-chance, before anyone
// has had the chance to handle them - so the game may well recover from what
// it reports.
enum ReportTrigger
{
    kTriggerUnhandled,
    kTriggerFirstChance,
};

volatile LONG gReportBusy  = 0;
volatile LONG gReportCount = 0;

void WriteReport(EXCEPTION_POINTERS *ep, ReportTrigger trigger)
{
    _fpreset();  // the FPU may be in a state that breaks our own float use

    SYSTEMTIME st{};
    GetLocalTime(&st);

    char when[64];
    wsprintfA(when, "%04d-%02d-%02d %02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    char stamp[32];
    wsprintfA(stamp, "%04d%02d%02d_%02d%02d%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    gOutLen = 0;
    BuildModuleTable();

    const CONTEXT *ctx = ep->ContextRecord;
    const StackBounds sb = FindStackBounds(ctx->Esp);

    BuildHeader(ep, when, trigger == kTriggerUnhandled);
    PrintVerdict(ctx, sb, reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress));
    PrintCallStack(ctx, sb);
    PrintModState();
    PrintRegisters(ctx);
    PrintStack(ctx, sb);
    PrintModules();

    Emit("\r\n================================================================\r\n"
         " End of crash log. Please send the whole file, not a screenshot.\r\n"
         "================================================================\r\n");

    // The folder is created on demand rather than at startup, so a run with no
    // crashes leaves nothing behind. If it cannot be created - read-only game
    // directory, say - fall back to writing beside the .asi rather than
    // losing the report entirely.
    char dir[MAX_PATH];
    lstrcpynA(dir, gCfg.dir, sizeof(dir));
    if (!CreateDirectoryA(dir, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        lstrcpynA(dir, gCfg.dir, sizeof(dir));
        if (char *slash = strrchr(dir, '\\'))
            *slash = '\0';
    }

    const char *kind = trigger == kTriggerUnhandled ? "" : "_firstchance";

    char path[MAX_PATH];
    wsprintfA(path, "%s\\TacePatch_%s%s.log", dir, stamp, kind);

    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(h, gOut, static_cast<DWORD>(gOutLen), &written, nullptr);
        FlushFileBuffers(h);
        CloseHandle(h);
    }

    // A .dmp per first-chance exception would be tens of megabytes each, for
    // exceptions the game is probably about to handle. Only the real thing
    // gets one unless the ini says otherwise.
    if (gCfg.miniDump && (trigger == kTriggerUnhandled || gCfg.vehMiniDump))
    {
        char dmp[MAX_PATH];
        wsprintfA(dmp, "%s\\TacePatch_%s%s.dmp", dir, stamp, kind);
        WriteMiniDump(dmp, ep);
    }
}

bool ShouldReport(EXCEPTION_POINTERS *ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return false;
    if (gReportCount >= gCfg.maxLogs)
        return false;
    return true;
}

LONG WINAPI TaceCrashFilter(EXCEPTION_POINTERS *ep)
{
    if (!ShouldReport(ep))
        return EXCEPTION_CONTINUE_SEARCH;

    // A crash inside the crash handler must not loop.
    if (InterlockedExchange(&gReportBusy, 1) != 0)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&gReportCount);
    WriteReport(ep, kTriggerUnhandled);
    InterlockedExchange(&gReportBusy, 0);

    // Now let everyone we displaced write theirs. Ours is already on disk, so
    // a handler that terminates the process costs us nothing.
    if (gCfg.chain)
    {
        for (LONG i = gChainCount - 1; i >= 0; i--)
        {
            if (!gChained[i])
                continue;
            const LONG r = gChained[i](ep);
            if (r != EXCEPTION_CONTINUE_SEARCH)
                return r;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Only the codes that mean something has genuinely gone wrong. Debugger and
// C++ exception codes are routine traffic in a running process and must never
// produce a crash log.
bool IsFatalCode(DWORD code)
{
    switch (code)
    {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_INVALID_DISPOSITION:
        return true;
    default:
        return false;
    }
}

// The vectored handler.
//
// The top-level filter is not reliable in a modded GTA IV: something in this
// install keeps SetUnhandledExceptionFilter returning NULL, so the filter we
// register is never the one that runs. A vectored handler cannot be displaced
// that way - it is a separate list, and ours stays on it.
//
// The cost is that it fires first-chance, before anyone has had a chance to
// handle the exception, so a report from here is evidence rather than proof.
// It is labelled as such in the log, it never writes a .dmp by default, and it
// ALWAYS returns EXCEPTION_CONTINUE_SEARCH - observing only, never altering
// what the process would have done.
LONG CALLBACK TaceVectoredHandler(EXCEPTION_POINTERS *ep)
{
    if (!ep || !ep->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!IsFatalCode(ep->ExceptionRecord->ExceptionCode))
        return EXCEPTION_CONTINUE_SEARCH;
    if (!ShouldReport(ep))
        return EXCEPTION_CONTINUE_SEARCH;

    if (InterlockedExchange(&gReportBusy, 1) != 0)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&gReportCount);
    WriteReport(ep, kTriggerFirstChance);
    InterlockedExchange(&gReportBusy, 0);

    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

void CrashLog_SetPatchStats(int applied, int already, int missing, int ambiguous)
{
    gState.applied   = applied;
    gState.already   = already;
    gState.missing   = missing;
    gState.ambiguous = ambiguous;
}

void CrashLog_NoteFailedPatch(const char *what)
{
    if (!what)
        return;
    if (gState.failedCount >= kMaxFailedPatches)
    {
        gState.failedOverflow++;
        return;
    }
    lstrcpynA(gState.failed[gState.failedCount], what, sizeof(gState.failed[0]));
    gState.failedCount++;
}

void CrashLog_SetNote(const char *key, const char *value)
{
    if (!key || !value)
        return;

    for (int i = 0; i < gState.noteCount; i++)
    {
        if (lstrcmpA(gState.noteKey[i], key) == 0)
        {
            lstrcpynA(gState.noteVal[i], value, sizeof(gState.noteVal[0]));
            return;
        }
    }

    if (gState.noteCount >= kMaxNotes)
        return;

    lstrcpynA(gState.noteKey[gState.noteCount], key, sizeof(gState.noteKey[0]));
    lstrcpynA(gState.noteVal[gState.noteCount], value, sizeof(gState.noteVal[0]));
    gState.noteCount++;
}

bool CrashLog_Active()
{
    return gActive;
}

void CrashLog_Init()
{
    gStartTick = GetTickCount();

    gCfg.enabled    = TaceIniBool("DEBUG", "CrashLogger", true);
    gCfg.miniDump   = TaceIniBool("DEBUG", "CrashMiniDump", true);
    gCfg.fullDump   = TaceIniBool("DEBUG", "CrashFullDump", false);
    gCfg.trackFiles = TaceIniBool("DEBUG", "CrashTrackFiles", true);
    gCfg.chain      = TaceIniBool("DEBUG", "CrashChain", true);
    gCfg.veh        = TaceIniBool("DEBUG", "CrashVectored", true);
    gCfg.vehMiniDump = TaceIniBool("DEBUG", "CrashVectoredMiniDump", false);
    gCfg.maxLogs    = TaceIniInt("DEBUG", "CrashMaxLogs", 8);
    gCfg.stackWords = TaceIniInt("DEBUG", "CrashStackWords", 128);
    gCfg.scanWords  = TaceIniInt("DEBUG", "CrashScanWords", 4096);

    if (!gCfg.enabled)
    {
        TACE_INFO("[crash] crash logger disabled by ini");
        return;
    }

    if (gCfg.stackWords < 16)   gCfg.stackWords = 16;
    if (gCfg.stackWords > 4096) gCfg.stackWords = 4096;
    if (gCfg.scanWords < 256)   gCfg.scanWords = 256;
    if (gCfg.scanWords > 65536) gCfg.scanWords = 65536;
    if (gCfg.maxLogs < 1)       gCfg.maxLogs = 1;
    if (gCfg.maxLogs > 64)      gCfg.maxLogs = 64;

    // Output directory: next to the .asi unless the ini overrides it.
    {
        const std::string custom = TaceIniString("DEBUG", "CrashDir");
        if (!custom.empty())
        {
            lstrcpynA(gCfg.dir, custom.c_str(), sizeof(gCfg.dir));
        }
        else
        {
            char self[MAX_PATH]{};
            HMODULE hm = nullptr;
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(&CrashLog_Init), &hm);
            GetModuleFileNameA(hm, self, sizeof(self));

            // Remember the stem ("TacePatch") before trimming to the folder,
            // so the file tracker can recognise our own writes.
            if (const char *leaf = strrchr(self, '\\'))
            {
                lstrcpynA(gSelfStem, leaf + 1, sizeof(gSelfStem));
                if (char *dot = strrchr(gSelfStem, '.'))
                    *dot = '\0';
            }

            std::string dir = TaceFolder("Crashes");
            dir.pop_back();   // the paths built from it add their own separator
            lstrcpynA(gCfg.dir, dir.c_str(), sizeof(gCfg.dir));
        }
    }

    // dbghelp now, not at crash time - LoadLibrary inside an exception filter
    // can deadlock on the loader lock.
    if (gCfg.miniDump)
    {
        if (HMODULE dbg = LoadLibraryA("dbghelp.dll"))
            gMiniDumpWriteDump = reinterpret_cast<PFN_MiniDumpWriteDump>(
                GetProcAddress(dbg, "MiniDumpWriteDump"));
        if (!gMiniDumpWriteDump)
            TACE_WARN("[crash] dbghelp.dll has no MiniDumpWriteDump - no .dmp will be written");
    }

    // Reserve stack for the handler so a STACK_OVERFLOW still leaves room to
    // run it. Without this, the one crash class that most needs a log is the
    // one that cannot produce one.
    {
        ULONG guarantee = 64 * 1024;
        SetThreadStackGuarantee(&guarantee);
    }

    gOurFilter = &TaceCrashFilter;
    RememberDisplaced(SetUnhandledExceptionFilter(gOurFilter));

    // Does the top-level filter actually stick? Setting it again must hand
    // back what we just installed. In this game it does not: something keeps
    // SetUnhandledExceptionFilter returning NULL, so the filter we register is
    // never the one that runs, and the first in-game crash produced a
    // ZolikaPatch dump and no log of ours. Worth stating plainly at startup
    // rather than discovering it after the crash you needed.
    {
        LPTOP_LEVEL_EXCEPTION_FILTER readBack = SetUnhandledExceptionFilter(gOurFilter);
        gFilterSticks = (readBack == gOurFilter);
        if (!gFilterSticks)
            TACE_WARN("[crash] the top-level exception filter is being suppressed "
                      "(read back %p, not ours) - relying on the vectored handler",
                      readBack);
    }

    if (gCfg.veh)
    {
        // First in the list, so we see the exception before any handler that
        // might terminate the process. We only ever observe: the handler
        // always returns EXCEPTION_CONTINUE_SEARCH.
        if (AddVectoredExceptionHandler(1, &TaceVectoredHandler))
            TACE_TRACE("[crash] vectored handler installed");
        else
            TACE_WARN("[crash] AddVectoredExceptionHandler failed");
    }

    if (gCfg.trackFiles)
        InstallFileTracking();

    if (HANDLE t = CreateThread(nullptr, 0, &ReassertThread, nullptr, 0, nullptr))
        CloseHandle(t);

    gActive = true;
    TACE_OK("[crash] crash logger armed -> %s", gCfg.dir);

    // Deliberate crash, for verifying the logger without waiting for a real
    // one. Guarded by an explicit magic value so it cannot fire by accident.
    if (TaceIniInt("DEBUG", "CrashTest", 0) == 1337)
    {
        TACE_WARN("[crash] CrashTest = 1337 - raising a deliberate access violation");
        CrashLog_SetNote("crash test", "deliberate, triggered by [DEBUG] CrashTest = 1337");
        *reinterpret_cast<volatile int *>(4) = 0;
    }
}
