#pragma once

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <string>

// Minimal append-only log next to the .asi. The limit adjusters patch code and
// pointers before the game has finished starting, so a crash leaves no other
// trace of which signature matched and which silently didn't.
inline void TaceLog(const char *fmt, ...)
{
    static std::string path = []
    {
        char buf[MAX_PATH]{};
        HMODULE module = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(&TaceLog), &module);
        GetModuleFileNameA(module, buf, MAX_PATH);

        std::string p = buf;
        size_t dot = p.find_last_of('.');
        if (dot != std::string::npos)
            p = p.substr(0, dot);
        return p + ".log";
    }();

    FILE *f = fopen(path.c_str(), "a");
    if (!f)
        return;

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fputc('\n', f);
    fclose(f);
}
