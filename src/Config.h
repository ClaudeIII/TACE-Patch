#pragma once

#include <windows.h>
#include <cstdlib>
#include <string>

// Shared TacePatch.ini access. Uses the Win32 profile API rather than
// deps/IniReader: that header needs std::string::starts_with (C++20) and this
// project builds as C++17.

inline const std::string &TaceIniPath()
{
    static const std::string path = []
    {
        char buf[MAX_PATH]{};
        HMODULE hm = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(&TaceIniPath), &hm);
        GetModuleFileNameA(hm, buf, MAX_PATH);

        std::string p = buf;
        const size_t dot = p.find_last_of('.');
        if (dot != std::string::npos)
            p = p.substr(0, dot);
        return p + ".ini";
    }();
    return path;
}

// Reads the raw value. Trailing "// ..." comments (FusionFix's ini layout) are
// left intact here and handled by the numeric parser below; string callers get
// them trimmed.
inline std::string TaceIniString(const char *section, const char *key, const char *def = "")
{
    char buf[256]{};
    GetPrivateProfileStringA(section, key, def, buf, sizeof(buf), TaceIniPath().c_str());

    std::string s = buf;
    const size_t comment = s.find("//");
    if (comment != std::string::npos)
        s.erase(comment);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.pop_back();
    return s;
}

// strtol stops at the first character that isn't part of the number, so the
// trailing "// ..." comments are ignored; anything unparseable falls back.
inline int TaceIniInt(const char *section, const char *key, int def)
{
    char buf[64]{};
    if (GetPrivateProfileStringA(section, key, "", buf, sizeof(buf), TaceIniPath().c_str()) == 0)
        return def;
    char *end = nullptr;
    const long v = strtol(buf, &end, 10);
    return (end == buf) ? def : static_cast<int>(v);
}

inline bool TaceIniBool(const char *section, const char *key, bool def)
{
    return TaceIniInt(section, key, def ? 1 : 0) != 0;
}
