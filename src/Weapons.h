#pragma once

#include <cstdlib>
#include <cstring>
#include <string>

// Weapon ids from the GTA IV weapon enum, shared by the loadout features.
//
// The EPISODIC_n names are the engine's own; the aliases beside them are what
// those slots actually hold, which is what anyone editing an ini will look for.
struct NamedId { const char *name; int id; };

inline const NamedId kWeapons[] = {
    { "UNARMED", 0 }, { "BASEBALLBAT", 1 }, { "POOLCUE", 2 }, { "KNIFE", 3 },
    { "GRENADE", 4 }, { "MOLOTOV", 5 }, { "ROCKET", 6 }, { "PISTOL", 7 },
    { "DEAGLE", 9 }, { "SHOTGUN", 10 }, { "BARETTA", 11 }, { "MICRO_UZI", 12 },
    { "MP5", 13 }, { "AK47", 14 }, { "M4", 15 }, { "SNIPERRIFLE", 16 },
    { "M40A1", 17 }, { "RLAUNCHER", 18 }, { "FTHROWER", 19 }, { "MINIGUN", 20 },
    { "EPISODIC_1", 21 },  { "GRENADE_LAUNCHER", 21 },
    { "EPISODIC_2", 22 },  { "ASSAULT_SHOTGUN", 22 },
    { "EPISODIC_4", 24 },  { "BROKEN_POOL_CUE", 24 },
    { "EPISODIC_6", 26 },  { "SAWNOFF_SHOTGUN", 26 },
    { "EPISODIC_7", 27 },  { "AUTOMATIC_PISTOL", 27 },
    { "EPISODIC_8", 28 },  { "PIPE_BOMB", 28 },
    { "EPISODIC_9", 29 },  { "PISTOL_44", 29 },
    { "EPISODIC_11", 31 }, { "AA12", 31 },
    { "EPISODIC_12", 32 }, { "P90", 32 },
    { "EPISODIC_13", 33 }, { "GOLDEN_UZI", 33 },
    { "EPISODIC_14", 34 }, { "M249", 34 },
    { "EPISODIC_15", 35 }, { "ADVANCED_SNIPER", 35 },
    { "EPISODIC_16", 36 }, { "STICKY_BOMB", 36 },
};

// Accepts a name from the table above or a plain number.
inline bool LookUpNamed(const NamedId *table, size_t count, const std::string &token, int &out)
{
    if (!token.empty() && isdigit(static_cast<unsigned char>(token[0])) != 0)
    {
        out = atoi(token.c_str());
        return true;
    }
    for (size_t i = 0; i < count; i++)
    {
        if (_stricmp(table[i].name, token.c_str()) == 0)
        {
            out = table[i].id;
            return true;
        }
    }
    return false;
}

inline bool LookUpWeapon(const std::string &token, int &out)
{
    if (!LookUpNamed(kWeapons, sizeof(kWeapons) / sizeof(kWeapons[0]), token, out))
        return false;

    // A weapon id is written into a `push imm8` or a byte-wide displacement, so
    // anything above 127 would be sign-extended into a negative. Every real id
    // is far below that.
    return out >= 0 && out <= 127;
}

inline const char *WeaponName(int id)
{
    for (const NamedId &w : kWeapons)
        if (w.id == id)
            return w.name;
    return "?";
}

inline std::string TrimToken(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
    return s;
}
