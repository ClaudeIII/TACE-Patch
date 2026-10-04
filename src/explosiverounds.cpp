#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Config.h"
#include "Game.h"
#include "Log.h"
#include "Patterns.h"
#include "Weapons.h"
#include "rage/Hash.h"

// ============================================================================
// Explosive rounds, per weapon and per vehicle.
//
// Every instant-hit shot ends in one function (named SetWeaponExplosionEffects
// in the 1.0.8.0 database, called once from the weapon's fire code) that plays
// the impact effects. Its tail holds three hardcoded explosions at the hit
// point, all already opened to every episode by TacePatch's gate NOPs:
//
//   - weapon 30 (AA12 explosive shells)  -> explosion type 16, anyone firing
//   - weapon 40 (APC cannon)             -> explosion type 18, anyone firing
//   - a helicopter firing weapon 20 with the player at the controls
//                                        -> explosion type 17 (the Annihilator)
//
// Each only fires when the shot hit something. Those three addExplosion calls
// are turned into no-ops, and the function's one call site goes through a
// wrapper that runs it and then looks the shot up in the ini's tables instead.
// The tables default to exactly the three cases above.
// ============================================================================

namespace
{
    constexpr size_t kWeaponType     = 0x18;   // CWeapon
    constexpr size_t kEntityType     = 0x28;   // (x & 0x3C0): 0x80 vehicle, 0xC0 ped
    constexpr size_t kPedRemote      = 0x218;  // CPed::IsPlayer (misnamed GetPedType in the
    constexpr size_t kPedIsPlayer    = 0x219;  //   database): !remote && isPlayer
    constexpr size_t kVehicleDriver  = 0xFA0;
    constexpr size_t kHitPosition    = 0x10;   // phIntersection
    constexpr int    kAnnihilatorFx  = 17;     // vanilla passes its fx flag as 0 for this type only

    struct Rule
    {
        std::string model;      // vehicle rules only
        int  modelIndex = -1;
        int  weapon = -1;
        int  explosion = -1;    // -1 = none
        bool playerOnly = false;
    };

    std::vector<Rule> gWeaponRules;
    std::vector<Rule> gVehicleRules;
    bool gTrace = false;
    int  gTraceLeft = 0;

    using EffectsFn = void(__thiscall *)(uint8_t *weapon, uint8_t *shooter, void *matrix, uint8_t *hit, void *end, int noFx);
    using AddExplosionFn = char(__cdecl *)(int, uint8_t *, int, float, float *, char, int, int, float,
                                           int, int, int, int, int, char, char, int, char, int);
    using IsCloneFn = bool(__thiscall *)(uint8_t *entity);
    using ModelIndexFn = int(__cdecl *)(uint32_t hash);

    EffectsFn      gEffects = nullptr;
    AddExplosionFn gAddExplosion = nullptr;
    IsCloneFn      gIsClone = nullptr;
    ModelIndexFn   gModelIndex = nullptr;

    bool IsPlayerPed(const uint8_t *ped)
    {
        return ped != nullptr && ped[kPedRemote] == 0 && ped[kPedIsPlayer] != 0;
    }

    const Rule *FindRule(const uint8_t *shooter, int weapon, bool &byPlayer)
    {
        const uint32_t type = Field<uint32_t>(shooter, kEntityType) & 0x3C0;
        const uint8_t *player = shooter;
        if (type == 0x80)
        {
            player = Field<uint8_t *>(shooter, kVehicleDriver);
            const int model = Field<int16_t>(shooter, kEntityModel);
            for (Rule &r : gVehicleRules)
            {
                // Model names resolve once the model list is loaded, not at startup.
                if (r.modelIndex < 0)
                    r.modelIndex = gModelIndex(rage::atStringHash(r.model.c_str()));
                if (r.modelIndex == model && r.weapon == weapon)
                {
                    byPlayer = IsPlayerPed(player);
                    return &r;
                }
            }
        }
        else if (type != 0xC0)
        {
            player = nullptr;
        }

        byPlayer = IsPlayerPed(player);
        for (const Rule &r : gWeaponRules)
            if (r.weapon == weapon)
                return &r;
        return nullptr;
    }

    void __fastcall EffectsHook(uint8_t *weapon, void *, uint8_t *shooter, void *matrix, uint8_t *hit, void *end, int noFx)
    {
        gEffects(weapon, shooter, matrix, hit, end, noFx);

        if (shooter == nullptr || hit == nullptr || Field<void *>(hit, 0) == nullptr)
            return;

        const int type = Field<int>(weapon, kWeaponType);
        bool byPlayer = false;
        const Rule *rule = FindRule(shooter, type, byPlayer);
        if (rule == nullptr || rule->explosion < 0 || (rule->playerOnly && !byPlayer) || gIsClone(shooter))
            return;

        float *pos = reinterpret_cast<float *>(hit + kHitPosition);
        if (gTrace && gTraceLeft-- > 0)
            TACE_TRACE("[explosive] weapon %d (%s) -> explosion %d at %.1f %.1f %.1f",
                       type, rule->model.empty() ? "any shooter" : rule->model.c_str(), rule->explosion,
                       pos[0], pos[1], pos[2]);
        gAddExplosion(0, shooter, rule->explosion, 1.0f, pos, rule->explosion != kAnnihilatorFx, 0, 1, -1.0f,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, -1);
    }

    char __cdecl NoExplosion(int, uint8_t *, int, float, float *, char, int, int, float,
                             int, int, int, int, int, char, char, int, char, int)
    {
        return 0;
    }

    // [<model>:]<weapon>:<explosion>[:P]
    bool ParseRule(const std::string &entry, bool vehicle, Rule &r)
    {
        std::vector<std::string> parts = SplitList(entry, ':');
        if (vehicle)
        {
            r.model = parts[0];
            parts.erase(parts.begin());
            if (r.model.empty())
                return false;
        }
        if (parts.size() < 2 || parts.size() > 3 || !LookUpWeapon(parts[0], r.weapon))
            return false;
        char *end = nullptr;
        r.explosion = strtol(parts[1].c_str(), &end, 10);
        if (end == parts[1].c_str() || *end != 0 || r.explosion < -1 || r.explosion > 25)
            return false;
        r.playerOnly = parts.size() == 3;
        return !r.playerOnly || _stricmp(parts[2].c_str(), "P") == 0;
    }

    void LoadRules(const char *key, const char *def, bool vehicle, std::vector<Rule> &out)
    {
        for (const std::string &entry : SplitList(TaceIniString("EXPLOSIVEROUNDS", key, def)))
        {
            Rule r;
            if (entry.empty())
                continue;
            if (ParseRule(entry, vehicle, r))
                out.push_back(r);
            else
                TACE_WARN("[explosive] %s: \"%s\" is not %s<weapon>:<explosion>[:P] - skipped", key, entry.c_str(),
                          vehicle ? "<model>:" : "");
        }
    }
}

void ExplosiveRounds_Init()
{
    if (!TaceIniBool("EXPLOSIVEROUNDS", "Enabled", true))
    {
        TaceLog("[explosive] Enabled = 0 - explosive rounds as vanilla");
        return;
    }
    gTrace = TaceTraceEnabled("explosive");
    gTraceLeft = TaceTraceBudget(200);

    // CWeapon fire: push the five args ; mov ecx,edi ; call SetWeaponExplosionEffects
    auto site = find_pattern("51 53 55 52 56 8B CF E8 ? ? ? ? 8B 44 24");
    // its three explosions: push <type> ; push ebx ; push 0 ; call addExplosion ; add esp,4Ch
    auto annihilator = find_pattern("6A 11 53 6A 00 E8 ? ? ? ? 83 C4 4C");
    auto aa12        = find_pattern("6A 10 53 6A 00 E8 ? ? ? ? 83 C4 4C");
    auto apc         = find_pattern("6A 12 53 6A 00 E8 ? ? ? ? 83 C4 4C");
    // the AA12 case's network-clone check: mov ecx,ebx ; call ; test al,al ; jnz ; push -1 ; fld
    auto clone       = find_pattern("8B CB E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 6A FF D9 05");
    // CModelInfoStore::getModelIndexByKey
    auto modelIndex  = find_pattern("8B 44 24 04 89 44 24 04 66 A1 ? ? ? ? 66 85 C0 76 2B");
    if (site.empty() || annihilator.empty() || aa12.empty() || apc.empty() || clone.empty() || modelIndex.empty())
    {
        TaceLog("[explosive] signature not found (site %d, explosions %d/%d/%d, clone %d, models %d), not patched",
                int(site.size()), int(annihilator.size()), int(aa12.size()), int(apc.size()),
                int(clone.size()), int(modelIndex.size()));
        return;
    }

    uint8_t *call  = site.get_first<uint8_t>(7);
    uint8_t *calls[3] = { annihilator.get_first<uint8_t>(5), aa12.get_first<uint8_t>(5), apc.get_first<uint8_t>(5) };
    uint8_t *explosion = CallTarget(calls[0]);
    if (CallTarget(calls[1]) != explosion || CallTarget(calls[2]) != explosion)
    {
        TaceLog("[explosive] ABORTED - the three explosion calls don't share a target. Not patched.");
        return;
    }

    LoadRules("Weapons", "30:16, 40:18", false, gWeaponRules);
    LoadRules("Vehicles", "annihilator:20:17:P", true, gVehicleRules);
    gEffects      = reinterpret_cast<EffectsFn>(CallTarget(call));
    gAddExplosion = reinterpret_cast<AddExplosionFn>(explosion);
    gIsClone      = reinterpret_cast<IsCloneFn>(CallTarget(clone.get_first<uint8_t>(2)));
    gModelIndex   = reinterpret_cast<ModelIndexFn>(modelIndex.get_first<void>(0));

    for (uint8_t *c : calls)
        injector::MakeCALL(c, NoExplosion, true);
    injector::MakeCALL(call, EffectsHook, true);

    TaceLog("[explosive] OK - explosive rounds from the ini: %d weapon rules, %d vehicle rules",
            int(gWeaponRules.size()), int(gVehicleRules.size()));
}
