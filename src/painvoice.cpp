#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

#include "Config.h"
#include "rage/Hash.h"
#include "Log.h"
#include "Patterns.h"

// ============================================================================
// Per-model pain voices.
//
// GTA IV picks pain/death speech from a THREE-entry voice table:
//
//     slot 0  the player's own voice   (root bank name set by
//             SET_PLAYER_PAIN_ROOT_BANK_NAME, "NIKO" by default)
//     slot 1  "PAIN_MALE"
//     slot 2  "PAIN_FEMALE"
//
// The pain playback function chooses the slot purely from "is this ped the
// player" and the gender bit, so Johnny and Luis only ever sound like themselves
// while they ARE the player. As NPCs they fall back to PAIN_MALE, which is what
// this feature fixes.
//
// The slot owns residency: it has two wave slots, and the speech manager's
// preloader keeps one "<ROOT>_<NN>" bank streamed in at all times, double
// buffered, cycling the variation. That is why simply renaming the voice at
// playback time does nothing audible - the LUIS_xx bank is not resident because
// no slot ever asked for it. Both halves are needed.
//
// So this adds EXTRA slots (3, 4, ...) rather than rewriting the existing ones:
//
//   * per-slot state lives in this module, not in the game's fixed 3-slot block
//     inside audSpeechManager, so nothing has to be relocated or re-based;
//   * the five tiny per-slot accessors are replaced outright - each has exactly
//     ONE caller, the pain playback function, so this cannot affect anything
//     else - and answer out of our state for slots >= 3;
//   * the preloader is wrapped: the original still runs slots 0-2 untouched,
//     then we run the same algorithm over the extra slots;
//   * slot selection and the voice-name lookup inside playback are patched to
//     pick and name an extra slot for the configured models.
//
// There is a SECOND pain path, and it needs a separate fix. Alongside the pain
// bank, the game plays pain-adjacent speech CONTEXTS - ON_FIRE, HIGH_FALL,
// COUGH, DROWNING and friends - through audSpeechAudioEntity::playSpeech with a
// placeholder voice, PAIN_VOICE. PED_VOICES_EXTRAS resolves that placeholder:
//
//     if (ped is the local player)  ->  the player's own pain voice
//     else                         ->  PAIN_MALE_EXTRAS / PAIN_FEMALE_EXTRAS
//
// which is why an NPC Johnny still let out one generic male scream even with the
// bank side working. These use the ordinary streamed SPEECH_* wave slots, so no
// residency work is needed - only the voice hash. Both dispatcher call sites are
// wrapped below.
//
// A configured character is never allowed to make a generic ped noise. We try
// their own voices in turn and, if none of them has the context (PANIC_SHORT is
// the common one - the player never panics, so it was never recorded for a pain
// voice), we still return one of theirs, so the lookup finds nothing and the
// sound is simply dropped.
//
// Each extra slot needs two wave slots of its own, and wave slots come from
// pc/audio/config/waveslots.xml - see assets/waveslots-painvoice.xml. If they
// are absent, or the episode's speech data does not contain the bank (JOHNNY_xx
// only ships in TLAD's audio, LUIS_xx only in TBoGT's), the slot never becomes
// ready and selection falls back to the vanilla PAIN_MALE / PAIN_FEMALE choice -
// so a missing bank costs the character his own voice, never silence.
// ============================================================================

namespace
{
    // ---- audSpeechManager per-slot state block, byte offsets from `this` ----
    // Confirmed against the preloader's own addressing: 0x4FC / 0x500 for
    // entry+4 / entry+8, 0x540 current entry, 0x543 variation, 0x548 cooldown.
    constexpr size_t kEntries   = 1272;   // entry e of slot i at +24*i +12*e
    constexpr size_t kCurEntry  = 1344;   // 1 byte per slot
    constexpr size_t kVariation = 1347;   // 1 byte per slot
    constexpr size_t kCooldown  = 1352;   // 4 bytes per slot
    constexpr size_t kIndex     = 1364;   // 4 bytes per slot, one per pain type
    constexpr size_t kCounter   = 1376;   // 4 bytes per slot, one per pain type

    constexpr int kGameSlots     = 3;
    constexpr int kMaxExtraSlots = 4;

    // How many recorded takes each pain type has. The speech manager's init
    // writes exactly these constants into its own globals.
    constexpr uint8_t kTypeLimits[4] = { 5, 5, 2, 2 };

    // One half of a slot's double buffer. Same shape as the game's, so the
    // vanilla slots can be read through the identical helpers.
    struct PainEntry
    {
        uint8_t  state;        // 0 loading, 1 loaded, 2 live, 3 wants a bank
        uint8_t  pad[3];
        uint32_t waveSlot;
        uint16_t soundId;
        uint16_t pad2;
    };
    static_assert(sizeof(PainEntry) == 12, "entry must match the game's stride");

    struct ExtraSlot
    {
        PainEntry entry[2]{};
        uint8_t   curEntry   = 0;
        uint8_t   variation  = 1;
        uint32_t  cooldown   = 0;
        uint8_t   index[4]   = { 1, 1, 1, 1 };
        uint8_t   counter[4] = { 0, 0, 0, 0 };

        // "this half has a bank streamed in", which is NOT the same as its state
        // byte. The vanilla `state == 2` test conflates "playable" with "not
        // queued for rotation", so a slot reads as unavailable for the frame or
        // two between hitting its use limit and the other half swapping in. Our
        // banks stay perfectly playable across that window, so track residency
        // separately and let rotation run on the state byte as the game does.
        bool      resident[2] = { false, false };

        std::string              root;             // bank root, e.g. "JOHNNY"

        // Voices to try for a pain-adjacent speech context, best first. The
        // character's pain-extras voice covers the hurt vocalisations, but not
        // panic - as the player you never panic, so PANIC_SHORT was never
        // recorded for it. Their ordinary dialogue voice has those lines.
        std::string              voiceNames[3];
        uint32_t                 voiceHashes[3] = { 0, 0, 0 };
        uint8_t                  variationCount = 15;
        std::vector<std::string> modelNames;
        std::vector<int32_t>     modelIndices;

        bool usable        = false;   // both wave slots were found
        bool missingLogged = false;
        bool announced     = false;
    };

    ExtraSlot gExtra[kMaxExtraSlots];
    int       gExtraCount = 0;
    bool      gEnabled    = false;

    // Every pain sound the game plays is one line, capped so a long session does
    // not fill the log. A generic scream with NO line here did not come from the
    // pain system at all.
    bool gTrace      = false;
    int  gTraceLeft  = 0;

    // The two voices PED_VOICES_EXTRAS hands out to non-player peds. Hashed here
    // rather than read out of the game's globals so no extra signature is needed;
    // rage::atStringHash is the engine's own algorithm.
    constexpr uint32_t kPainMaleExtras   = rage::atStringHash("PAIN_MALE_EXTRAS");
    constexpr uint32_t kPainFemaleExtras = rage::atStringHash("PAIN_FEMALE_EXTRAS");

    const char **gVoiceTable = nullptr;   // the game's 3-entry voice-name table

    // ---- game functions and globals, all resolved by signature ----
    void     (__fastcall *OrigPreloader)(void *self, void *)                    = nullptr;
    int      (__cdecl    *LookupSpeech)(const char *bank, const char *entry)    = nullptr;
    void     (__fastcall *WaveSlotRequest)(void *waveSlot, void *, int soundId) = nullptr;
    int      (__fastcall *WaveSlotPoll)(void *waveSlot, void *, int soundId)    = nullptr;
    int      (__cdecl    *WaveSlotByName)(const char *name)                     = nullptr;
    bool     (__fastcall *StreamingBusy)(void *self, void *, const char *tag)   = nullptr;
    bool     (__cdecl    *IsGameSuspended)()                                    = nullptr;
    int      (__fastcall *OrigResolveVoice)(void *self, void *, int voice, const char *context) = nullptr;
    int      (__cdecl    *SpeechContextCount)(int voice, const char *context)   = nullptr;
    bool     (__fastcall *IsPedMale)(void *ped, void *)                         = nullptr;
    uint32_t *gAudioTimer = nullptr;
    uint32_t *gPainVoice  = nullptr;   // the PAIN_VOICE placeholder the dispatcher resolves

    // Index of the stock "PLAYER" model, so a player wearing something else can
    // be told apart from Niko.
    int32_t gPlayerModelIndex = -1;

    // ---- vanilla slot access ----
    inline PainEntry *GameEntry(uint8_t *self, int slot, int entry)
    {
        return reinterpret_cast<PainEntry *>(self + kEntries + 24 * slot + 12 * entry);
    }
    inline uint8_t &GameCurEntry(uint8_t *self, int slot)  { return self[kCurEntry + slot]; }
    inline uint8_t &GameVariation(uint8_t *self, int slot) { return self[kVariation + slot]; }
    inline uint8_t &GameIndex(uint8_t *self, int slot, int type)   { return self[kIndex + 4 * slot + type]; }
    inline uint8_t &GameCounter(uint8_t *self, int slot, int type) { return self[kCounter + 4 * slot + type]; }
    inline uint32_t &GameCooldown(uint8_t *self, int slot)
    {
        return *reinterpret_cast<uint32_t *>(self + kCooldown + 4 * slot);
    }

    inline ExtraSlot *Extra(int slot)
    {
        const int i = slot - kGameSlots;
        return (i >= 0 && i < gExtraCount) ? &gExtra[i] : nullptr;
    }

    // Wave slot names are ours, not the voice's: naming them after the bank root
    // would collide with slot 0's NIKO_0 / NIKO_1 if someone configures "NIKO".
    std::string WaveSlotName(int extraIndex, int half)
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "PAIN_EXTRA_%d_%d", extraIndex, half);
        return buf;
    }
}

extern void *(*CModelInfoStore__GetModelByName)(const char *name, int32_t *index);

// ----------------------------------------------------------------------------
// The five per-slot accessors. Each is replaced outright rather than
// trampolined - they are one-liners with a single call site, so re-implementing
// them is both shorter and safer than jumping back into a half-overwritten
// prologue. __fastcall with an unused second parameter is how MSVC spells
// __thiscall for a free function: `this` arrives in ECX and the callee cleans
// the stack, exactly as the originals do.
// ----------------------------------------------------------------------------

// "is this slot's current bank live?"
bool __fastcall PainVoice_IsSlotReady(uint8_t *self, void *, unsigned int slot)
{
    if (slot < static_cast<unsigned int>(kGameSlots))
        return GameEntry(self, static_cast<int>(slot), GameCurEntry(self, static_cast<int>(slot)))->state == 2;

    const ExtraSlot *s = Extra(static_cast<int>(slot));
    return s != nullptr && s->usable && s->resident[s->curEntry];
}

// the wave slot the live bank sits in
uint32_t __fastcall PainVoice_GetWaveSlot(uint8_t *self, void *, int slot)
{
    if (slot < kGameSlots)
        return GameEntry(self, slot, GameCurEntry(self, slot))->waveSlot;

    const ExtraSlot *s = Extra(slot);
    return s ? s->entry[s->curEntry].waveSlot : 0;
}

// which "<ROOT>_<NN>" is live; formatted straight into the bank name by the caller
uint32_t __fastcall PainVoice_GetVariation(uint8_t *self, void *, int slot)
{
    if (slot < kGameSlots)
        return GameVariation(self, slot);

    const ExtraSlot *s = Extra(slot);
    return s ? s->variation : 1;
}

// which take of this pain type to play
uint32_t __fastcall PainVoice_GetTypeIndex(uint8_t *self, void *, int slot, int type)
{
    if (slot < kGameSlots)
        return GameIndex(self, slot, type);

    const ExtraSlot *s = Extra(slot);
    return s ? s->index[type & 3] : 1;
}

// called once a pain sound starts: advance the take, count the use, and hold the
// bank resident for at least another 500 ticks
uint32_t __fastcall PainVoice_NoteUsed(uint8_t *self, void *, int slot, int type)
{
    const uint32_t hold = *gAudioTimer + 500;
    type &= 3;

    if (slot < kGameSlots)
    {
        ++GameCounter(self, slot, type);
        GameIndex(self, slot, type) = static_cast<uint8_t>(GameIndex(self, slot, type) % kTypeLimits[type] + 1);
        if (GameCooldown(self, slot) <= hold)
            GameCooldown(self, slot) = hold;
        return hold;
    }

    if (ExtraSlot *s = Extra(slot))
    {
        ++s->counter[type];
        s->index[type] = static_cast<uint8_t>(s->index[type] % kTypeLimits[type] + 1);
        if (s->cooldown <= hold)
            s->cooldown = hold;
    }
    return hold;
}

namespace
{
    // Retried every tick rather than latched: the wave slot table is built long
    // before the speech manager exists, but a slot that reported missing once
    // must not be written off for the rest of the session.
    void ResolveWaveSlots(int extraIndex, ExtraSlot &s)
    {
        const std::string a = WaveSlotName(extraIndex, 0);
        const std::string b = WaveSlotName(extraIndex, 1);
        s.entry[0].waveSlot = static_cast<uint32_t>(WaveSlotByName(a.c_str()));
        s.entry[1].waveSlot = static_cast<uint32_t>(WaveSlotByName(b.c_str()));

        if (s.entry[0].waveSlot == 0 || s.entry[1].waveSlot == 0)
        {
            if (!s.missingLogged)
            {
                s.missingLogged = true;
                TaceLog("[painvoice] %s: wave slots \"%s\" / \"%s\" are not in waveslots.xml"
                        " - this voice stays on the generic pain bank",
                        s.root.c_str(), a.c_str(), b.c_str());
            }
            return;
        }

        // The same starting state the manager's init gives its own three slots.
        s.entry[0].state = s.entry[1].state = 3;
        s.entry[0].soundId = s.entry[1].soundId = 0;
        s.resident[0] = s.resident[1] = false;
        s.curEntry  = 0;
        s.variation = 1;
        s.cooldown  = 0;
        for (int i = 0; i < 4; i++) { s.index[i] = 1; s.counter[i] = 0; }

        s.usable = true;
        TaceLog("[painvoice] %s: wave slots %s=%p %s=%p", s.root.c_str(),
                a.c_str(), reinterpret_cast<void *>(s.entry[0].waveSlot),
                b.c_str(), reinterpret_cast<void *>(s.entry[1].waveSlot));
    }

    // A verbatim port of one iteration of the game's preloader loop, reading and
    // writing our own slot state instead of the manager's.
    void TickExtraSlot(void *self, int extraIndex, ExtraSlot &s)
    {
        if (!s.usable)
        {
            ResolveWaveSlots(extraIndex, s);
            if (!s.usable)
                return;
        }

        const int  other = (s.curEntry + 1) % 2;
        PainEntry &e     = s.entry[other];

        if (e.state == 0)
        {
            const int status = WaveSlotPoll(reinterpret_cast<void *>(e.waveSlot), nullptr, e.soundId);
            if (status == 0)
                e.state = 1;                     // the bank landed
            else if (status == 2 || status == 3)
                e.state = 3;                     // slot got taken, ask again
        }
        else if (e.state == 2)
        {
            e.state = 3;
        }
        else if (e.state == 3)
        {
            const bool timeToTry = IsGameSuspended() || s.cooldown < *gAudioTimer;

            if (e.waveSlot != 0 && !StreamingBusy(self, nullptr, nullptr) && timeToTry &&
                *reinterpret_cast<uint32_t *>(e.waveSlot + 8) == 0)
            {
                char bank[64] = {};
                snprintf(bank, sizeof(bank), "%s_%02d", s.root.c_str(),
                         s.variation % s.variationCount + 1);

                const int soundId = LookupSpeech(bank, "PAIN_LOW");
                if (soundId != 0xFFFF)
                {
                    e.soundId       = static_cast<uint16_t>(soundId);
                    WaveSlotRequest(reinterpret_cast<void *>(e.waveSlot), nullptr, soundId);
                    e.state         = 0;
                    s.resident[other] = false;
                    s.cooldown      = *gAudioTimer + 1500;

                    if (!s.announced || (gTrace && gTraceLeft > 0))
                    {
                        s.announced = true;
                        TaceLog("[painvoice] %s: loading bank \"%s\" into half %d",
                                s.root.c_str(), bank, other);
                    }
                }
                else if (!s.announced)
                {
                    s.announced = true;
                    TaceLog("[painvoice] %s: bank \"%s\" is not in this episode's speech data"
                            " - falling back to the generic voice", s.root.c_str(), bank);
                }
            }
        }

        PainEntry &live = s.entry[s.curEntry];
        switch (live.state)
        {
        case 0:
        case 1:
            live.state = 3;
            break;

        case 2:
            for (int type = 0; type < 4; type++)
            {
                if (s.counter[type] >= kTypeLimits[type])
                {
                    live.state = 3;              // heard enough of this bank
                    break;
                }
            }
            break;

        case 3:
            if (e.state == 1)                    // the other half is ready: swap
            {
                e.state           = 2;
                s.resident[other] = true;
                s.curEntry        = static_cast<uint8_t>(other);
                s.variation = static_cast<uint8_t>(s.variation % s.variationCount + 1);
                *reinterpret_cast<uint32_t *>(s.counter) = 0;
            }
            break;

        default:
            break;
        }
    }
}

// The manager's own preloader still runs slots 0-2 exactly as before; we only add
// passes for the extra ones.
void __fastcall PainVoice_Preloader(void *self, void *)
{
    OrigPreloader(self, nullptr);

    for (int i = 0; i < gExtraCount; i++)
        TickExtraSlot(self, i, gExtra[i]);
}

// ----------------------------------------------------------------------------
// Slot selection. Stands in for the two instructions right after the game's
// player/gender choice, with EDI holding the slot it picked.
// ----------------------------------------------------------------------------
extern "C" int __cdecl PainVoice_PickSlot(void *audioEntity, int gameSlot)
{
    if (!gEnabled || audioEntity == nullptr)
        return gameSlot;

    uint8_t *ped = *reinterpret_cast<uint8_t **>(static_cast<uint8_t *>(audioEntity) + 8);
    if (ped == nullptr)
    {
        // Traced too: an absent ped here is indistinguishable in the log from
        // never being called at all, and those need different fixes.
        if (gTrace && gTraceLeft > 0)
        {
            gTraceLeft--;
            TACE_TRACE("[painvoice] pain: no ped on the audio entity, leaving slot %d", gameSlot);
        }
        return gameSlot;
    }

    const int32_t model = *reinterpret_cast<int16_t *>(ped + 0x2E);

    if (gameSlot == 0)
    {
        static int32_t lastPlayerModel = -2;
        if (model != lastPlayerModel)
        {
            lastPlayerModel = model;
            TaceLog("[painvoice] player ped model is %d (PLAYER is %d)", model, gPlayerModelIndex);
        }
    }

    int chosen  = gameSlot;
    int matched = -1;

    for (int i = 0; i < gExtraCount && matched < 0; i++)
    {
        for (int32_t index : gExtra[i].modelIndices)
        {
            if (index >= 0 && index == model)
            {
                matched = i;
                break;
            }
        }
    }

    // A matched voice whose bank is not resident stays off it: handing playback a
    // slot with nothing in it produces silence, not a voice. This runs for the
    // player too, so playing AS Johnny gets his bank the same way an NPC does.
    if (matched >= 0 && gExtra[matched].usable && gExtra[matched].resident[gExtra[matched].curEntry])
    {
        chosen = kGameSlots + matched;
    }
    else if (gameSlot == 0 && gPlayerModelIndex >= 0 && model != gPlayerModelIndex &&
             IsPedMale != nullptr)
    {
        // Slot 0 is Niko's own voice, and the game hands it to any single-player
        // player ped. Wearing a different model that is wrong, so fall back on
        // gender exactly as the multiplayer branch alongside it already does.
        chosen = IsPedMale(ped, nullptr) ? 1 : 2;
    }

    if (gTrace && gTraceLeft > 0)
    {
        gTraceLeft--;
        if (matched < 0)
        {
            TACE_TRACE("[painvoice] pain: model %d -> slot %d (game said %d, no configured voice)",
                    model, chosen, gameSlot);
        }
        else
        {
            const ExtraSlot &s = gExtra[matched];
            TACE_TRACE("[painvoice] pain: model %d %s -> slot %d | live=%d state=%d resident=%d,%d"
                    " var=%u counters=%u,%u,%u,%u",
                    model, s.root.c_str(), chosen, s.curEntry, s.entry[s.curEntry].state,
                    s.resident[0] ? 1 : 0, s.resident[1] ? 1 : 0, s.variation,
                    s.counter[0], s.counter[1], s.counter[2], s.counter[3]);
        }
    }

    return chosen;
}

static void __declspec(naked) PainVoice_PickSlotStub()
{
    __asm
    {
        pushad
        push edi                        // the slot the game chose
        push esi                        // audSpeechAudioEntity
        call PainVoice_PickSlot
        add  esp, 8
        mov  dword ptr [esp], eax       // overwrite saved EDI in the pushad frame
        popad

        mov  eax, [ebp + 8]             // the two instructions we replaced
        sub  eax, 2
        ret
    }
}

// ----------------------------------------------------------------------------
// The pain-adjacent speech contexts. Wraps PED_VOICES_EXTRAS at both of its call
// sites: let it resolve as usual, then swap the generic result for the
// character's own extras voice.
// ----------------------------------------------------------------------------
int __fastcall PainVoice_ResolveVoice(void *self, void *, int voice, const char *context)
{
    const int result = OrigResolveVoice(self, nullptr, voice, context);

    // Gate on the placeholder the dispatcher was asked to resolve rather than on
    // what it resolved to. Matching the result would only catch NPCs, since for
    // the player it returns the local player pain voice instead - and playing AS
    // Johnny should get his own vocalisations too, the same as the natives give.
    if (!gEnabled || self == nullptr || context == nullptr || gPainVoice == nullptr ||
        static_cast<uint32_t>(voice) != *gPainVoice)
        return result;

    uint8_t *ped = *reinterpret_cast<uint8_t **>(static_cast<uint8_t *>(self) + 8);
    if (ped == nullptr)
        return result;

    const int32_t model = *reinterpret_cast<int16_t *>(ped + 0x2E);

    for (int i = 0; i < gExtraCount; i++)
    {
        const ExtraSlot &s = gExtra[i];
        bool match = false;
        for (int32_t index : s.modelIndices)
            match = match || (index >= 0 && index == model);
        if (!match)
            continue;

        // One-time proof that the hash and the lookup agree with the engine: the
        // generic voice demonstrably HAS whatever context we are being asked
        // about, so a zero here means our own plumbing is wrong, not the data.
        static bool selfTested = false;
        if (!selfTested)
        {
            selfTested = true;
            TaceLog("[painvoice] self-test: PAIN_MALE_EXTRAS has %d line(s) of \"%s\""
                    " (0 would mean our hash or lookup is wrong)",
                    SpeechContextCount(static_cast<int>(kPainMaleExtras), context), context);
        }

        // The engine gates its own NIKO_ANGRY / ROMAN_SAD swaps on the voice
        // actually having the context; without that a voice missing one line
        // would go silent, which is worse than the generic scream.
        for (int v = 0; v < 3; v++)
        {
            if (SpeechContextCount(static_cast<int>(s.voiceHashes[v]), context) <= 0)
                continue;

            if (gTrace && gTraceLeft > 0)
            {
                gTraceLeft--;
                TACE_TRACE("[painvoice] extras: model %d context \"%s\" -> %s",
                        model, context, s.voiceNames[v].c_str());
            }
            return static_cast<int>(s.voiceHashes[v]);
        }

        // Nothing of theirs covers this context. Hand back their own voice
        // regardless: the speech lookup finds no line and plays nothing, which
        // is what we want - a configured character must never be heard making a
        // generic ped noise, and silence reads as fine next to the pain bank
        // sound that plays on the same hit anyway.
        if (gTrace && gTraceLeft > 0)
        {
            gTraceLeft--;
            TACE_TRACE("[painvoice] extras: model %d context \"%s\" -> silent"
                    " (none of %s / %s / %s has that line; generic suppressed)",
                    model, context, s.voiceNames[0].c_str(), s.voiceNames[1].c_str(),
                    s.voiceNames[2].c_str());
        }
        return static_cast<int>(s.voiceHashes[0]);
    }

    // No configured voice for this model. The dispatcher's pain branch has only
    // two outcomes - the generic pair for anyone else, or the local player's own
    // voice - so a result that is neither generic means it took the player path.
    // Wearing an unrelated model that is wrong for the same reason slot 0 is:
    // the falls, burns and coughs would still be screamed in Niko's voice. Send
    // them to the generic pair by gender, matching the slot choice made for the
    // pain bank on the very same hit.
    const bool tookPlayerBranch = static_cast<uint32_t>(result) != kPainMaleExtras &&
                                  static_cast<uint32_t>(result) != kPainFemaleExtras;

    if (tookPlayerBranch && gPlayerModelIndex >= 0 && model != gPlayerModelIndex &&
        IsPedMale != nullptr)
    {
        const bool male = IsPedMale(ped, nullptr);

        if (gTrace && gTraceLeft > 0)
        {
            gTraceLeft--;
            TACE_TRACE("[painvoice] extras: model %d context \"%s\" -> %s"
                    " (player is not the PLAYER model)",
                    model, context, male ? "PAIN_MALE_EXTRAS" : "PAIN_FEMALE_EXTRAS");
        }
        return static_cast<int>(male ? kPainMaleExtras : kPainFemaleExtras);
    }

    return result;
}

// ----------------------------------------------------------------------------
// Voice name. Stands in for `mov eax, [edi*4 + <voice table>]`, which only knows
// about the three vanilla entries.
// ----------------------------------------------------------------------------
extern "C" const char *__cdecl PainVoice_PickName(void *, int slot)
{
    if (slot >= kGameSlots)
    {
        const ExtraSlot *s = Extra(slot);
        return s ? s->root.c_str() : "PAIN_MALE";
    }

    return (gVoiceTable != nullptr && slot >= 0) ? gVoiceTable[slot] : nullptr;
}

static void __declspec(naked) PainVoice_PickNameStub()
{
    __asm
    {
        pushad
        push edi                            // voice slot
        push esi                            // audSpeechAudioEntity
        call PainVoice_PickName
        add  esp, 8
        mov  dword ptr [esp + 0x1C], eax    // overwrite saved EAX
        popad
        ret
    }
}

// ----------------------------------------------------------------------------

namespace
{
    std::string Trim(std::string s)
    {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
        return s;
    }

    // "<bank root>, <variation count>, <model>[, <model>...]"
    bool ParseVoice(const std::string &value, ExtraSlot &s)
    {
        std::vector<std::string> parts;
        size_t start = 0;
        for (;;)
        {
            const size_t comma = value.find(',', start);
            parts.push_back(Trim(value.substr(start, comma - start)));
            if (comma == std::string::npos)
                break;
            start = comma + 1;
        }

        if (parts.size() < 3 || parts[0].empty())
            return false;

        s.root = parts[0];

        const int count = atoi(parts[1].c_str());
        if (count < 1 || count > 99)
            return false;
        s.variationCount = static_cast<uint8_t>(count);

        for (size_t i = 2; i < parts.size(); i++)
        {
            if (!parts[i].empty())
                s.modelNames.push_back(parts[i]);
        }
        return !s.modelNames.empty();
    }
}

void PainVoice_Init()
{
    gEnabled = TaceIniBool("PAINVOICE", "Enabled", false);
    if (!gEnabled)
    {
        TaceLog("[painvoice] disabled in ini");
        return;
    }

    gTrace     = TaceTraceEnabled("painvoice", "PAINVOICE");
    gTraceLeft = gTrace ? TaceTraceBudget(200) : 0;

    for (int i = 0; i < kMaxExtraSlots; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "Voice%d", i + 1);

        const std::string value = TaceIniString("PAINVOICE", key);
        if (value.empty())
            continue;

        ExtraSlot &s = gExtra[gExtraCount];
        if (!ParseVoice(value, s))
        {
            TaceLog("[painvoice] %s: expected \"<bank root>, <variations>, <model>[, ...]\","
                    " got \"%s\" - skipped", key, value.c_str());
            s = ExtraSlot{};
            continue;
        }

        s.voiceNames[0] = s.root + "_EXTRAS";
        s.voiceNames[1] = s.root + "_NORMAL";
        s.voiceNames[2] = s.root;
        for (int v = 0; v < 3; v++)
            s.voiceHashes[v] = rage::atStringHash(s.voiceNames[v].c_str());

        TaceLog("[painvoice] slot %d = \"%s\" (%u variations), %u model(s)",
                kGameSlots + gExtraCount, s.root.c_str(),
                static_cast<unsigned>(s.variationCount),
                static_cast<unsigned>(s.modelNames.size()));
        gExtraCount++;
    }

    if (gExtraCount == 0)
    {
        TaceLog("[painvoice] no voices configured, nothing to do");
        gEnabled = false;
        return;
    }

    // --- the five per-slot accessors, reached through their only call site ---
    auto accessors = find_pattern(
        "57 B9 ? ? ? ? E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 57 B9 ? ? ? ? E8 ? ? ? ? "
        "89 44 24 24 8B 44 24 14 50 57 B9 ? ? ? ? E8 ? ? ? ? 57 B9 ? ? ? ? "
        "89 44 24 30 E8 ? ? ? ?");

    // --- everything the preloader needs, taken from the preloader itself ---
    auto preloadCall = find_pattern("88 9E 8C 04 00 00 8B CE E8 ? ? ? ? 38 1D ? ? ? ? 74 ?");
    auto helpers     = find_pattern("8B CE E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? E8 ? ? ? ? 84 C0 75 13 "
                                    "8B 84 BE 48 05 00 00 3B 05 ? ? ? ?");
    auto lookup      = find_pattern("51 E8 ? ? ? ? 83 C4 14 8D 54 24 1C 68 ? ? ? ? 52 E8 ? ? ? ? "
                                    "0F B7 C0 83 C4 08 66 3D FF FF");
    auto waveRequest = find_pattern("8B 89 FC 04 00 00 50 E8 ? ? ? ? C6 45 00 00 A1 ? ? ? ? 05 DC 05 00 00");
    auto wavePoll    = find_pattern("8B 88 FC 04 00 00 52 E8 ? ? ? ? 83 E8 00 74 10 83 E8 02");
    auto waveByName  = find_pattern("8D 54 24 30 52 E8 ? ? ? ? 89 06 83 C7 01 83 C4 14 83 C6 0C 83 FF 02 72 CA");

    // --- the two playback sites we take over ---
    auto bump      = find_pattern("6A 00 6A 00 50 E8 ? ? ? ? 8B 4C 24 14 51 57 B9 ? ? ? ? "
                                  "E8 ? ? ? ? 8B 45 08 89 86 B8 00 00 00");
    auto selection = find_pattern("BF 01 00 00 00 E8 ? ? ? ? 84 C0 74 0D E8 ? ? ? ? 84 C0 75 04 "
                                  "33 FF EB 11 8B 4E 08 E8 ? ? ? ? 84 C0 75 05 BF 02 00 00 00 "
                                  "8B 45 08 83 E8 02");
    auto nameRead  = find_pattern("8B 54 24 24 8B 04 BD ? ? ? ? 52 50 68 ? ? ? ?");

    // --- the pain-adjacent speech contexts ---
    auto extras1  = find_pattern("8B 45 14 53 50 8B CE E8 ? ? ? ? 8B CE 89 45 14 E8 ? ? ? ? "
                                 "84 C0 0F 85 ? ? ? ?");
    auto extras2  = find_pattern("8B 4D 0C 8B 55 14 51 52 8B CE 89 44 24 28 E8 ? ? ? ? "
                                 "56 B9 ? ? ? ? 89 45 14 E8 ? ? ? ?");
    auto ctxCount = find_pattern("8B 9C 24 20 05 00 00 56 53 8B F8 E8 ? ? ? ? 8B F0 83 C4 10 85 F6 7F 08");
    auto voiceHead = find_pattern("83 EC 08 53 56 8B 74 24 14 3B 35 ? ? ? ? 57 8B F9 75 ? "
                                  "8B 47 08 05 18 02 00 00 33 DB 38 18");

    const struct { const char *what; bool missing; } required[] = {
        { "slot accessors",    accessors.empty()   },
        { "preloader",         preloadCall.empty() },
        { "streaming helpers", helpers.empty()     },
        { "speech lookup",     lookup.empty()      },
        { "wave slot request", waveRequest.empty() },
        { "wave slot poll",    wavePoll.empty()    },
        { "wave slot lookup",  waveByName.empty()  },
        { "use counter",       bump.empty()        },
        { "slot selection",    selection.empty()   },
        { "voice name read",   nameRead.empty()    },
        { "voice dispatcher",  extras1.empty()     },
        { "voice dispatcher 2", extras2.empty()    },
        { "speech context count", ctxCount.empty() },
        { "PAIN_VOICE global", voiceHead.empty() },
    };

    bool ok = true;
    for (const auto &r : required)
    {
        if (r.missing)
        {
            TaceLog("[painvoice] signature not found: %s - feature disabled", r.what);
            ok = false;
        }
    }
    if (!ok)
    {
        gEnabled = false;
        return;
    }

    LookupSpeech    = injector::GetBranchDestination(lookup.get_first(19),    true).get();
    WaveSlotRequest = injector::GetBranchDestination(waveRequest.get_first(7), true).get();
    WaveSlotPoll    = injector::GetBranchDestination(wavePoll.get_first(7),    true).get();
    WaveSlotByName  = injector::GetBranchDestination(waveByName.get_first(5),  true).get();
    StreamingBusy   = injector::GetBranchDestination(helpers.get_first(2),     true).get();
    IsGameSuspended = injector::GetBranchDestination(helpers.get_first(15),    true).get();

    // Both of these are absolute-address operands, so read the value stored in
    // the instruction, not the address of the operand bytes.
    gAudioTimer = *helpers.get_first<uint32_t *>(33);
    gVoiceTable = *nameRead.get_first<const char **>(7);

    injector::MakeJMP(injector::GetBranchDestination(accessors.get_first(6),  true), PainVoice_IsSlotReady,  true);
    injector::MakeJMP(injector::GetBranchDestination(accessors.get_first(25), true), PainVoice_GetWaveSlot,  true);
    injector::MakeJMP(injector::GetBranchDestination(accessors.get_first(45), true), PainVoice_GetTypeIndex, true);
    injector::MakeJMP(injector::GetBranchDestination(accessors.get_first(60), true), PainVoice_GetVariation, true);
    injector::MakeJMP(injector::GetBranchDestination(bump.get_first(21),      true), PainVoice_NoteUsed,     true);

    OrigPreloader = injector::MakeCALL(preloadCall.get_first(8), PainVoice_Preloader, true).get();

    // `mov eax, [ebp+8]` + `sub eax, 2` - 6 bytes, so a call plus one filler.
    injector::MakeCALL(selection.get_first(44), PainVoice_PickSlotStub, true);
    injector::MakeNOP(selection.get_first(49), 1, true);

    // `mov eax, [edi*4 + <table>]` - 7 bytes.
    injector::MakeCALL(nameRead.get_first(4), PainVoice_PickNameStub, true);
    injector::MakeNOP(nameRead.get_first(9), 2, true);

    SpeechContextCount = injector::GetBranchDestination(ctxCount.get_first(11), true).get();
    IsPedMale          = injector::GetBranchDestination(selection.get_first(30), true).get();
    gPainVoice         = *voiceHead.get_first<uint32_t *>(11);

    // Both sites call the same dispatcher; wrapping each in turn leaves
    // OrigResolveVoice pointing at the real one either way.
    OrigResolveVoice = injector::MakeCALL(extras1.get_first(7),  PainVoice_ResolveVoice, true).get();
    injector::MakeCALL(extras2.get_first(14), PainVoice_ResolveVoice, true);

    TaceLog("[painvoice] armed: %d extra voice slot(s), voice table %p, audio timer %p",
            gExtraCount, static_cast<void *>(gVoiceTable), static_cast<void *>(gAudioTimer));
}

// Model indices only exist once the map has loaded, and they differ per episode.
void PainVoice_OnInitMap()
{
    if (!gEnabled || CModelInfoStore__GetModelByName == nullptr)
        return;

    gPlayerModelIndex = -1;
    CModelInfoStore__GetModelByName("PLAYER", &gPlayerModelIndex);
    TaceLog("[painvoice] PLAYER model = %d", gPlayerModelIndex);

    for (int i = 0; i < gExtraCount; i++)
    {
        ExtraSlot &s = gExtra[i];
        s.modelIndices.clear();

        for (const std::string &name : s.modelNames)
        {
            int32_t index = -1;
            CModelInfoStore__GetModelByName(name.c_str(), &index);
            s.modelIndices.push_back(index);

            if (index < 0)
                TaceLog("[painvoice] %s: model %s is not in this episode", s.root.c_str(), name.c_str());
            else
                TaceLog("[painvoice] %s: model %s = %d", s.root.c_str(), name.c_str(), index);
        }
    }
}
