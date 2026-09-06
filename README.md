# TacePatch

[![Latest release](https://img.shields.io/github/v/release/ClaudeIII/TACE-Patch?style=flat-square)](https://github.com/ClaudeIII/TACE-Patch/releases/latest)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square)](LICENSE)
[![Game](https://img.shields.io/badge/GTA%20IV-1.0.8.0%20%C2%B7%20Complete%20Edition-orange?style=flat-square)](#requirements)

The ASI patch behind **[GTA IV: The Actual Complete Edition](https://gtaforums.com/topic/967792-grand-theft-auto-iv-the-actual-complete-edition)** — the engine-side half of the mod. It raises engine limits, gives each playable character their own voice, makes gangs and police carry sensible weapons, and unlocks content that vanilla locks to a single episode.

---

## Install

1. Grab **[TacePatch.7z](https://github.com/ClaudeIII/TACE-Patch/releases/latest)** from the latest release.
2. Drop `TacePatch.asi` and `TacePatch.ini` next to `GTAIV.exe`.
3. Launch the game.

You need an ASI loader already installed. That's it — the defaults are the shipping configuration, so there is nothing to configure unless you want to.

### Requirements

| | |
|---|---|
| **Game** | GTA IV **1.0.8.0**, developed and tested against that build |
| **Needs** | An ASI loader |
| **Runs alongside** | ZolikaPatch, ZMenuIV |

Patches are byte-signature searches rather than hardcoded addresses, and a call site can carry a signature per build (1.0.7.0, 1.0.8.0, Complete Edition), so other versions may work — but 1.0.8.0 is what this is built and tested on.

Anything that doesn't match on your build is **reported and skipped**, never applied to the wrong place, so a mismatch degrades to vanilla behaviour instead of corrupting the game. `TacePatch.log` tells you exactly what applied and what didn't.

> **Don't run it with FusionFix's limit adjuster.** TacePatch's `[LIMITS]` is ported from it — both raising the same limits is asking for trouble.

---

## What it does

| Feature | |
|---|---|
| **Engine limits** | Anim `.wad` dictionaries, the model store and more, raised past their vanilla caps. Ported from FusionFix's limit adjuster. |
| **Pain voices** | Per-model pain voices, so Niko, Johnny and Luis stop sharing one grunt. Needs a few extra wave slots — see [`assets/waveslots-painvoice.xml`](assets/waveslots-painvoice.xml). |
| **Gang loadouts** | Configurable weapons per gang, instead of the hardcoded vanilla set. |
| **Police loadouts** | Configurable police weapons, including rooftop snipers and helicopter crewmen. |
| **Episode gates** | Content the base game locks to one episode, opened across all three. |
| **Debug console** | A live console beside the game with per-subsystem tracing, plus a log file. |
| **Gate profiler** | Press a key before an action to see which episode gates it touched, and which locked you out. |
| **Crash logger** | Tells you whether a crash was TacePatch's fault. [See below.](#the-crash-logger) |

Everything lives in `TacePatch.ini`, under `[LIMITS]`, `[DEBUG]`, `[PAINVOICE]`, `[GANGWEAPONS]` and `[COPWEAPONS]`. Every key documents itself inline.

---

## The crash logger

GTA IV crashes. The question that costs the most time is always *"was it the mod?"* — normally answered by opening a `.dmp` in a debugger, finding the module bases, and scanning the faulting stack by hand.

TacePatch writes that answer at the moment of the crash, into a `TacePatch Crashes` folder next to the `.asi`:

```
--- Verdict ---------------------------------------------------
  Faulting instruction is in GTAIV.exe.
  NOT TACEPATCH: no pointers into TacePatch.asi appear anywhere in
  the faulting stack (537 words scanned).

  Modules present in the faulting stack, by pointer count:
    GTAIV.exe                       36
    ntdll.dll                        4
    KERNEL32.DLL                     2
```

Below that: the exception with the faulting opcode bytes, a reconstructed call stack, the last file and library the game opened, TacePatch's own patch tally, the registers, an annotated stack dump, and every loaded module with its address.

**Two things to know when reading one:**

- **`FIRST-CHANCE`** reports were seen *before* anything had a chance to handle the exception — the game may well have recovered, so check whether it actually died. **`UNHANDLED`** reports are what killed the process.
- Call stack entries marked **`[frame]`** came off the frame-pointer chain and are reliable. Entries marked **`[scan]`** are stack slots pointing just past a call instruction: strong evidence, but a stale frame from an earlier call looks identical.

It does not take crash reporting away from anyone — ZolikaPatch's dumps keep appearing exactly as before. `CrashLogger = 0` under `[DEBUG]` turns it off entirely.

### Reporting a crash

Send the **whole `.log` file**, not a screenshot. The `.dmp` beside it helps, and `TacePatch.log` from the same run is worth including — it records which signatures matched on your build and which didn't.

---

## Building

Open `TacePatch.sln` in Visual Studio and build **Release | x86**. Output lands in `build/Release/bin/`.

Dependencies are vendored in [`deps/`](deps/) — [Hooking.Patterns](deps/Hooking.Patterns), [injector](deps/injector) and IniReader. Nothing to fetch.

---

## Repository layout

| | |
|---|---|
| [`src/`](src/) | The mod. One file per feature, plus `crashlog.cpp` and the header-only `Log.h`. |
| [`assets/`](assets/) | Game files you paste into your install — currently the pain-voice wave slots. |
| [`docs/`](docs/) | [`episode-gates.txt`](docs/episode-gates.txt) — an inventory of every episode gate in `GTAIV.exe` 1.0.8.0, what each one does, and which are still unidentified. Findings only, nothing prescriptive. |
| [`deps/`](deps/) | Vendored dependencies. |

---

## Credits

- **[@ClaudeIII](https://github.com/ClaudeIII)** — author and maintainer of TacePatch and of [The Actual Complete Edition](https://gtaforums.com/topic/967792-grand-theft-auto-iv-the-actual-complete-edition).
- **[@Flentric](https://github.com/Flentric)** — co-programmer.
- **[@akifle47](https://github.com/akifle47)** — features and contributions.
- **[ThirteenAG](https://github.com/ThirteenAG)** — [FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix), which the limit adjuster is ported from.

Licensed under [GPL-3.0](LICENSE).
