# 01 — Program architecture: startup, main loop, frame pacing, scene machine

Scope: `bugs_decompiled.c` (576 functions, BUGS.EXE @ `0x401000`–`0x45b0xx`, VC++6 PE32
i386). Every structural claim below is tagged. `CONFIRMED` means a quoted line from the
decompile proves it, or (where marked) a measurement from the running Linux port.
`PLAUSIBLE` means the mechanism is visible but the trigger is inferred. `UNKNOWN` means
the decompile does not settle it.

Line numbers cited as `file:line` are into `bugs_decompiled.c`. Citations of the form
`0x40xxxx:` are the function VA followed by the quoted decompile text, per the brief.

Verification method: I read whole functions (`/tmp/fn.py` dump) before assigning a role,
and for §6 I built `linux/build/bblit`, ran it, and instrumented the shim to observe the
fault. All temporary instrumentation was reverted; `git diff` is empty and the only
untracked path is this `analysis/` directory.

---

## 0. Findings that correct the brief's premises

Three of the "known unnamed big functions" listed as pure game logic are not.

| VA | what it actually is | evidence |
| --- | --- | --- |
| `0x40fe90` (681 L) | software rasteriser: z-ordered, view-clipped polygon fill with a `switch` on polygon kind | `switch(cVar1) { case '\0': case '\x04': … case '\b': case '\f':` over 4-vertex and 3-vertex records (`bugs_decompiled.c:20918`, `:20955`). Called only from `FUN_0044c270`. |
| `0x4034f0` (354 L) | DirectSound secondary-buffer slot allocator / format setter | walks `(&DAT_00555ff0)[DAT_005546a0 * 0x40]`, i.e. a 0x40-stride pool (`bugs_decompiled.c:3212` area, caller `FUN_00403300`). |
| `0x434cd0` (1084 L) | fixed-point matrix / pose evaluator writing into a scratch arena, with a deliberate overflow trap | `if ((int *)(DAT_004efac0 + 0x400) <= param_4 + 0x72) { do { } while( true ); }` (`bugs_decompiled.c`, `FUN_00434cd0` body). |

`0x4318f0` (686 L) *is* game logic: per-entity update, called only from `FUN_00447d40`.

`FUN_0040e790` is named `ogl_init` in `tools/renames.json`. Verified body: it is the
**game-window + renderer init**, and it installs either of two renderer vtables
(§3.3). `ogl_init` understates it. CONFIRMED (see §3.3 quotes).

---

## 1. Startup sequence inside `0x405950` (winmain)

In order, as it appears in the function. CONFIRMED throughout unless tagged.

```
0x405950: LoadStringA(param_1,*(UINT *)(PTR_DAT_0045f344 + 8),local_250,0x104);
0x405950: LoadStringA(DAT_004b1ce8,*(UINT *)(PTR_DAT_0045f344 + 4),local_14c,0x104);
0x405950: pHVar5 = FindWindowA(s_BBLIT_Game_0045f348,local_14c);
```

1. **Two `LoadStringA` calls**, then a **single-instance check** by
   `FindWindowA("BBLIT_Game", <title>)`. If found: `BringWindowToTop`, and either
   `return 0` or `ShowWindow(pHVar5,9); return 0`. CONFIRMED.

   Ordering defect in the original (verified empirically, §6.3): the second
   `LoadStringA` is passed `DAT_004b1ce8` as the module handle, but `DAT_004b1ce8` is
   not assigned until far later in the same function
   (`0x405950: DAT_004b1ce8 = param_1;`). Measured initial value of `DAT_004b1ce8` in
   the mapped PE image is **NULL** (`[INIT] … DAT_004b1ce8=(nil)`). So on retail Win32
   this `LoadStringA` fails, `local_14c` is left uninitialised, and the single-instance
   check compares against stack garbage. CONFIRMED as a defect; it does **not** crash
   Win32 and is not the port's SIGSEGV.

   `PTR_DAT_0045f344` is dereferenced at this point and only assigned ~30 lines later by
   a switch on the language id. It has a static initialiser: measured
   `PTR_DAT_0045f344 = 0x45f2b8` (the language-0 record). Not a NULL deref. CONFIRMED by
   measurement.

```
0x405950: DAT_007c95e4 = GetSystemMetrics(0);
0x405950: DAT_007c95e0 = GetSystemMetrics(1);
0x405950: FUN_00409e30();
0x405950: FUN_00409cc0();
0x405950: switch(_DAT_009ca828) {
0x405950: case 0:  PTR_DAT_0045f344 = &DAT_0045f2b8; break;
0x405950: case 1:  PTR_DAT_0045f344 = &DAT_0045f2d0; break;
...
0x405950: case 5:  PTR_DAT_0045f344 = &DAT_0045f330;
```

2. **Screen size** into `DAT_007c95e4` / `DAT_007c95e0`; then two init calls
   (`FUN_00409e30`, `FUN_00409cc0` = `load_config`); then a **6-way language switch**
   selecting a 0x18-byte string record. CONFIRMED. (Measured defaults in the port run:
   `GetSystemMetrics` stub returns 640x480, not the retail 512x384 — that is the shim,
   not the game.)

```
0x405950: LVar7 = RegOpenKeyExA((HKEY)0x80000001,s_Software_Infogrames_Bugs_Bunny_L_0045f388,0,0x20019,&local_8);
0x405950: if (LVar7 != 0) { return 0; }
0x405950: local_14c[0] = DAT_004b1a34;
0x405950: puVar18 = (undefined4 *)(local_14c + 1);
0x405950: for (iVar10 = 0x40; iVar10 != 0; iVar10 = iVar10 + -1) { *puVar18 = 0; puVar18 = puVar18 + 1; }
0x405950: LVar7 = RegQueryValueExA(local_8,s_installation_path_0045f374,(LPDWORD)0x0,&local_10,local_14c,&local_c);
0x405950: if (LVar7 != 0) { RegCloseKey(local_8); return 0; }
```

3. **Registry gate.** `HKCU\Software\Infogrames\Bugs Bunny Lost In Time` (access
   `0x20019` = `KEY_READ`), value `installation_path`, type `REG_SZ`, into a 260-byte
   buffer that is explicitly zeroed first (0x40 dword stores at `local_14c+1`, then a
   `u16` and a byte — exactly 259 bytes, **in bounds**, `local_14c` is 260). Any failure
   ⇒ silent `return 0` before any window exists. CONFIRMED. This matches `RE_NOTES.md`
   step 2; I verified it in the code.

4. Two hand-inlined `strcat`-shaped loops append a separator and a subdirectory to the
   install path (constants at `0x45f36c` / `0x45f370`), then:

```
0x405950: FUN_00450760();
0x405950: RegCloseKey(local_8);
```

   `FUN_00450760` is the `SetCurrentDirectoryA` wrapper, which on success also writes
   `GetCurrentDirectoryA` output back as an environment variable:
   `FUN_00450760: BVar2 = SetCurrentDirectoryA(param_1); … DVar3 = GetCurrentDirectoryA(0x105,lpBuffer);`
   CONFIRMED.

5. **Disc check — inline, twice.** RE_NOTES describes this as `FUN_00405850` plus two
   inline copies. Verified: winmain does **not** call `FUN_00405850` at all; the loop is
   inlined twice (initial scan + retry scan). `FUN_00405850` is a *third*, standalone copy
   that is only reached later, from `FUN_0042e7a0` (the BZE loader). CONFIRMED.

```
0x405850: local_20c = (char)DAT_0045f368;
0x405850: if ('z' < local_20c) { … return uVar5; }
0x405850: UVar2 = GetDriveTypeA(*(LPCSTR *)(puVar6 + -4));
0x405850: if (UVar2 == 5) { … BVar3 = GetVolumeInformationA(...); … iVar4 = __strcmpi(...,"BBLIT"); }
0x405850: DAT_004b1928 = puVar6[-4]; _DAT_004b1929 = DAT_0045f354; _DAT_004b192d = DAT_0045f358; DAT_004b1931 = DAT_0045f35c;
```

   Start letter is **not** `'C'`: measured `DAT_0045f368 = "a:\"`, and the loop bound is
   `'z'`. So the scan is `'a'`…`'z'`, root string `"<letter>:\"`, kept when
   `GetDriveTypeA()==5` **and** `__strcmpi(volumeLabel,"BBLIT")==0`, stored into the
   12-byte `DAT_004b1928`. CONFIRMED (code + measurement). `RE_NOTES.md` says "from
   `DAT_0045f368` up to `z`", which is right but does not say the first letter is `'a'`.

6. **No CD ⇒ modal retry loop**, which is the documented exit gate:
```
0x405950: if (!bVar2) {
0x405950:   do {
0x405950:     iVar10 = FUN_00405640();
0x405950:     if (iVar10 == 2) break;
0x405950:     … rescan …
0x405950:   } while (!bVar2);
0x405950:   if (!bVar2) { return 0; }
0x405950: }
```
   `FUN_00405640` = `error_message_box`: `FUN_00450490(local_400,param_1,&stack0x00000008)`
   (a `printf`-family format call into a 1024-byte buffer), then
   `MessageBoxA(DAT_004b1cec,local_400,s_Bugs_Bunny_0045f278,5)`. Its declared return is
   `void` in the decompile but winmain reads it, so the value is `MessageBoxA`'s return
   register. I did not pin the exact `MB_*` decoding of the literal `5`; the observed
   control flow is "2 ⇒ stop rescanning, anything else ⇒ rescan". CONFIRMED for the
   control flow, UNKNOWN for the exact button-flag spelling.

7. **`FUN_00408f70` = `parse_command_line`.** `GetCommandLineA()` then a chain of
   `_strstr` pairs, case-insensitive via `&DAT_004676xx` / `s__lowercase_004675xx`.
   Flags recovered and their targets, all CONFIRMED by quoted assignment:
   `/no_sync`,`/NO_SYNC` ⇒ `DAT_0045f2a4 = 0`; `/no_skip`,`/NO_SKIP` ⇒ `DAT_004b1900 = 1`;
   `/full` ⇒ `DAT_009ca838 = 1`; `/opengl` ⇒ `DAT_009ca824 = 2`; `/soft`,`/soft8`,`/soft16`,
   `/soft24`,`/softpal`,`/softrgb` ⇒ `DAT_009ca824` ∈ {0,1}; `/skip_intro` ⇒
   `DAT_0045f2a8 = 0`; `/cons` ⇒ `_DAT_004b18e8 = 1`; `/fntp` ⇒ `_DAT_004b1ce4 = 1`.
   Two flags carry a **level/scene number as text**: `_strncpy(&DAT_004b1a38,pcVar2 + 2,2);`
   and `_strncpy(&DAT_007c9360,pcVar2,in_ECX);` set `DAT_004b1d04 = 2` / `= 1`
   respectively (debug scene-jump modes). CONFIRMED.

8. **`FUN_0042a620`** — CPU/OS probe. It formats the strings
   `s_Platform_is_WIN95_004ac490`, `s_Version__d__d_004ac444`,
   `s_CPU_has_cpuid_instruction___s_004ac408`, `s_CPU_vender_is__s_004ac3f4`,
   `s_CPU_family_is__d_004ac3e0`, `s_CPU_speed__i_004ac398`,
   `s_Number_of_Processor__d_004ac380` via `FUN_00451a50`. `DAT_004b1de4` is the CPU
   MHz. CONFIRMED — and this is what feeds the retail 300 MHz gate:
   `0x405950: DAT_009ca824 = (uint)(299 < DAT_004b1de4);`
   CONFIRMED. `FUN_0042a0d0` is the underlying `GetSystemInfo`/`GetVersionExA`/
   `GlobalMemoryStatus`/CPUID routine.

9. **`FUN_00409860`, `FUN_00409990`** — renderer/GDI setup. Empirically these are where
   the port's four `ChoosePixelFormat` calls happen (they occur before the registry read
   in the observed run). Their bodies I did not read end to end; role assigned from call
   position plus the `ChoosePixelFormat` markers. PLAUSIBLE.

10. **Video init with up to three attempts** (`0x405950`):
```
0x405950: DAT_004b1ce8 = param_1;
0x405950: pHVar5 = (HWND)FUN_0040e790();
0x405950: if (pHVar5 == (HWND)0x0) {
0x405950:   if (DAT_009ca838 != (HWND)0x0) { DAT_009ca838 = pHVar5; pHVar5 = (HWND)FUN_0040e790(); }
0x405950:   if (pHVar5 == (HWND)0x0) {
0x405950:     DAT_009ca824 = (uint)(299 < DAT_004b1de4);
0x405950:     pHVar5 = (HWND)FUN_0040e790();
0x405950:     if (pHVar5 == (HWND)0x0) goto LAB_004060fc;
```
    Attempt 2 forces the windowed path (`DAT_009ca838 = NULL`), attempt 3 forces
    software and re-derives the renderer choice from CPU speed. Returns `NULL` ⇒ jump to
    the teardown tail. CONFIRMED.

11. **Game init `FUN_00406190`** (§5). **`FUN_00406190` also derives the scene id**:
```
0x406190: if (iVar8 == -2) {
0x406190:   *(undefined4 *)(DAT_0052fd00 + 0x10000) = 2;
0x406190: } else {
0x406190:   uVar6 = FUN_004508e0();
0x406190:   *(undefined4 *)(DAT_0052fd00 + 0x10000) = uVar6;
0x406190: }
```
    `DAT_004b1a38` empty ⇒ scene **2**; otherwise `FUN_004508e0` (which is `FUN_00450840`
    = CRT `atoi`) parses the command-line number. CONFIRMED. Table entry 2's filename is
    `"..\BZE\TITLE.BZE;1"` — the first record of the scene table sits at `0x4ad380`
    immediately before that literal, so **scene 2 is the title screen**. CONFIRMED from
    the symbol name + table layout.

### 1.1 First-time / intro path — CONFIRMED

```
0x406190: if (DAT_0045f2a8 != 0) {
0x406190:   DAT_007c95f8 = 0;
0x406190:   FUN_00430f30(0x4e);
0x406190:   DVar3 = GetTickCount();
0x406190:   (*DAT_004b1a80)();
0x406190:   uVar4 = GetTickCount();
0x406190:   while (uVar4 < DVar3 + 3000) { FUN_0042e370(); …PeekMessageA/Translate/Dispatch… if ((DAT_007c95f8 != 0) && (DAT_004b1a31 == '\0')) break; uVar4 = GetTickCount(); }
0x406190:   FUN_00430f30(0x4f);   … same 3-second loop …
0x406190:   FUN_00430f30(0x50);   … same 3-second loop …
0x406190: }
```
`DAT_0045f2a8` measured **1** in the image, cleared only by `/skip_intro`. Three
consecutive "demo/intro" scenes are loaded by table index `0x4e`/`0x4f`/`0x50`
(=78/79/80), each given a 3000 ms wall-clock budget via `GetTickCount`, each pumped with
`FUN_0042e370` + a Win32 message pump, each abandoned early if the level script sets
`DAT_007c95f8`. The renderer is presented between them through `(*DAT_004b1a80)()`.
CONFIRMED. **I do not claim which visual content these three are** — the code only gives
table indices.

`DAT_004b1a31` is the persisted "first time" flag. Load side reads `FirstTime=%i` out of
`..\bin\bugs.ini` (`FUN_00450d50(local_150,s_FirstTime__i_004676cc,local_154); DAT_004b1a31 = local_154[0];`),
save side writes `FirstTime=%i` back into `..\bin\config.pc`
(`FUN_00409f60: pcVar1 = _strstr(&stack0x00001000,s_FirstTime__00467714); if (pcVar1 != 0) { pcVar1[10] = (DAT_004b1a31 != '\0') + '0'; }`).
CONFIRMED.

---

## 2. The main loop

**The per-frame loop is inlined in `winmain` itself, at `0x405950`, label `LAB_00405db9`.**
There is no separate `main_loop()` function. CONFIRMED.

```
0x405950: while (puVar16 = puVar15, DAT_0045f2b0 == 1) {
0x405950:   pHVar5 = GetForegroundWindow();
0x405950:   if ((pHVar5 == DAT_004b1cec) || (DAT_004b2277 != '\0')) {
0x405950:     iVar10 = FUN_004065e0();
0x405950:     if (iVar10 == 0) { DAT_0045f2b0 = 0; break; }
...
0x405950:     FUN_00406ee0();
0x405950:     _DAT_004b18f0 = _DAT_004b18f0 + 1;
0x405950:   }
0x405950:   … PeekMessageA / TranslateMessage / DispatchMessageA …
0x405950: }
```

Shape: it is a **Win32 message pump with a fixed timestep**, not a sleep-based loop.
There is no `Sleep` in the steady-state path. The only `Sleep` in `winmain` is a
one-shot 3000 ms stall on level change:
```
0x4065e0: DVar2 = GetTickCount();
0x4065e0: if ((int)(DVar2 - local_8) < 3000) { … *(DWORD *)(puVar4 + -4) = 3000 - (DVar2 - local_8); Sleep(…); }
```
CONFIRMED.

The whole loop is gated on the game window having focus:
`if ((pHVar5 == DAT_004b1cec) || (DAT_004b2277 != '\0'))`. CONFIRMED.

### 2.1 Tick rate: 30 Hz — CONFIRMED

Computed once at the end of `FUN_00406190` from `QueryPerformanceFrequency`:

```
0x406190: QueryPerformanceFrequency((LARGE_INTEGER *)&DAT_004b1918);
0x406190: _DAT_007c95b0 = (float)_DAT_004b1918;
0x406190: _DAT_007c95c0 = 1000.0 / _DAT_007c95b0;
0x406190: _DAT_007c95a0 = _DAT_007c95b0 * 0.033333335;
0x406190: DAT_007c95cc = (int)((ulonglong)uVar13 >> 0x20);
0x406190: DAT_007c95c8 = (int)uVar13;
0x406190: DAT_007c95f0 = iVar8;   /* iVar8 = -DAT_007c95c8            */
0x406190: DAT_007c95f4 = iVar7;   /* iVar7 = -(DAT_007c95cc + (c8!=0)) */
0x406190: uVar13 = __allmul();    /* args: 0x1e, iVar7, iVar8          */
0x406190: DAT_007c95d4 = (int)((ulonglong)uVar13 >> 0x20);
0x406190: DAT_007c95d0 = (int)uVar13;
```
`0.033333335` is `1/30` as a float, so `DAT_007c95c8:c8` is the tick period in
performance-counter units — **30 ticks per second**. Two independent corroborations in
the same block: the literal `0x033333335` and the multiplier `0x1e` (=30) fed to
`__allmul`, which produces the `DAT_007c95d0/d4` catch-up tolerance (30 ticks).

### 2.2 Time source: `QueryPerformanceCounter` — CONFIRMED

The pacer is `FUN_00406ee0`, called once per iteration from the loop:

```
0x406ee0: QueryPerformanceCounter((LARGE_INTEGER *)&DAT_007c95d8);
0x406ee0: bVar10 = CARRY4(DAT_007c95e8,DAT_007c95c8);
0x406ee0: uVar1 = DAT_007c95e8 + DAT_007c95c8;
0x406ee0: DAT_007c95e8 = uVar1;
0x406ee0: iVar3 = DAT_007c95ec + DAT_007c95cc + (uint)bVar10;
0x406ee0: uVar2 = uVar1 - DAT_007c95d8;
0x406ee0: DAT_007c95ec = iVar3;
0x406ee0: iVar4 = (iVar3 - DAT_007c95dc) - (uint)(uVar1 < DAT_007c95d8);
```

`DAT_007c95e8/ec` is a 64-bit accumulator (low/high dwords). Each call adds exactly one
tick period and compares against `QueryPerformanceCounter` read into `DAT_007c95d8/dc`.
So: **`acc += freq/30; now = QPC(); dt = now - acc`** — a textbook fixed-timestep
accumulator, 64-bit, no floating point in the loop. CONFIRMED.

`GetTickCount` **is** used, but only for coarse 3000 ms budgets (the intro loops in
`FUN_00406190` and the level-change stall), not for the frame clock. CONFIRMED.

### 2.3 The "one tick elapsed" flag and frame counting

```
0x406ee0: if (((iVar4 <= DAT_007c95f4) && ((iVar4 < DAT_007c95f4 || (uVar2 < DAT_007c95f0)))) && (DAT_004b1900 == 0)) goto LAB_00407070;
0x406ee0: LAB_00407070: DAT_004b1d00 = 1; DAT_004b1924 = DAT_004b1924 + 1; return;
0x406ee0: DAT_004b1d00 = 0;
0x406ee0: DAT_004b1924 = 0;
0x406ee0: … while( true ) { do { QueryPerformanceCounter(…); } while (DAT_007c95dc < iVar3); … }
```

`DAT_004b1d00` is the **"a fixed tick elapsed" flag**; `DAT_004b1924` counts consecutive
elapsed ticks (thresholds 2 and 4 in the branches). When the frame arrives early the
pacer **busy-waits on `QueryPerformanceCounter`** until the scheduled time — it spins,
it does not sleep. `/no_skip` (`DAT_004b1900`) suppresses the early-out. CONFIRMED.

The loop body then branches on that flag:

```
0x405950: if (DAT_004b1d00 == 0) {
0x405950:   … full game update chain …  DAT_004b18fc = DAT_004b18fc + 1;
0x405950: } else {
0x405950:   _DAT_004b2368 = _DAT_004b2368 & 0xffff0000;
0x405950:   FUN_0040a530(DAT_004b39ac);
0x405950:   DAT_004b18f8 = DAT_004b18f8 + 1;
0x405950: }
```

Reading it the natural way round: `FUN_00406ee0` sets `DAT_004b1d00 = 1` when ≥1 tick
elapsed, so on the **next** iteration `DAT_004b1d00 == 1` and the *short* branch runs
(`FUN_0040a530`); when no tick elapsed the *full* chain runs. Either way the four
counters are what a profiler wants, and the pairing of `DAT_004b18f0` (+1 per iteration,
increment of the outer tick) with `DAT_004b18f8`/`DAT_004b18fc`/`DAT_004b18f4` is
consistent with **4 counters = total frames / ticks-fell-on / ticks-landed / presented**.
The exact semantics of each counter are **PLAUSIBLE**, not CONFIRMED: Ghidra's
`_DAT_004b18f0` is a 4-byte read at `0x4b18f0` that the type map renders as a pointer,
so the frame counters' widths are ambiguous in the decompile.

Two more counters: `DAT_004b39b0` counts pending presents
(`0x4065e0: DAT_004b39b0 = DAT_004b39b0 + 1;`) and is cleared after each present
(`0x405950: DAT_004b39b0 = 0;`). `DAT_004b2368` is the sub-tick/field written by the
pacer (`_DAT_004b2368 = _DAT_004b2368 & 0xffff0000;`) and indexed as
`(&DAT_004b3664)[DAT_004b2368 * 5]` in the renderers — a 5-entry table (likely
light/env slots). Its element type is UNKNOWN.

---

## 3. Per-frame call order

### 3.1 One iteration of the `winmain` loop (0x405950)

```
GetForegroundWindow()                                   focus gate
└─ FUN_004065e0()            [0x4065e0]   <-- THE PER-FRAME UPDATE, see 3.2
   ├─ if (DAT_004b1d00 == 1)  -> FUN_0040a530(DAT_004b39ac)
   └─ else                    -> 0x40ceb0, 0x40a1f0, 0x44b370, 0x44c4b0, 0x44bb50, 0x44cfa0
(*DAT_004b1a90)()            present  (renderer vtable)
  or InvalidateRect/UpdateWindow(DAT_004b1cec)          software blit path
DAT_004b39b0 = 0
FUN_00406ee0()               [0x406ee0]  <-- THE PACER (sets DAT_004b1d00)
_DAT_004b18f0 += 1
PeekMessageA/TranslateMessage/DispatchMessageA          win32 pump
```

The present branch:
```
0x405950: if (DAT_004b39b0 < 1) { (*DAT_004b1a90)(); }
0x405950: else { if (DAT_004b1d00 == 0) { if (DAT_004e5e40 < 1) { (*DAT_004b1a90)(); } else { InvalidateRect(DAT_004b1cec,0,0); UpdateWindow(DAT_004b1cec); _DAT_004b18f4 = _DAT_004b18f4 + 1; } …pump… } DAT_004b39b0 = 0; }
```
CONFIRMED. `DAT_004e5e40` selects deferred WM_PAINT blitting over an explicit flip.

### 3.2 `FUN_004065e0` — the update, in source order

```
0x4065e0: DAT_004b24a4 = DAT_004b24a4 + 2;
0x4065e0: DAT_004b2384 = DAT_004b24a4 - DAT_004b28c4;
0x4065e0: DAT_004b28c4 = DAT_004b24a4;
0x4065e0: FUN_004491c0();                        <-- INPUT
0x4065e0: FUN_00447d40(DAT_004b3740);            <-- WORLD / SCENE UPDATE  (445 L)
0x4065e0: FUN_0041edb0((int)DAT_004b39c0);       <-- SOUND state update   (450 L)
0x4065e0: FUN_0041e2b0();                        <-- AUDIO MIX / XA-ADPCM (159 L)
0x4065e0: if (DAT_0045f2ac == '\0') goto LAB_00406ec2;   (just bump tick counters)
0x4065e0: if (DAT_004b39bc == 0) { FUN_00407190(); }      <-- GAME LOGIC / SCRIPT
0x4065e0: … DAT_004b2260 / DAT_004b226c / DAT_004b1908 / DAT_004b1a2c / DAT_004b3232 / DAT_004b3940 state machine …
0x4065e0: FUN_0041d900();                        <-- MUSIC TRACK SELECT
0x4065e0: if (DAT_004b39bc == 1) { … SCENE TRANSITION, see §5 … }
0x4065e0: if (DAT_004b39bc == 2) { … state reset … }
```
Roles, each CONFIRMED from its body:

* `FUN_004491c0` (341 L) — **input**. `PeekMessageA` pump, then `FUN_00403010`, then
  `FUN_004023e0`/`FUN_00402290` depending on `DAT_0045f2b0 == 1`, which assemble a
  bit-packed device state into `DAT_004b18d8` from the table `(&DAT_009ca8c0)[…]`; then
  it decodes that into a **PSX-pad register block at `DAT_0052fd00 + 0x10000..0x1003e`**
  (`DAT_0052fd00+0x1000a`, `+0x1000c`, `+0x10010`, `+0x10012`, `+0x10014`, `+0x1003e`,
  with 0x8000/0x2000/0x4000/0x1000 as directional overflow flags and `0x7f`/`0xff80` as
  axis clamp values). This is the PS1 pad the port emulates; the exe never calls
  `GetAsyncKeyState`.
* `FUN_00447d40` (445 L) — **world/scene update**. `FUN_004318f0(DAT_004b39b8, *(undefined4 *)(DAT_004b324c + 0x1b4));`
  per entity, plus camera bookkeeping (`piVar5[6] = DAT_004b38cc - DAT_004b38c0;`).
  `FUN_004318f0` (686 L) calls `FUN_00434cd0` (the matrix/pose evaluator) — so this is
  the **physics/step** leg.
* `FUN_0041edb0` / `FUN_0041e2b0` — **audio**. `FUN_0041e2b0` indexes a per-language
  sample table `DAT_0045c338[((DAT_0052fd00+0x10050) * 0x40 + DAT_004b322e) * 4]` and
  mixes with `long double`; `FUN_0041da00` is the DirectSound bootstrap
  (`DirectSoundCreate` is the only API in its inventory) and is called from
  `FUN_0042e7a0`. CONFIRMED.
* `FUN_00407190` (119 L) — **game logic / scene script actions**. Dispatches
  `DAT_004b226a` ∈ {4,5,6}: 4 = reset world state to a default,
  5 = **load a savegame** (`FUN_00450420(local_160,s____bin_Savegame_d_dat_0045f3b8,*(undefined1 *)(DAT_0052fd00 + 0x100df));`
  then `FUN_00405760` + `FUN_004508f0(local_140,0x140,1,iVar2)` and a 0x140-byte copy into
  `DAT_0052fd00 + 0x10000`), 6 = `FUN_004074f0()` → `DAT_004b2268 = 20 or 26`.
  CONFIRMED.
* `FUN_0041d900` — **music track select**, walking `DAT_004b3a20` (3-byte records) and
  calling `FUN_0041d630(track)`; `FUN_0041d5c0`/`FUN_0041d5e0`/`FUN_0041d5a0` are the
  music start/stop calls.

### 3.3 Draw leg and the renderer vtable

The "draw" chain is four calls that push into a shared render context at
`DAT_004efac0` / `DAT_004efb8c`:

* `FUN_0040ceb0` (137 L) — **camera / view matrix**. Reads a 6-field camera struct
  (`param_1[0..5]`, position + angles), builds 0x1000-fractional fixed-point matrices via
  `FUN_00408060`, `FUN_004079e0`, `FUN_00407da0`, `FUN_00407c30`, `FUN_00408640`,
  `FUN_00408260`, and copies 8 dwords out via `FUN_00407930(…, &DAT_0052fd20)`.
  CONFIRMED. **Correction to the brief:** `0x40ceb0` is *not* input.
* `FUN_0040a1f0` (119 L) — scene-graph/object update for the visible set.
  `DAT_007c6248 = GetTickCount();` then walks `DAT_004efac0` nodes keyed off
  `param_1` (`DAT_004b39ac`), reading `*(short *)(param_1 + 0x26)` as an id and following
  `*(int *)(param_1 + 0x78)` as a child list; calls `FUN_0040a050` (which, from its body,
  walks `piVar4[0x12]` and applies a `DAT_007c6248` timestamp — a visibility/cull pass).
* `DAT_004efb8c = DAT_004e5e44;` — reset the render handle before the frame.
* `FUN_0044b370` (77 L), `FUN_0044c4b0` (264 L), `FUN_0044bb50` (138 L), `FUN_0044cfa0`
  (89 L) — the four draw passes, all calling through the renderer function-pointer
  slots: `(*DAT_004b1a64)(…)`, `(*DAT_004b1a5c)(DAT_004efb8c,0x1000 - DAT_004b3738)`,
  `(*DAT_004b1a60)(DAT_004efb8c)`, `(*DAT_004b1a68)(&DAT_004ae368)`, `(*DAT_007c961c)()`,
  `(*DAT_007c9618)(psVar5 + 0x48)`.

**There are two full renderer vtables, installed by `FUN_0040e790`, CONFIRMED:**

```
0x40e790: DAT_004b1a70 = &LAB_004124b0;  DAT_004b1a90 = &LAB_0040d440;  _DAT_004b1a94 = &LAB_0041f800;
0x40e790: DAT_007c624c = &LAB_0040a6c0;  DAT_007c6250 = &LAB_0040b130;
0x40e790: DAT_004b1a5c = &LAB_0040b980;  DAT_004b1a60 = &LAB_0040be10;
0x40e790: DAT_004b1a64 = &LAB_0040c5e0;  DAT_004b1a68 = &LAB_0040c850;
0x40e790: DAT_004b1a74 = &LAB_00414b40;  DAT_004b1a78 = &LAB_00414590;  DAT_004b1a7c = &LAB_00413be0;
0x40e790: DAT_004b1a8c = &LAB_00413a20;  DAT_004b1a80 = &LAB_00413f00;
0x40e790: _DAT_004b1a84 = &LAB_00413b40; _DAT_004b1a88 = (code *)&LAB_00413e40;
0x40e790: _DAT_004b1a98 = &LAB_0040f8f0; DAT_004b1a9c = &LAB_0040efb0;
0x40e790: _DAT_004b1aa0 = &LAB_0040f510; DAT_004b1aa4 = &LAB_0040fa90;
0x40e790: DAT_007c961c = &LAB_00411330; DAT_007c9618 = &LAB_00411350;
0x40e790: DAT_004ac094 = DAT_009ca824;          /* OpenGL path   */
```
```
0x40e790: DAT_004b1a80 = &LAB_00416ff0;  _DAT_004b1a88 = FUN_00417010;
0x40e790: DAT_004b1a90 = &LAB_0040d4c0;  _DAT_004b1a94 = &LAB_0041ffc0;
0x40e790: DAT_007c624c = &LAB_0040aaf0;  DAT_007c6250 = &LAB_0040b550;
0x40e790: DAT_004b1a64 = &LAB_0040c350;  DAT_004b1a68 = &LAB_0040c920;
0x40e790: DAT_004b1a74 = &LAB_004161b0;  DAT_004b1a78 = &LAB_004159c0;
0x40e790: DAT_004b1a5c = &LAB_0040bc60;  DAT_004b1a60 = &LAB_0040c070;
0x40e790: DAT_004b1a7c = &LAB_00414350;  if (DAT_0046af60 != 8) { DAT_004b1a7c = &LAB_00414020; }
0x40e790: DAT_004b1a8c = &LAB_00413f10;
0x40e790: _DAT_004b1a98 = &LAB_0040f6e0;  DAT_004b1a9c = &LAB_0040f150;
0x40e790: _DAT_004b1aa0 = &LAB_0040f340;  DAT_004b1aa4 = &LAB_0040fc00;
0x40e790: DAT_007c961c = &LAB_004116f0;  DAT_007c9618 = &LAB_00411720;
0x40e790: DAT_004ac094 = DAT_009ca824;          /* software path */
```
That verifies `RE_NOTES.md`'s `DAT_004ac094` claim (0/1 = software, 2 = OpenGL, no D3D)
**in the code** — I saw both assignments. `FUN_0040e790` also sets
`0x40e790: DAT_004ac094 = 0x10;` on entry as an "in-progress" sentinel. CONFIRMED.
The vtable is a **set of scattered globals** (`0x4b1a5c`…`0x4b1aa4` plus
`0x7c9618/61c`, `0x7c624c/50`), not a contiguous struct — so there is no single
"dispatch table address" to quote. Confirmed by the individual assignments above.
`DAT_0046af60` selects a colour depth (8 vs 16 vs 24) and picks a third variant of
`DAT_004b1a7c`.

### 3.4 ASCII call graph of one tick

```
                    winmain 0x405950   LAB_00405db9   while (DAT_0045f2b0 == 1)
                             |
             +---------------+---------------- GetForegroundWindow()==DAT_004b1cec
             |
             v
      FUN_004065e0 0x4065e0   "one frame"
             |
             +-- INPUT .................................. FUN_004491c0 (341L)
             |     PeekMessageA/Translate/Dispatch
             |     FUN_00403010 -> pad read
             |     FUN_004023e0 | FUN_00402290 -> DAT_004b18d8
             |     -> DAT_0052fd00+0x10000..0x1003e  (PSX pad regs)
             |
             +-- UPDATE / PHYSICS ......................... FUN_00447d40 (445L)
             |     +-- per entity ......................... FUN_004318f0 (686L)
             |     |        +-- pose/matrix .............. FUN_00434cd0 (1084L)
             |     +-- FUN_00447b80 (list build)
             |     camera bookkeeping into DAT_004efac0
             |
             +-- AUDIO state ............................. FUN_0041edb0 (450L)
             +-- AUDIO mix  .............................. FUN_0041e2b0 (159L)
             |     sample table DAT_0045c338[lang*0x40 + id]
             |
             +-- GAME LOGIC / SCRIPT ..................... FUN_00407190 (119L)
             |     DAT_004b226a==4 reset | ==5 load savegame | ==6 ->FUN_004074f0
             |
             +-- STATE MACHINE (DAT_004b226c, 2260, 1908, 1a2c,
             |   3232 fade, 3940)  see section 4
             +-- MUSIC select ............................. FUN_0041d900 -> FUN_0041d630
             |
             +-- if DAT_004b39bc==1  SCENE TRANSITION ..... see section 5
             |
             +-- DRAW  (only when DAT_004b1d00 == 0)
             |     FUN_0040ceb0   camera/view matrix   (fixed point 0x1000)
             |     FUN_0040a1f0   scene graph update + cull
             |     DAT_004efb8c = DAT_004e5e44
             |     FUN_0044b370   pass 1  -> (*DAT_007c961c)() (*DAT_007c9618)(…)
             |     FUN_0044c4b0   pass 2  -> (*DAT_004b1a5c) (*DAT_004b1a60) (*DAT_004b1a64)
             |     FUN_0044bb50   pass 3  -> (*DAT_004b1a64) FUN_0040cc10
             |     FUN_0044cfa0   pass 4  -> (*DAT_004b1a68)
             |   (renderer vtable chosen in FUN_0040e790; see 3.3)
             |
             +-- if DAT_004b39bc != 1: FUN_0040a530(DAT_004b39ac)   (short leg)
             |
    back in winmain:
             +-- PRESENT ................. (*DAT_004b1a90)()
             |                           or InvalidateRect+UpdateWindow(DAT_004b1cec)
             +-- DAT_004b39b0 = 0
             +-- PACER .................. FUN_00406ee0 0x406ee0
             |     QueryPerformanceCounter -> DAT_007c95d8/dc
             |     acc(DAT_007c95e8/ec) += freq/30 ; dt = now - acc
             |     -> DAT_004b1d00 , DAT_004b1924   (busy-wait on QPC if early)
             +-- _DAT_004b18f0 += 1
             +-- PeekMessageA / TranslateMessage / DispatchMessageA
             `-> loop
```

---

## 4. Scene / game-state machine

**There is no exe-level scene switch and no function-pointer table indexed by scene id.**
Scene selection is a table lookup plus a data-driven trigger. Three layers exist, all
CONFIRMED unless tagged.

### 4.1 Layer 1 — app state `DAT_0045f2b0` (the only `switch`-like machine in the exe)

Measured initial value **1**. Values and their handlers, all in `0x405950`:

| `DAT_0045f2b0` | meaning | evidence |
| --- | --- | --- |
| `0` | quit | `0x405950: DAT_0045f2b0 = 0; break;` then `PostQuitMessage(0)` |
| `1` | running | the `while (…, DAT_0045f2b0 == 1)` loop condition |
| `0x13` (19) | display-mode change, do it silently | `0x405950: if (DAT_0045f2b0 == 0x13) { FUN_0040dd40(); goto LAB_004060b5; }` |
| `0x14` (20) | resolution-change prompt | `0x405950: if (DAT_0045f2b0 == 0x14) goto LAB_00406039;` |
| any other | fall back to 1 | `0x405950: DAT_0045f2b0 = 1; goto LAB_00405db9;` |

`0x14` handler:
```
0x405950: if (DAT_009ca838 != (HWND)0x0) { FUN_0040e1d0(0); FUN_0040dd40(); }
0x405950: DAT_0045f2b0 = 0;
0x405950: iVar10 = MessageBoxA(DAT_004b1cec,local_250,s_Bugs_Bunny_0045f278,4);
0x405950: if (iVar10 == 7) { if (DAT_009ca7b8 == 0) { DAT_0045f2b0 = 1; } else { DAT_0045f2b0 = 0x13; FUN_0040e1d0(1); FUN_0040dd40(); DAT_0045f2b0 = 1; } }
```
`0x405950: DAT_009ca7a4 = 0; DAT_009ca7b8 = 0; _DAT_009ca7b0 = 0x200; _DAT_009ca7b4 = 0x180;`
is the confirmed **default 512x384** fallback (`0x200`x`0x180`), and the same pair is set
by `FUN_0040e1d0`. CONFIRMED.

Producers: `FUN_004491c0` sets 0 on `WM_QUIT`; `FUN_00430f30`/`FUN_00430f80`/`FUN_00430e60`
set 0 on load failure; `FUN_0040e1d0` sets `0x13`. CONFIRMED (all 26 references checked).

### 4.2 Layer 2 — the scene id and its table

Current scene id is a dword at **`DAT_0052fd00 + 0x10000`**. CONFIRMED (every read and
write quoted in §1.11 and §5).

Scene id → `.BZE` file number, via a 16-byte-stride table based at `0x4ad380`:

```
0x430e60: if (*(short *)(&DAT_004ad384 + param_1 * 0x10) != 0) {
0x430e60:   DAT_004b3e48 = 4;
0x430e60:   … (param_1 == 3 special-cased per language) …
0x430e60:   iVar2 = FUN_0042e7a0(iVar2,DAT_0052fd00 + 0x200000);
```
```
0x430f30: if (*(short *)(&DAT_004ad384 + param_1 * 0x10) != 0) {
0x430f30:   DAT_004b3e48 = 4;
0x430f30:   iVar1 = FUN_0042e7a0((int)*(short *)(&DAT_004ad384 + param_1 * 0x10),DAT_0052fd00 + 0x200000);
```
`0x4ad380` holds `char* filename` at +0 and the loader writes `u16` at +6:
```
0x42e7a0: *(undefined2 *)(&DAT_004ad386 + param_1 * 0x10) = 1;
0x42e7a0: pcVar5 = (&PTR_s____BZE_TITLE_BZE_1_004ad380)[param_1 * 4];
```
so the record is `{char* bze_path; u16 ?; u16 loaded; …}` at 16-byte stride, with the
*scene→BZE number* short at +4 and the *filename pointer* at +0. **I did not enumerate
the table's length** — the highest index referenced in the decompile is `0x50` (80), and
`RE_NOTES.md` records 167 `.BZE` files, but the table's true bound is UNKNOWN (it lives
in the PE `.data` section, which is not in this workspace).

Load-phase flag `DAT_004b3e48`: `0` = reset done, `4` = about to load, `2` = loaded,
`1` = set by `FUN_00406190` just before entering the loop. CONFIRMED.

### 4.3 Layer 3 — the trigger records (this is the actual "scene machine")

`FUN_004384a0` (104 L) evaluates a level trigger record. The record is
`{u16 ?, u16 ?, u32 flagmask @ +0x14, …, u32 payload[3] @ +0x18}` and the **flag word at
`piVar2[5]` (+0x14) is the opcode**:

```
0x4384a0: if ((piVar2[5] & 0x80000U) != 0) {
0x4384a0:   *(int *)(DAT_0052fd00 + 0x10000) = piVar2[6];
0x4384a0:   DAT_004b39bc = 1;
0x4384a0: }
```
**Bit `0x80000` = "load scene `payload[0]`".** That is the scene switch. CONFIRMED.
Neighbouring opcodes in the same block, CONFIRMED:

| mask | effect | line |
| --- | --- | --- |
| `0x80000000` | `FUN_004377a0(obj, payload…)` | `if ((piVar2[5] & 0x80000000U) != 0) { FUN_004377a0(param_1,piVar2[6],param_2); }` |
| `0x800` | `FUN_004379b0(payload[0..2])` | |
| `0x800000` | set globals `_DAT_004b2180/84/88 = payload[0..2]` | |
| `0x40000000` | detach object from parent, clear `+0x70`/`+0xc0`, reflag `+0x14 |= 0x202` | |
| `0x200000` | `FUN_00437b90(payload[0],0)` | |
| `0x400000` | `DAT_004b2370 = payload[0]` | |
| `0x100000` | `DAT_004b2460/64/68 = payload[0..2]`, `+0x6c` from parent | |
| `0x200` | `FUN_0041deb0(0,payload[0],1,DAT_004b2368)` | |
| `0x2000` | `FUN_00437510(obj,payload[0],…)` | |
| `0x40` (byte at +0x14) | `FUN_004373f0(&payload[0..2])` | |

So **title screen, level select, in-level play, cutscene and credits are all the same
mechanism**: different `.BZE` scene files whose script records fire these opcodes. The
exe contains no `switch` on "am I in a cutscene". UNKNOWN-but-expected: the mapping from
scene id to what the player sees is in the level data, which is not in this workspace.

### 4.4 The in-scene sub-machine (`DAT_004b226c`, `DAT_004b226a`, fade)

All written in exactly one place, `FUN_004065e0`:

```
0x4065e0: if ((char)DAT_004b2260 == '\0') {
0x4065e0:   if (DAT_004b226c == '\0') { … if (DAT_004b1908 == 0) { if (DAT_004b1a2c == 0) goto LAB_0040679a; FUN_00449d60(DAT_004b2164); DAT_004b226c = '\x03'; FUN_0041d5c0(); FUN_0041f450(); } else { … DAT_004b226c = '\x01'; DAT_004b226d = 0; DAT_004b226e = 1; DAT_004b226f = 0; DAT_004b2270 = 1; … } }
0x4065e0:   else if (DAT_004b226c == '\x02') { if (DAT_004b3fc0 == 0) { DAT_004b226c = '\0'; … FUN_0041d5e0(); FUN_0041f510(); goto LAB_0040679a; } }
0x4065e0:   else { DAT_004b1908 = 0; DAT_004b1a2c = 0; FUN_0041d5c0(); }
0x4065e0: } else LAB_0040678e: DAT_004b1908 = 0; DAT_004b1a2c = 0;
0x4065e0: LAB_0040679a: FUN_0041d900();
```

* `DAT_004b226c` ∈ {0,1,2,3}: 0 = active, 1 = fade-out in progress (`_DAT_004b226c` set),
  2 = wait for `DAT_004b3fc0 == 0` then hand back, 3 = triggered. Paired with
  `DAT_004b1908` / `DAT_004b1a2c` which gate entry (`DAT_004b1a2c == 0` ⇒ state 3,
  else state 1 with `DAT_004b226d/e/f/70` cleared). CONFIRMED.
* **The pause menu is not here.** I searched every write to `DAT_004b226c` (5 sites, all
  in `FUN_004065e0`) and every write to `DAT_004b226a` (1 site, the reset at the end of
  `FUN_00407190`). `DAT_004b226a` is *read* as {4,5,6} but never written in the exe —
  so its producer is outside the decompiled set or lives in the level data.
  **Where the pause menu lives is UNKNOWN.** PLAUSIBLE: it is a `.BZE` scene reached via
  the `0x80000` trigger, because `DAT_004b1a2c`/`DAT_004b1908` gate exactly that and
  `DAT_004b226c == 2` waits on a counter — but I have no line proving it.
* **Screen fade**: `DAT_004b3232` is a bitfield fade state, with
  `FUN_0044bec0(2,0x100)` = start fade-out and `FUN_0044be90(1,0x100)` = start fade-in:
  ```
  0x44bec0: DAT_004b3232 = param_1; _DAT_004b3236 = param_2; DAT_004b2388 = 0x1000; DAT_004b3738 = 0;
  0x44be90: DAT_004b3232 = param_1; _DAT_004b3236 = param_2; DAT_004b2388 = 0;     DAT_004b3738 = 0x1000;
  ```
  with a per-frame stepper in `FUN_0044bef0`/`FUN_0044c4b0` using steps of `0x100` over a
  `0x1000` range (16 steps) and a `while ('\0' < DAT_004b3232)` drain loop in the caller.
  CONFIRMED.

---

## 5. Level transition

### 5.1 Who calls `bze_load_level` (`0x42e7a0`)

Four call sites, CONFIRMED from the call graph and quoted args:

| caller | call | context |
| --- | --- | --- |
| `FUN_00406190` `0x406190` | `FUN_0042e7a0(uVar2, DAT_0052fd00 + 0x200000)` | first load; `uVar2` = table lookup of `*(int*)(DAT_0052fd00+0x10000)`. Failure ⇒ `FUN_00434c30(DAT_004b2490)`, `FUN_00450800(1)` (exit 1). |
| `FUN_00430e60` `0x430e60` | `FUN_0042e7a0(iVar2, DAT_0052fd00 + 0x200000)` | mid-game scene change |
| `FUN_00430f30` `0x430f30` | `FUN_0042e7a0((int)*(short *)(&DAT_004ad384 + param_1*0x10), DAT_0052fd00 + 0x200000)` | intro scenes 0x4e/0x4f/0x50 |
| `FUN_004430f80` `0x430f80` | `FUN_0042e7a0(param_1, DAT_0052fd00 + 0x200000)` | reload |

Destination buffer is always `DAT_0052fd00 + 0x200000` — the world/scratch arena.
`DAT_004b1dfc` is set to 1 around the `0x430e60` load. CONFIRMED.

### 5.2 The transition sequence in `FUN_004065e0` — CONFIRMED

```
0x4065e0: if (DAT_004b39bc == 1) {
0x4065e0:   DAT_004b226c = 0; DAT_004b28cc = 0; DAT_004b238a = 0; DAT_004b39b2 = 0;
0x4065e0:   FUN_00449d60(DAT_004b2164);
0x4065e0:   DAT_004b1908 = 0; DAT_004b2277 = 0;
0x4065e0:   FUN_0041e2b0();
0x4065e0:   DAT_004b2368 = DAT_004b2368 + 1;
0x4065e0:   DAT_004b39b0 = DAT_004b39b0 + 1;
0x4065e0:   FUN_0044bec0(2,0x100);                      /* fade OUT           */
0x4065e0:   DAT_0045f2ac = 0;
0x4065e0:   … one full frame of the old scene …  (*DAT_004b1a90)(); DAT_0045f2ac = 1;
0x4065e0: LAB_00406a3a:
0x4065e0:   DAT_004b39bc = 0;
0x4065e0:   *(undefined1 *)(DAT_0052fd00 + 0x1004f) = 0;
0x4065e0:   if (*(int *)(DAT_0052fd00 + 0x10000) < 0) { return 1; }
0x4065e0:   local_8 = GetTickCount();
0x4065e0:   _DAT_004b3650 = *(undefined2 *)(DAT_0052fd00 + 0x10000);
0x4065e0:   FUN_00430e60();                            /* <== THE LOAD        */
0x4065e0:   (*DAT_004b1a80)();                          /* renderer reset     */
0x4065e0:   DAT_004b2384 = 0; DAT_004b28c4 = 0; DAT_004b24a4 = 1;
0x4065e0:   FUN_00430f80();
0x4065e0:   … up to 3000 ms Sleep(3000 - elapsed) if the new scene id is one of a
0x4065e0:     fixed list of ids (2, 0x45, 0x31, 0x32, 0x2c, 0x41..0x43, 0x28, 0x3d..0x40,
0x4065e0:     0x3a..0x3c, 0x39, 6, 7, 0x34..0x36, 0x46) …
0x4065e0:   DAT_004b2368 = DAT_004b2368 + 1;
0x4065e0:   FUN_0044be90(1,0x100);                      /* fade IN            */
0x4065e0:   DAT_0045f2ac = 0; DAT_004b1d00 = 0;
0x4065e0:   iVar1 = 0;
0x4065e0:   do { iVar1 = FUN_004065e0(); FUN_0040a530(DAT_004b39ac); iVar1 = iVar1 + 1; } while (iVar1 < 2);
0x4065e0:   FUN_0044bef0(); iVar1 = FUN_004065e0();
0x4065e0:   … resume normal frames …
0x4065e0: LAB_00406dc6:
0x4065e0:   _DAT_004b18f0 = 0; DAT_004b18f8 = 0; DAT_004b1d00 = 0; DAT_004b1924 = 0;
0x4065e0:   QueryPerformanceCounter((LARGE_INTEGER *)&DAT_007c9600);
0x4065e0:   DAT_007c95ec = DAT_007c9604; DAT_007c95e8 = DAT_007c9600;
0x4065e0:   return 1;
```

`FUN_004065e0` is therefore **both the per-frame update and the transition handler**, and
it is also re-entrant (it calls itself at `0x406972` and `0x406cfe`). CONFIRMED.

`DAT_004b39bc == 2` is a second transition kind: it only resets state, sets two
`DAT_0052fd00+0x1004x` bytes and re-bases the clock, without a `.BZE` load.
CONFIRMED. Who sets `== 2`: only the reset at the end of this function; **the producer of
the value 2 is UNKNOWN**.

Notable: the pacer's accumulator is **re-based** at both ends of the transition
(`0x406de9`/`0x406dc6`), so a scene change does not inherit a fractional tick — which is
what stops the first post-transition frame from immediately stalling.

The `Sleep(3000 - elapsed)` list is a **hardcoded id allow-list for a 3-second stall
right after loading** — those ids are titles/menus rather than gameplay. The set is
CONFIRMED as quoted; **what the individual ids are is UNKNOWN** except id 2 = TITLE.

---

## 6. The startup SIGSEGV

Environment: I built `linux/build/bblit` with `tools/build.sh` (gcc, clean, 4 s) and ran
it. `README.md` says startup "ends in a SIGSEGV"; reproduced:

```
$ ./bblit >/tmp/run1.out 2>&1 ; echo $?
139                       # SIGSEGV
$ wc -l /tmp/run1.out
127992                    # ~42,662 iterations of the retry dialog first
```
CONFIRMED by measurement. `si_addr=(nil)`, and with a `ucontext` probe
(`RIP=0x0 RAX=0x0` in one run) — i.e. **a jump/call into address 0 after ~43–85 k loop
iterations**, iteration count varying between runs (42,662 vs 85,323), which points at
memory corruption rather than a deterministic bad call.

### 6.1 Root cause — CONFIRMED by measurement

The disc check never matches, so `winmain` spins in the retry dialog forever until the
frame-slot corruption below destroys the return path.

Instrumented `__strcmpi` shows exactly why it never matches:

```
[sc #1] n=2 a=0x7ffd444a12c0 ok_a=1 'BBLIT' | b=0x7ffd ok_b=0 '<unreadable>'
```

The label buffer holds `'BBLIT'` correctly, but the **needle is `0x00007ffd`, not
`0x0045f360`**. The needle is supposed to be re-read from the outgoing-call frame slot:

```
bblit_game.c:3698   *(char **)(puVar15 + -0x28) = STR_CD_VOLUME_LABEL;
bblit_game.c:3699   *(undefined1 **)(puVar15 + -0x2c) = local_354;
bblit_game.c:3700   iVar10 = __strcmpi(pad354,*(char **)(puVar15 + -0x28));
```

`*(undefined1 **)(puVar15 + -0x2c)` is an **8-byte** store covering slots `-0x2c`…`-0x25`,
which **clobbers the 8 bytes of the pointer just stored at `-0x28`**. What survives at
`-0x28` is the *high* half of a stack address (`0x7ffd`) — exactly the measured value.
In the original 32-bit code that slot held a 4-byte address (`0x0045f360`) and the read
back was 4 bytes, so there was no overlap and no corruption.

The same shape is visible in the decompile itself, one line earlier:
```
0x405950: UVar9 = GetDriveTypeA(*(LPCSTR *)(puVar15 + -4));
0x405950: *(undefined4 *)(puVar15 + -0x1c) = 0x104;
0x405950: *(undefined1 **)(puVar15 + -0x20) = local_354;
```
which is why the shim observed `vlen=32765` instead of `0x104`: the 8-byte pointer store
at `-0x20` overwrites the 4-byte `0x104` at `-0x1c`. The 32-bit slot model and the
64-bit pointer model are incompatible wherever Ghidra's `-4`/`-8`/`-0xc` slot arithmetic
produces overlapping slots.

**Two controls, both run:**

*Control A* — make the shim's `MessageBoxA` return 2 (the cancel value winmain tests):
```
$ BBLIT_MB_RET=2 ./bblit ; echo $?
0                       # clean exit, no fault
```
So the `RIP=0` crash is a **consequence** of the unbounded retry loop, not an independent
defect.

*Control B* — change the read-back to the constant the original 32-bit code would have
read (`STR_CD_VOLUME_LABEL`) and rebuild:
```
[sc #1] n=2 a=0x7ffff0b73b90 ok_a=1 'BBLIT' | b=0x45f360 ok_b=1 'BBLIT'
```
The retry loop **disappears** — the disc check now succeeds. Startup advances past it.

**Verdict: CONFIRMED.** Defect is in `linux/bblit_game.c` (generated by
`tools/decomp2linux.py` from the decompile) and in the shim's already-documented
"4-byte frame slots widened to 8 bytes" class of divergence. The fix belongs in the
generator, not in a hand-edit of the generated file. (My control-B edit was reverted;
`git diff` is empty.)

### 6.2 The next blocker after the disc check — PLAUSIBLE, same root cause

With control B applied, startup advances and then faults again, immediately inside the
CPU/platform probe `FUN_0042a0d0` called from `FUN_0042a620`:

```
=== SIGSEGV si_addr=(nil) RIP=0x7fc02fa16b61 (/usr/lib/libc.so.6) RDI=0x4b3fe0 RSI=0x0
[sstr #71] h=0x4b3fe0 n=(nil)
```
`RDI = 0x4b3fe0 = &DAT_004b3fe0`, the CPU-vendor string buffer; the needle is **NULL**,
and the crash is a NULL read inside libc's `strstr`. The call site:
```
0x42a0d0: if (4 < (int)DAT_004b3ff0) {
0x42a0d0:   *(undefined **)((int)puVar12 + -2) = PTR_s_CyrixInstead_004ac310;
0x42a0d0:   *(undefined **)((int)puVar12 + -6) = &DAT_004b3fe0;
0x42a0d0:   ((ushort *)((int)puVar12 + -10))[0] = 0xa42e;
0x42a0d0:   ((ushort *)((int)puVar12 + -10))[1] = 0x42;
0x42a0d0:   pcVar8 = _strstr(*(char **)((int)puVar12 + -6),*(char **)((int)puVar12 + -2));
```
Identical mechanism: the 8-byte store at `-6` overwrites the low 4 bytes of the 8-byte
pointer stored at `-2` with the **high half of `&DAT_004b3fe0`, which is zero** because
the PE image is mapped below 4 GiB. The read at `-2` therefore yields `0x0`. CONFIRMED
as a fault site (measured needle); PLAUSIBLE as to whether this is the *next* thing to fix
after 6.1 in a repaired build — I did not repair 6.1 and re-run to prove ordering.

`DAT_004b1ff4 < 4` gate: note `DAT_004b3ff0` is the CPU **family**
(`0x42a0d0: DAT_004b3ff0 = DAT_004b3fc8 >> 8 & 0xf;`), and the `0xa42e,0x42` magic is the
CPUID extended-vendor signature for a Pentium II-class part. So the branch is reached on
any family ≥ 5 CPU — i.e. **it is always taken on a modern host**, and the shim's
`cpuid_Version_info` deliberately reports family `0x6`. PLAUSIBLE that this is why it
fires in the port.

### 6.3 Other defects found in the disc-check region (not the crash)

* `SetCurrentDirectoryA` is reached with a **NULL path** in the port:
  `[scda n=1] p=(nil)`. The install-dir `chdir` therefore never happens, so the
  relative-path lookups (`..\bin\config.pc`, `..\BZE\*.BZE`) have no base. CONFIRMED
  (measured). `RE_NOTES.md` states the game "chdirs into the install dir so these resolve
  there first" — true of the original, **not** of the port as built.
* `FUN_00450760` (`SetCurrentDirectoryA` wrapper) passes two **uninitialised stack
  pointers** to `SetEnvironmentVariableA`:
  `FUN_00454480(); BVar2 = SetEnvironmentVariableA(&stack0xfffffee8,&stack0xfffffeec);`
  CONFIRMED as a defect in the decompile (both operands are raw stack addresses, not
  anything `FUN_00454480` can have written through). Reachable only after the `chdir`
  succeeds, so it is currently masked by the item above.

---

## 7. Open / not settled

* **Pause menu**: no exe-side state found. UNKNOWN. See §4.4.
* **`DAT_004b226a` writer**: never written in the decompiled set. UNKNOWN.
* **`DAT_004b39bc == 2` producer**: only the reset is in the decompile. UNKNOWN.
* **Scene-table length**: highest referenced index is 80; true bound UNKNOWN (image
  `.data` not in this workspace).
* **Identity of the `0x80000`-trigger target for each gameplay state** — needs the level
  data. Needs runtime confirmation.
* **Semantics of `DAT_004b18f0 / 18f4 / 18f8 / 18fc`**: four frame counters, pairing
  inferred, widths ambiguous in the decompile. PLAUSIBLE.
* **Element type of `DAT_004b3664[n*5]`** and the role of `DAT_004b2368` as its index.
  UNKNOWN.
* **Meaning of the 3-second post-load stall id list** beyond id 2 = TITLE. UNKNOWN.
* `FUN_00409860` / `FUN_00409990` roles: assigned from call position plus
  `ChoosePixelFormat` markers, bodies not read end to end. PLAUSIBLE.
* Nothing here needs runtime confirmation except: the exact `MB_*` flag word behind the
  literal `5` / `4` in the message boxes, and the visual identity of each scene id.