# 05 — INPUT, CONFIG and SAVE formats (BUGS.EXE)

Reverse engineering of the input pipeline, `..\bin\config.pc`, `..\bin\bugs.ini`,
the command line, `..\bin\Savegame%d.dat` and `..\bin\Savedata.dat` in
BUGS.EXE (Bugs Bunny: Lost in Time, PC 1999).

Every offset/size/constant below is followed by the decompile line that proves it.
Confidence tags: **CONFIRMED** (quoted evidence + an independent cross-check),
**PLAUSIBLE** (one line of evidence, interpretation inferred), **UNKNOWN**.

No binary was run. Where a statement needs a live run to be sure it says so.

---

## 0. TL;DR of contradictions with RE_NOTES.md

| RE_NOTES.md says | The code says | Evidence |
| --- | --- | --- |
| "Input: ReadConsoleInputA + GetKeyboardState" | `ReadConsoleInputA` is used **only by the MSVC CRT `getch()`**, never by the game. The game's keyboard path is `GetKeyboardState` alone. | `0x45b010:` the only two `ReadConsoleInputA` call sites in the whole binary; it is `getch()` (see §1.4). |
| "config is `..\bin\config.pc` … FirstTime=%i, Language=%i" | `config.pc` is a **raw 128-byte binary blob**. `FirstTime`/`Language` are keys of `..\bin\bugs.ini`, a text file. | `0x409cc0:` `FUN_004508f0(&DAT_009ca820,0x80,1,iVar1);` / `FUN_004505c0(&DAT_009ca820,0x80,1,iVar1);` vs `0x409e30:` `_strstr(local_150,s_FirstTime_004676dc);` `FUN_00450d50(local_150,s_FirstTime__i_004676cc,local_154);` |
| "saves `..\bin\Savegame%d.dat`, `..\bin\Savedata.dat` (360/320B)" | Sizes are the other way round: **Savegame%d.dat = 320 B, Savedata.dat = 360 B**. | `0x4074f0:` `FUN_004505c0(DAT_0052fd00 + 0x10000,0x140,1,iVar3);` (Savegame) and `FUN_004505c0(&DAT_004b28e0,0x168,1,iVar3);` (Savedata). |
| "flags `/SKIP_INTRO /SOFT24 /SOFT16 /SOFTRGB /SOFTPAL /SOFT8 /OPENGL /NO_SKIP /NO_SYNC`" | Those 9 exist, **plus 20 more**: `/B /P: /R: /X /Y /FULL /WIN /OGL /SOFT /CONS /FNTP /PAL: /DLL:` and `/?`. See §5. | `0x467544`–`0x4676b4` string block, all consumed in `0x408f70`. |
| "bugs.ini keys `CheckGDI` and `DLL` override renderer detection" | No `CheckGDI` string exists anywhere in the image; `DLL` is a **command-line** flag `/DLL:`, not an ini key. | searched the whole 0x400000–0x9da000 blob for `CheckGDI`/`checkgdi`: 0 hits. `/DLL:` parsed at `0x408f70:` `pcVar2 = _strstr(_Str,s__DLL__0046756c);` |
| "two floats of 1.0" in config | There are **five** float fields (0x2C, 0x64, 0x6C, 0x74 = 1.0f, 0x28/0x58/0x60/0x68/0x70 = 0) plus a 256-byte gamma ramp built from three of them. | `0x409a90:` `param_2[0xb] = 0x3ff00000;` `param_2[0x19] = 0x3ff00000;` `param_2[0x1b] = 0x3ff00000;` `param_2[0x1d] = 0x3ff00000;` |
| "Input: no DirectInput" (implied by "ReadConsoleInputA + GetKeyboardState") | **DirectInput COM gamepad support exists and is always attempted at startup.** | `0x4025b0:` `DAT_009ca9c4 = 1; DAT_009ca9c0 = (code *)&LAB_00402810; FUN_00402610();` and `0x4477a0:` `iVar2 = FUN_004025b0(1,DAT_004b1ce8,DAT_004b1cec);` |

---

## 1. The input pipeline

### 1.0 Shape of the thing (CONFIRMED)

```
  GetKeyboardState(256-byte stack buffer)      DirectInput device (COM)
            |                                            |
   FUN_004028a0  (0x4028a0)                    FUN_00402180 (0x402180) Poll+GetDeviceState
   88 hand-unrolled copies                      |                     |
   keybuf[VK]>>7  ->  keystate[gameKeyId]      +----> DAT_004b1860 (lx) / DAT_004b1864 (ly)
   (array @0x009CA8C0, 256 bytes)                     DAT_004b1878 (32-bit button mask)
            |                                            |
            +----------------------+---------------------+
                                   |
                              keystate[]  + config bind bytes (0x46..0x55)
                                   |
             FUN_004023e0 (0x4023e0, menu mode)  |  FUN_00402290 (0x402290, game mode)
             FUN_00403010 (0x403010, analog stick + joystick buttons)
                                   |
                     PSX pad struct @ DAT_004B18D8
                     +0 status, +1 type(0x41/0x73/0x80), +2/+3 two ACTIVE-LOW button bytes
                                   |
                 FUN_004491c0 (0x4491c0) main loop: pad -> emulated PS1 RAM
                     RAM+0x1000C = live state, +0x1000E = prev, +0x1003E = just-pressed,
                     +0x1000A = "pressed" (mirrored), 0x10010 = pad state for the game
```

Call order per frame, from `0x4491c0` (the frame function):

```
0x449228:  FUN_00403010();                       // poll DirectInput -> pad analog/digital
0x44923d:  FUN_004023e0();                       // if (DAT_0045f2b0 == 1)  menu/navigation pad
0x449236:  FUN_00402290();                       // else                     in-game pad
```

`0x4491c0:` `FUN_00403010(); if (DAT_0045f2b0 == 1) { FUN_004023e0(); } else { FUN_00402290(); }`

### 1.1 The key-state array — address, size, indexing (CONFIRMED)

* **Array base: `0x009CA8C0`. Size: 256 bytes (`0x100`)** — indices 0..255, one byte each.
  The next global after it is `0x009CA9C0` (`DAT_009ca9c0`, the poller function pointer) and
  `0x009CA9C4` (`DAT_009ca9c4`, the mode flag), so the array cannot be larger.

* The array is **indexed by a game key ID, NOT by a virtual-key code.** This is the one
  place the usual assumption is wrong. Proof: the config file stores default binds as
  `0x46=0xC8, 0x47=0xD0, 0x48=0xCD, 0x49=0xCB, 0x4A=0x10 …` (`0x409a90:`), the display
  name for ID `200` is `KEY_UPARROW` and for ID `208` is `KEY_DOWNARROW` (table at
  `0x45E030`, read by `FUN_00402250`), and the read sites index it by those IDs:

  ```
  0x4023e0:  if ((&DAT_009ca8c0)[DAT_009ca866] != '\0') { *(byte *)(iVar2 + 2) = bVar3 | 0x10; }
  0x409a90:  *(undefined1 *)((int)param_2 + 0x46) = 200;
  0x409a90:  *(undefined1 *)((int)param_2 + 0x47) = 0xd0;
  0x45e030:  name record i=85 -> "KEY_UPARROW", id field (at +0x20) = 200
  0x45e030:  name record i=99 -> "KEY_DOWNARROW", id field (at +0x20) = 208
  ```
  (all three quoted lines are from the respective artefacts; the ID→name table is
  reproduced in §1.5 and is also `FUN_00402250`'s search table:
  `0x402250:` `if (param_1 == iVar1) { return iVar3 * 0x24 + 0x45e030; }`)

* The **GetKeyboardState buffer is a 256-byte stack buffer indexed by virtual-key code**,
  and the game copies 88 specific VKs into the 88 matching array slots with
  hand-unrolled code:

  ```
  0x4028a0:  BVar3 = GetKeyboardState(*(PBYTE *)(puVar4 + -4));
  0x4028a0:  if (BVar3 == 0) { FUN_004055d0("***********keyboard handler error***********\n"); }
  0x4028a0:  DAT_009ca8c1 = (char)((*(uint *)(puVar4 + 0x27) & 0xff) >> 7);   // id 1  = Esc   , VK 0x1B
  0x4028a0:  DAT_009ca988 = (char)((*(uint *)(puVar4 + 0x32) & 0xff) >> 7);   // id 200= Up    , VK 0x26
  0x4028a0:  DAT_009ca98d = (char)((*(uint *)(puVar4 + 0x33) & 0xff) >> 7);   // id 205= Right , VK 0x27
  ```
  `>> 7` after `& 0xff` is the Windows "high bit set = down" convention.

  The arithmetic relation **`buffer_index = (decompile offset) - 0x0C`** holds for
  **all 88 stores** (0 mismatches) against the independently recovered VK of every
  name in the `0x45E030` table. The decompiler prints the `GetKeyboardState` argument
  as `frame+0x10` while the reads prove it is `frame+0x0C`; that 4-byte discrepancy is
  Ghidra stack-slot mis-tracking, not a different index. Absolute stack address is
  UNKNOWN (needs disassembly); the *relative* base and the VK indexing are CONFIRMED.

* **88 of the 105 named keys are polled.** The 17 that are *not* copied from the
  keyboard buffer can therefore never be pressed and can never be bound to a
  working action: `NULL(0)`, `KEY_MINUS(12)`, `KEY_EQUAL(13)`, `KEY_LEFTBRACKET(26)`,
  `KEY_RIGHTBRACKET(27)`, `KEY_SEMICOLON(39)`, `KEY_APOSTROPHE(40)`, `KEY_TICK(41)`,
  `KEY_BACKSLASH(43)`, `KEY_COMMA(51)`, `KEY_PERIOD(52)`, `KEY_SLASH(53)`,
  `KEY_PADENTER(156)`, `KEY_LEFTWINDOW(219)`, `KEY_RIGHTWINDOW(220)`,
  `KEY_KEYBOARDMOUSE(221)`, `' '(255)`.
  `KEY_PADENTER` is not polled either but is kept in sync by a copy:
  `0x4028a0: DAT_009ca95c = DAT_009ca8dc;` (array[156] = array[28] = Enter).

* **Where the array is written:** only by `0x4028a0` (keyboard) and by the DI path for
  the byte values the UI reads. There is no separate clear — every polled slot is
  rewritten with 0 or 1 every frame, so the array is pure **level** state.

### 1.2 The binding table and what each slot means (CONFIRMED)

The bindings are **16 bytes inside config.pc** at offsets **0x46..0x55** (see §4),
exposed as globals `0x009CA866..0x009CA875`. They are *key IDs*, not VK codes.

Two pad-mapping functions read them. `FUN_004023e0` (used when
`DAT_0045f2b0 == 1`, i.e. menus) and `FUN_00402290` (in game) both write a **PSX
controller** structure at `DAT_004B18D8` whose bytes +2/+3 are **active-low** (the
standard PS1 pad: bit set = released), proved by the final double complement:

```
0x4023e0:  bVar3 = ~*(byte *)(DAT_004b18d8 + 2);
0x4023e0:  *(byte *)(iVar2 + 2) = bVar3 | 0x10;                       // Up
0x4023e0:  *(byte *)(iVar2 + 2) = *(byte *)(iVar2 + 2) | 0x20;        // Right
0x4023e0:  *(byte *)(iVar2 + 2) = *(byte *)(iVar2 + 2) | 0x40;        // Down
0x4023e0:  *(byte *)(iVar2 + 2) = *(byte *)(iVar2 + 2) | 0x80;        // Left
0x4023e0:  *(byte *)(iVar2 + 2) = *(byte *)(iVar2 + 2) | 1;           // Select
0x4023e0:  *(byte *)(iVar2 + 2) = *(byte *)(iVar2 + 2) | 8;           // Start
0x4023e0:  *(byte *)(iVar2 + 3) = ~bVar1 | 1;                         // L2
0x4023e0:  *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 2;          // R2
0x4023e0:  *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 4;          // L1
0x4023e0:  *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 8;          // R1
0x4023e0:  *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 0x10;       // Triangle
0x4023e0:  *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 0x20;       // Circle
0x4023e0:  *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 0x40;       // Cross
0x4023e0:  *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 0x80;       // Square
0x4023e0:  *(byte *)(iVar2 + 2) = ~*(byte *)(iVar2 + 2);
0x4023e0:  *(byte *)(iVar2 + 3) = ~*(byte *)(iVar2 + 3);
```

Full mapping (byte offsets are config.pc offsets; the quoted `(&DAT_009ca8c0)[…]` forms
are literally what the decompiler prints):

| PSX button | pad byte/bit | binds used | config offset | **default key ID** | **default key** |
| --- | --- | --- | --- | --- | --- |
| Up | +2 bit4 | `[DAT_009ca866]` | 0x46 | 0xC8 = 200 | `KEY_UPARROW` |
| Down | +2 bit6 | `[DAT_009ca867]` | 0x47 | 0xD0 = 208 | `KEY_DOWNARROW` |
| Right | +2 bit5 | `[DAT_009ca868 & 0xff]` | 0x48 | 0xCD = 205 | `KEY_RIGHTARROW` |
| Left | +2 bit7 | `[DAT_009ca868 >> 8 & 0xff]` | 0x49 | 0xCB = 203 | `KEY_LEFTARROW` |
| L2 | +3 bit0 | `[DAT_009ca868 >> 0x10 & 0xff]` | 0x4A | 0x10 = 16 | `Q` |
| R2 | +3 bit1 | `[DAT_009ca868 >> 0x18]` | 0x4B | 0x11 = 17 | `W` |
| L1 | +3 bit2 | `[DAT_009ca86c & 0xff]` | 0x4C | 0x12 = 18 | `E` |
| R1 | +3 bit3 | `[DAT_009ca86c >> 8 & 0xff]` | 0x4D | 0x13 = 19 | `R` |
| Triangle | +3 bit4 | `[DAT_009ca86c >> 0x10 & 0xff]` | 0x4E | 0x1E = 30 | `A` |
| Circle | +3 bit5 | `[DAT_009ca86c >> 0x18]` | 0x4F | 0x1F = 31 | `S` |
| Cross | +3 bit6 | `[DAT_009ca870 & 0xff]` | 0x50 | 0x20 = 32 | `D` |
| Square | +3 bit7 | `[DAT_009ca870 >> 8 & 0xff]` | 0x51 | 0x21 = 33 | `F` |
| (unused slot) | — | — | 0x52 | 0x0F = 15 | `KEY_TAB` |
| (unused slot) | — | — | 0x53 | 0x1C = 28 | `KEY_ENTER` |
| Select | +2 bit0 | `[DAT_009ca874 & 0xff]` | 0x54 | 0x0F = 15 | `KEY_TAB` |
| Start | +2 bit3 | `[DAT_009ca874 >> 8 & 0xff]` | 0x55 | 0x1C = 28 | `KEY_ENTER` |

The defaults come from `0x409a90` and the names from the `0x45E030` table, e.g.

```
0x409a90:  *(undefined1 *)((int)param_2 + 0x46) = 200;      // 200 = KEY_UPARROW
0x409a90:  *(undefined1 *)(param_2 + 0x14) = 0x20;          // 0x50 = 32 = "D" = Cross
0x45e8a0:  record i=60: "D" id=32
```

Notes:
* 0x52/0x53 hold the same TAB/ENTER pair as 0x54/0x55 and are **never read by either pad
  function** — vestigial/duplicate slots.
* The game-level names of the face/shoulder buttons ("jump", "action", "pause",
  "camera") are **not** decided here. The port feeds a PS1 pad into the original
  engine, so the mapping PSX-button → game verb lives in the emulated engine, not in
  the Win32 layer. UNKNOWN without further engine work; what is certain is that the
  Win32 layer only ever produces these 16 PSX bits.
* In-game (`FUN_00402290`) the four directions and Select/Start come from **fixed**
  array slots instead of the config binds — i.e. the config only remaps the pad in menus:
  ```
  0x402290:  if (DAT_009ca988 != '\0') { *(byte *)(iVar2 + 2) = bVar3 | 0x10; }   // Up    id 200
  0x402290:  if (DAT_009ca98d != '\0') { *(byte *)(iVar2 + 2) = … | 0x20; }        // Right id 205
  0x402290:  if (DAT_009ca990 != '\0') { *(byte *)(iVar2 + 2) = … | 0x40; }        // Down  id 208
  0x402290:  if (DAT_009ca98b != '\0') { *(byte *)(iVar2 + 2) = … | 0x80; }        // Left  id 203
  0x402290:  if (DAT_009ca8cf != '\0') { *(byte *)(iVar2 + 2) = … | 1;  }         // Select id 15
  0x402290:  if (DAT_009ca8dc != '\0') { *(byte *)(iVar2 + 2) = … | 8;  }         // Start  id 28
  ```
  The eight face/shoulder bits still use the config binds in `FUN_00402290`.
* UI text displays the bind by name: `0x44d100:` `pcVar17 = (char *)FUN_00402250(uVar19);`
  where `uVar19` is one of the 16 bind bytes. The equivalent for joystick buttons uses
  `0x403260:` `FUN_00450420(&DAT_009ca740,s_BUTTON_i_0045f26c,param_1);` with the
  format string `"BUTTON%i"` at `0x45F26C`.

### 1.3 Joystick / gamepad button bindings (CONFIRMED)

`config.pc` **0x3C..0x45, 10 bytes**, are *joystick button indices* (0..31), plus a
joystick-enabled flag at **0x38**:

```
0x409a90:  *(undefined1 *)(param_2 + 0xf) = 0;          // config+0x3C = 0
0x409a90:  *(undefined1 *)((int)param_2 + 0x3d) = 1;     // config+0x3D = 1
0x409a90:  *(undefined1 *)((int)param_2 + 0x45) = 9;     // config+0x45 = 9
0x409a90:  param_2[0xe] = 0;                             // config+0x38 = joystick off
0x403010:  if ((uVar1 & 1 << ((byte)DAT_009ca85c & 0x1f)) != 0) { puVar2[3] = 0x10; }        // btn0 -> Triangle
0x403010:  if ((uVar1 & 1 << (DAT_009ca85c._1_1_ & 0x1f)) != 0) { puVar2[3] = … | 0x20; }   // btn1 -> Circle
0x403010:  if ((uVar1 & 1 << (DAT_009ca860 & 0x1f)) != 0) { DAT_004b1878 = … | 0x100; }     // btn8
0x403010:  if ((uVar1 & 1 << (DAT_009ca865 & 0x1f)) != 0) { DAT_004b1878 = … | 0x200; }     // btn9
0x44d100:  if ((DAT_009ca85c._3_1_ != 0) && (DAT_009ca858 != 0)) { … }   // only shown if pad enabled
```
`DAT_009ca858` = config+0x38 is the "joystick in use" switch: every UI and input
site guards on `DAT_009ca858 != 0`. `0x403210`/`0x4477a0` also route the 10 buttons.

### 1.4 The `ReadConsoleInputA` path (CONFIRMED — it is not the game's)

`ReadConsoleInputA` has exactly **two** call sites in BUGS.EXE, both inside
`FUN_0045B010`, which is the **MSVC CRT `_getch()`**:

```
0x45b010:  if (DAT_004b1840 != 0xffffffff) { uVar1 = DAT_004b1840 & 0xff; DAT_004b1840 = 0xffffffff; return uVar1; }   // 1-char pushback
0x45b010:  if (DAT_004b1844 == (HANDLE)0xfffffffe) { FUN_0045b200(); }        // STDIN unopened -> CreateFileA("CONIN$")
0x45b010:  GetConsoleMode(DAT_004b1844,local_18); SetConsoleMode(DAT_004b1844,0);
0x45b010:  iVar2 = ReadConsoleInputA(DAT_004b1844,(PINPUT_RECORD)&stack0xffffffdc,1,(LPDWORD)&stack0xffffffd4);
0x45b010:  if ((iVar2 == 0) || (puVar4 = puVar5, *(int *)(puVar5 + 0x10) == 0)) { … return 0xffffffff; }   // EventType != KEY_EVENT -> skip
0x45b010:  if ((*(short *)(puVar5 + 0x18) == 1) && (*(int *)(puVar5 + 0x1c) != 0)) {   // wRepeatCount? != 0  (field offset per INPUT_RECORD, see below)
0x45b010:    uVar1 = *(uint *)(puVar5 + 0x26) & 0xff;                                  // uChar
0x45b010:    if (uVar1 != 0) goto LAB_0045b0e9;
0x45b010:    pbVar3 = (byte *)FUN_0045b120();  if (pbVar3 != 0) { uVar1 = *pbVar3; DAT_004b1840 = pbVar3[1]; … }
0x45b120:  uVar1 = *(uint *)(param_1 + 0xc);                       // KEY_EVENT_RECORD.dwControlKeyState
0x45b120:  if ((uVar1 & 0x100) == 0) { if ((uVar1 & 3) == 0) { … pcVar2 = &DAT_004b1578 + wVirtualScanCode*8 … } }
0x45b120:  if ((uVar1 & 0x100) != 0) { … search DAT_004b1500 by wVirtualScanCode, return 10-byte {char,char} records … }
```

Decoded against `INPUT_RECORD`/`KEY_EVENT_RECORD` (record base = `puVar5+0x18`, so the
decompiled offsets are +0 EventType, +4 bKeyDown, +8 wRepeatCount, +0xA wVirtualKeyCode,
+0xC wVirtualScanCode, +0xE uChar, +0x10 dwControlKeyState):

| test | field | meaning |
| --- | --- | --- |
| `*(int *)(puVar5+0x10) == 0` → skip | `EventType` | only `KEY_EVENT` (0) is accepted; mouse/focus/resize/menu records are discarded |
| `*(short *)(puVar5+0x18) == 1` | `bKeyDown` | key-**up** records are dropped |
| `*(int *)(puVar5+0x1c) != 0` | `wRepeatCount` | used only as a *non-zero* test |
| `*(uint *)(puVar5+0x26) & 0xff` | `uChar` | plain ASCII first, else the scancode table |
| `FUN_0045b120` | extended-key path | `dwControlKeyState & 0x100` = ENHANCED_KEY → scans `DAT_004b1500` by `wVirtualScanCode`; else indexes `DAT_004b1578/7A/7C/7E + scan*8` per shift/ctrl state |
| `DAT_004b1840 = pbVar3[1]` | **repeat handling** | `wRepeatCount` is **not** expanded; the table's second byte re-queues exactly **one** more char into the 1-byte pushback `DAT_004b1840` |

Consequences for a rewrite: (a) you do **not** need `ReadConsoleInputA` for the game;
(b) `GetKeyboardState` gives you no key-up/repeat information at all, so nothing in
the game depends on it.

### 1.5 Key-ID ↔ VK table (CONFIRMED, recovered from two independent artefacts)

Artefact A — `FUN_004028a0`'s 88 stores give `array[id] = keybuf[VK]`.
Artefact B — the name/ID table at `0x45E030`, 105 records of 0x24 bytes
(`char name[32]; uint32 id;`), terminator `id == 0xFFFFFFFF` at record 105
(`0x45EEF4`), searched by `FUN_00402250` to turn an ID into a display name.

Cross-check: for all 88 polled IDs, `VK == (decompiled stack offset) − 0x0C` and the
name found for that ID in artefact B has exactly that VK. 88/88, zero mismatches.

| id | VK | name | | id | VK | name | | id | VK | name |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0x1B | Esc | | 30 | 0x41 | A | | 57 | 0x20 | KEY_SPACE |
| 2 | 0x31 | 1 | | 31 | 0x53 | S | | 58 | 0x14 | KEY_CAPSLOCK |
| 3 | 0x32 | 2 | | 32 | 0x44 | D | | 59 | 0x70 | KEY_F1 |
| 4 | 0x33 | 3 | | 33 | 0x46 | F | | 60 | 0x71 | KEY_F2 |
| 5 | 0x34 | 4 | | 34 | 0x47 | G | | 61 | 0x72 | KEY_F3 |
| 6 | 0x35 | 5 | | 35 | 0x48 | H | | 62 | 0x73 | KEY_F4 |
| 7 | 0x36 | 6 | | 36 | 0x4A | J | | 63 | 0x74 | KEY_F5 |
| 8 | 0x37 | 7 | | 37 | 0x4B | K | | 64 | 0x75 | KEY_F6 |
| 9 | 0x38 | 8 | | 38 | 0x4C | L | | 65 | 0x76 | KEY_F7 |
| 10 | 0x39 | 9 | | 42 | 0xA0 | KEY_LEFTSHIFT | | 66 | 0x77 | KEY_F8 |
| 11 | 0x30 | 0 | | 44 | 0x5A | Z | | 67 | 0x78 | KEY_F9 |
| 14 | 0x08 | KEY_BACKSPACE | | 45 | 0x58 | X | | 68 | 0x79 | KEY_F10 |
| 15 | 0x09 | KEY_TAB | | 46 | 0x43 | C | | 69 | 0x90 | KEY_NUMLOCK |
| 16 | 0x51 | Q | | 47 | 0x56 | V | | 70 | 0x91 | KEY_SCROLLLOCK |
| 17 | 0x57 | W | | 48 | 0x42 | B | | 71 | 0x67 | KEY_PAD7 |
| 18 | 0x45 | E | | 49 | 0x4E | N | | 72 | 0x68 | KEY_PAD8 |
| 19 | 0x52 | R | | 50 | 0x4D | M | | 73 | 0x69 | KEY_PAD9 |
| 20 | 0x54 | T | | 54 | 0xA1 | KEY_RIGHTSHIFT | | 74 | 0x6D | KEY_PADMINUS |
| 21 | 0x59 | Y | | 55 | 0x6A | KEY_PADSTAR | | 75 | 0x64 | KEY_PAD4 |
| 22 | 0x55 | U | | 56 | 0xA4 | KEY_LEFTALT | | 76 | 0x65 | KEY_PAD5 |
| 23 | 0x49 | I | | | | | | 77 | 0x66 | KEY_PAD6 |
| 24 | 0x4F | O | | | | | | 78 | 0x6B | KEY_PADPLUS |
| 25 | 0x50 | P | | | | | | 79 | 0x61 | KEY_PAD1 |
| 28 | 0x0D | KEY_ENTER | | | | | | 80 | 0x62 | KEY_PAD2 |
| 29 | 0xA2 | KEY_LEFTCTRL | | | | | | 81 | 0x63 | KEY_PAD3 |
| | | | | | | | | 82 | 0x60 | KEY_PAD0 |
| | | | | | | | | 83 | 0x6E | KEY_PADPERIOD |
| | | | | | | | | 87 | 0x7A | KEY_F11 |
| | | | | | | | | 88 | 0x7B | KEY_F12 |
| | | | | | | | | 157 | 0xA3 | KEY_RIGHTCTRL |
| | | | | | | | | 181 | 0x6F | KEY_PADSLASH |
| | | | | | | | | 183 | 0x2C | KEY_SYSRQ |
| | | | | | | | | 184 | 0xA5 | KEY_RIGHTALT |
| | | | | | | | | 199 | 0x24 | KEY_HOME |
| | | | | | | | | 200 | 0x26 | KEY_UPARROW |
| | | | | | | | | 201 | 0x21 | KEY_PAGEUP |
| | | | | | | | | 203 | 0x25 | KEY_LEFTARROW |
| | | | | | | | | 205 | 0x27 | KEY_RIGHTARROW |
| | | | | | | | | 207 | 0x23 | KEY_END |
| | | | | | | | | 208 | 0x28 | KEY_DOWNARROW |
| | | | | | | | | 209 | 0x22 | KEY_PAGEDOWN |
| | | | | | | | | 210 | 0x2D | KEY_INSERT |
| | | | | | | | | 211 | 0x2E | KEY_DELETE |

`KEY_SYSRQ` maps to VK `0x2C` = `VK_SNAPSHOT`, i.e. PrintScreen on Win98+ (it is
*not* `VK_SYSRQ` 0x54). Needs a live check on 9x vs 2000+, but the code is unambiguous.

Also in the name table but never polled: id 0 `NULL`, 12 `KEY_MINUS`, 13 `KEY_EQUAL`,
26 `KEY_LEFTBRACKET`, 27 `KEY_RIGHTBRACKET`, 39 `KEY_SEMICOLON`, 40 `KEY_APOSTROPHE`,
41 `KEY_TICK`, 43 `KEY_BACKSLASH`, 51 `KEY_COMMA`, 52 `KEY_PERIOD`, 53 `KEY_SLASH`,
156 `KEY_PADENTER`, 219 `KEY_LEFTWINDOW`, 220 `KEY_RIGHTWINDOW`, 221
`KEY_KEYBOARDMOUSE`, 255 `' '`.

---

## 2. Edge detection — level vs "just pressed" (CONFIRMED)

**There is no hardware "just pressed" bit anywhere.** `GetKeyboardState` and
`GetDeviceState` are both polled, so the array is level state. The engine synthesises
edges itself, in `FUN_004491C0`, in the emulated PS1 RAM window
`DAT_0052FD00 + 0x10000` (= `0x53FD00`):

| RAM offset | meaning | evidence |
| --- | --- | --- |
| `+0x1000C` | live pad state (u16, bit set = pressed) | `0x4491c0: *(undefined2 *)(DAT_0052fd00 + 0x1000c) = 0;` then OR of the pad bits |
| `+0x1000E` | previous pad state, **masked by the repeat mask** | `0x4491c0: *(undefined2 *)(DAT_0052fd00 + 0x1000e) = *(undefined2 *)(DAT_0052fd00 + 0x1000c); *(ushort *)(DAT_0052fd00 + 0x1000e) = *(ushort *)(DAT_0052fd00 + 0x1000e) & DAT_004b3228;` |
| `+0x1003E` | **just-pressed (edge)** | `0x4491c0: *(ushort *)(DAT_0052fd00 + 0x1003e) = *(ushort *)(DAT_0052fd00 + 0x1000c) & ~*(ushort *)(DAT_0052fd00 + 0x1000e);` |
| `+0x1000A` | mirror of `+0x1003E` (the SDK's `pad.pressed`) | `0x4491c0: *(undefined2 *)(DAT_0052fd00 + 0x1000a) = *(undefined2 *)(DAT_0052fd00 + 0x1003e);` |
| `+0x10010` | second copy the game body reads | `0x4491c0: *(ushort *)(DAT_0052fd00 + 0x10010) = *(ushort *)(DAT_0052fd00 + 0x10010) \| uVar6 & 0xfff;` |

**The edge mask `DAT_004B3228` is cleared every frame** (`0x4491c0: DAT_004b3228 = 0;`)
and is the *auto-repeat* mechanism, not an edge detector. Per held direction key:

```
0x4491c0:  if ((*(byte *)(DAT_0052fd00 + 0x1000c) & 0x40) == 0) { DAT_004b39b2 = '\x02'; }   // Right released
0x4491c0:  else if (DAT_004b39b2 == '\0') { DAT_004b3228 = 0x40; }                              // repeat due
0x4491c0:  else { DAT_004b39b2 = DAT_004b39b2 + -1; }
0x4491c0:  if ((*(byte *)(DAT_0052fd00 + 0x1000c) & 0x80) == 0) { DAT_004b238a = '\x02'; }       // Left
0x4491c0:  if ((*(byte *)(DAT_0052fd00 + 0x1000c) &  4) == 0) { DAT_004b28cc = '\x02'; }       // Down
```

So: `prev = cur & repeat_mask`; `edge = cur & ~prev`. A held key produces one edge on
press, then one edge every 3 frames (counter reloaded to 2 on release, decremented to 0
then re-armed ⇒ period 3). **Up (0x10) has no repeat counter** in this function — it is
handled elsewhere or not at all. UNKNOWN which.

Directional look vectors are also resolved into the state word from the same mask:

```
0x4491c0:  if ((uVar6 & 0x10) != 0) { uVar7 = uVar7 | *(ushort *)(DAT_0052fd00 + 0x10032); }
0x4491c0:  if ((uVar6 & 0x40) != 0) { uVar7 = uVar7 | *(ushort *)(DAT_0052fd00 + 0x10034); }
0x4491c0:  if ((uVar6 & 0x80) != 0) { uVar7 = uVar7 | *(ushort *)(DAT_0052fd00 + 0x1002e); }
0x4491c0:  *(ushort *)(DAT_0052fd00 + 0x1000c) = uVar6 & 0xff00 | uVar7;
```

Analog stick adds the four high bits as edges too:
`0x4491c0: *(ushort *)(DAT_0052fd00 + 0x1000a) = … | 0x8000;` (Left),
`… | 0x2000;` (Right), `… | 0x4000;` (Up), `… | 0x1000;` (Down), with the count in
`+0x10012` / `+0x10014` (`= 0x7f` / `= 0xff80` magnitudes).

The menu path uses a **per-frame level** 3-bit mask instead:

```
0x4023e0:  DAT_004b18d0 = 0;
0x4023e0:  if (DAT_009ca8dc != '\0') { DAT_004b18d0 = DAT_004b18d0 | 1; }   // Enter  (id 28)
0x4023e0:  if (DAT_009ca8c1 != '\0') { DAT_004b18d0 = DAT_004b18d0 | 2; }   // Esc    (id 1)
0x4023e0:  if (DAT_009ca8f9 != '\0') { DAT_004b18d0 = DAT_004b18d0 | 4; }   // Space  (id 57)
```
These are *held* bits (no edge), and `DAT_004b18d0` is zeroed at the top of the same
function, so it is per-frame level.

A separate "button changed since last frame" byte is produced when the pad's status
byte changes, used for one-shot sounds/animation:

```
0x4023e0:  if (bVar3 != *(byte *)(iVar2 + 2)) { *(undefined1 *)(iVar2 + 1) = 0x41; }   // pad+1 = 0x41 (analog/other type)
0x403010:  puVar2[1] = 0x73;                                                           // pad+1 = 0x73 (analog mode)
```

**Practical note for a rewrite:** the whole edge layer is 4 bytes of emulated RAM plus
one u16 mask. A faithful port must reproduce the *repeat mask* logic or menu navigation
will not auto-repeat, and must treat "just pressed" as `cur & ~prev` with `prev`
deliberately cleared each frame for non-repeating bits.

---

## 3. Gamepad — **YES** (CONFIRMED)

There is real gamepad support, and it is not optional: DirectInput is initialised at
startup on every run and only falls back to the keyboard if the COM device fails.

**No joystick API and no DirectInput *imports*.** The full import list contains no
`joyGetPos`, no `GetXAxis`, no `joy*` at all (grep over `tools/symbols.csv`
`IMPORT|` rows). DirectInput is used through **COM**, so `dinput.dll` is loaded by
`CoCreateInstance`, not by an import.

```
0x40dd40:  *(undefined4 *)(puVar5 + -0xc) = 1;
0x40dd40:  *(undefined4 *)(puVar5 + -0x8) = DAT_004b1ce8;
0x40dd40:  *(undefined4 *)(puVar5 + -4)   = 400;
0x40dd40:  iVar3 = FUN_004025b0();                       // FUN_004025b0(1, hwnd?, 400)
0x4477a0:  iVar2 = FUN_004025b0(1,DAT_004b1ce8,DAT_004b1cec);
0x4477a0:  if (iVar2 != 1) { FUN_004025b0(0,0,0); }
0x4025b0:  if (param_1 != 1) { DAT_009ca9c4 = 0; DAT_009ca9c0 = FUN_004028a0; return 1; }
0x4025b0:  DAT_009ca9c4 = 1; DAT_009ca9c0 = (code *)&LAB_00402810; FUN_00402610();
0x4025b0:  if (DAT_004b18c8 == 0) { DAT_009ca9c0 = FUN_004028a0; }
```

`DAT_009CA9C0` is the per-frame input poller (keyboard version at `0x4028a0`); the
DirectInput version is `LAB_00402810`, **whose body is not in the decompile dump** (the
exported `bugs_decompiled.c` only covers functions with headers). UNKNOWN what it does;
it is only reached when a DI device exists.

COM setup (`0x402610`):

```
0x402610:  HVar2 = CoInitialize(NULL);
0x402610:  HVar2 = CoCreateInstance(&DAT_0045ccb8, NULL, 1 /*CLSCTX_INPROC_SERVER*/, &DAT_0045ccc8, &DAT_004b18c0);
0x402610:  /* device GUID built on the stack: 0x6f1d2b61 / 0x11cfd5a0 / 0x4544c7bf / 0x5453 */
0x402610:  pcVar1 = *(code **)(iVar3 + 0xc);  iVar3 = (*pcVar1)(&GUID, &DAT_004b18c8, NULL);   // create device -> DAT_004b18c8
0x402610:  pcVar1 = *(code **)(*DAT_004b18c8 + 0x2c); (*pcVar1)(&DAT_0044fc00);                  // SetDataFormat
0x402610:  pcVar1 = *(code **)(iVar3 + 0x34); (*pcVar1)(DAT_004b1cec, 6);                       // SetCooperativeLevel(hwnd, 6)
0x402610:  pcVar1 = *(code **)(*DAT_004b18c8 + 0x1c); iVar3 = (*pcVar1)();                      // Acquire
0x402610:  DAT_009ca8a0 = (uint)(-1 < iVar3);
0x402610:  pcVar1 = *(code **)(iVar3 + 0x10); (*pcVar1)(4, &LAB_00402000, 1, 0);                // EnumDevices(4, cb, ref, 1)
```
GUIDs (read from the PE image bytes at those addresses):

| addr | GUID | identification |
| --- | --- | --- |
| `0x45CC98` | `5944E682-C92E-11CF-BFC7-444553540000` | DirectInput 7 IID (**PLAUSIBLE**) |
| `0x45CCA8` | `6F1D2B61-D5A0-11CF-BFC7-444553540000` | the device GUID passed to `CreateDevice` — a generic pad (**PLAUSIBLE**) |
| `0x45CCB8` | `25E609E0-B259-11CF-BFC7-444553540000` | `rclsid` ⇒ **CLSID_DirectInput** (DX6/DX7, not DirectInput8) (**PLAUSIBLE**) |
| `0x45CCC8` | `89521360-AA8A-11CF-BFC7-444553540000` | `riid` ⇒ **IID_IDirectInputW** (**PLAUSIBLE**) |
| `0x45CCD8` | `3BBA0080-2421-11CF-A31A-00AA00B93356` | IID_IDirectInputDevice8A, present but unused by this path |

Vtable-slot mapping is offset-consistent only for the polled device (there is exactly
one assignment that makes `GetDeviceState`'s buffer layout line up):

```
0x402180:  iVar3 = (**(code **)(*DAT_004b18c4 + 100))();                    // vtbl[25] = Poll
0x402180:  if ((iVar3 == -0x7ff8ffe2) || (iVar3 == -0x7ff8fff4)) { (**(code **)(*DAT_004b18c4 + 0x1c))(); … }  // vtbl[7] = Acquire
0x402180:  pcVar1 = *(code **)(iVar3 + 0x24);                               // vtbl[9] = GetDeviceState
0x402180:  ppiVar4[-2] = (int *)0x50;                                       // cbSize = 80 = sizeof DIDEVICESTATE (2 axes + 32 byte buttons)
0x402180:  *param_1 = *ppiVar4;  *param_2 = ppiVar4[1];                     // lX at +0, lY at +4
0x402180:  do { if (*(char *)((int)ppiVar4 + iVar3 + 0x30) != '\0') { *param_3 |= 1 << (iVar3 & 0x1f); } } while (iVar3 < 0x20);  // 32 buttons at +0x30
```

Analog handling in `0x403010` — axes are treated as **0..255, centre 0x80**, deadzone
0x10..0xE0, and each axis is nudged +0x80 and clamped every frame:

```
0x403010:  iVar4 = FUN_00402180(&DAT_004b1860,&DAT_004b1864,&DAT_004b1878);
0x403010:  DAT_004b1860 = DAT_004b1860 + 0x80;  if (0xff < DAT_004b1860) { DAT_004b1860 = 0xff; }
0x403010:  DAT_004b1864 = DAT_004b1864 + 0x80;  if (0xff < DAT_004b1864) { DAT_004b1864 = 0xff; }
0x403010:  if (DAT_004b1864 < 0x10) { puVar2[2] = bVar3 | 0x10; }   // Up
0x403010:  if (0xe0 < DAT_004b1860) { puVar2[2] = puVar2[2] | 0x20; }   // Right
0x403010:  if (0xe0 < DAT_004b1864) { puVar2[2] = puVar2[2] | 0x40; }   // Down
0x403010:  if (DAT_004b1860 < 0x10) { puVar2[2] = puVar2[2] | 0x80; }   // Left
```

Teardown: `0x402790` and `0x402610` call `Unacquire` (vtbl+0x20), `Release` (vtbl+8)
on `DAT_004b18c4` / `DAT_004b18c8` / `DAT_004b18c0`, then `CoUninitialize()`.

**Needs runtime confirmation:** which physical devices the enumerate callback at
`LAB_00402000` accepts (the `dwDevType=4` argument suggests mouse-class devices are
enumerated, which is odd for a pad); whether `dinput.dll` is present on the target;
whether two devices (keyboard-class and pad) are both created in practice.

---

## 4. `..\bin\config.pc` — 128-byte binary (CONFIRMED)

Path: `0x4676B8` = `"..\\bin\\config.pc"` (17 bytes incl. NUL).
Modes: read `0x45F3B4` = `"rb"`, write `0x4676B4` = `"wb+"`.

It is **not** a text file and has no `FirstTime=`/`Language=` keys. It is a flat
128-byte blob read and written whole:

```
0x409cc0:  iVar1 = FUN_00450740("..\bin\config.pc","rb");
0x409cc0:  FUN_004501d0(iVar1,0,2);  iVar2 = FUN_00450270(iVar1);  FUN_004501d0(iVar1,0,0);   // size check
0x409cc0:  if (iVar2 == 0x80) { FUN_004508f0(&DAT_009ca820,0x80,1,iVar1); FUN_00450500(iVar1);
0x409cc0:                    if (DAT_009ca820 == 0x10) { return; } }  else { FUN_00450500(iVar1); }
0x409cc0:  FUN_00409a90(0xff,&DAT_009ca820);  FUN_00409a90(0xff,&DAT_009ca7a0);
0x409cc0:  iVar1 = FUN_00405760("..\bin\config.pc","wb+");  FUN_004505c0(&DAT_009ca820,0x80,1,iVar1);
0x409a10:  iVar1 = FUN_00405760("..\bin\config.pc","wb+");  FUN_004505c0(&DAT_009ca820,0x80,1,iVar1);   // save
0x409c80:  /* 0x20 dwords: DAT_009ca7a0 = DAT_009ca820  -- snapshot     */
0x409ca0:  /* 0x20 dwords: DAT_009ca820 = DAT_009ca7a0  -- restore      */
```

**Load semantics (important):** if the file is exactly 0x80 bytes **and** its first
u32 is `0x10`, the blob is kept verbatim and the function returns. Otherwise the block
is re-defaulted by `FUN_00409a90(0xff, …)` and the file is rewritten. The shipped
`config.pc` starts `10 00 00 00` followed by zeros, so **it is accepted as-is and no
defaults are ever applied** — every field except the version word stays 0 until the
options menu writes it. (RE_NOTES' claim that the shipped file is "the default
template" is wrong for this reason.)

`FUN_00409A90(byte mask, u32 *p)` is a per-field reset routine; `p[0]=0x10` is
unconditional, the rest is gated by mask bits. `load_config` calls it with `0xff`, and
`FUN_0040E1D0` (options screen cancel/apply) uses `FUN_00409c80` / `FUN_00409ca0` to
swap the live block with the 0x009CA7A0 backup. Both blocks are 0x80 bytes and adjacent
(`0x009CA7A0..0x009CA81F` backup, `0x009CA820..0x009CA89F` live).

### 4.1 Byte-exact layout

`p` = block base. Offsets derived from `param_2[n]` = `p + 4n` and
`*(undefined1 *)((int)p + k)` = `p + k`, all read straight out of `0x409a90`, then
cross-checked against every use site in the binary.

| off | size | type | meaning | default (`FUN_00409a90`) | proof / use |
| --- | --- | --- | --- | --- | --- |
| 0x00 | 4 | u32 | version / magic — must be `0x10` or the file is rewritten | `0x10` | `0x409a90: *param_2 = 0x10;` `0x409cc0: if (DAT_009ca820 == 0x10) { return; }` |
| 0x04 | 4 | u32 | renderer: `0` = software 8-bit/palette, `1` = software 16/24-bit, `2` = OpenGL | `0`/`1` from CPU+OpenGL probe, `2` if OpenGL; **note the runtime fallback in `0x40dd40:` `if (DAT_009ca824 == 2) { DAT_009ca824 = (uint)(299 < DAT_004b1de4); … }`** | `0x409a90: if (iVar2 == 0) { if (DAT_004b1de4 < 300) { param_2[1] = 0; } else { param_2[1] = 1; } } else { param_2[1] = 2; }` ; `0x408f70: DAT_009ca824 = 2;` |
| 0x08 | 4 | u32 | **language index** 0..5 (0 unknown, 1 FR, 2 DE, 3 IT, 4 EN, 5 NL) | from `GetSystemDefaultLangID()` | `0x409a90: case 7: param_2[2] = 2; case 0xc: param_2[2] = 1; case 10: param_2[2] = 3; case 0x10: param_2[2] = 4; case 0x13: param_2[2] = 5;` `0x405950: switch(_DAT_009ca828) { case 1: PTR_DAT_0045f344 = &DAT_0045f2d0; … }` |
| 0x0C | 4 | u32 | OpenGL probe result cached | `FUN_0040e050()` | `0x409a90: uVar3 = FUN_0040e050(); param_2[3] = uVar3;` `0x409990: if (DAT_009ca82c == 2) {…}` |
| 0x10 | 4 | u32 | screen width | `0x200` (512) | `0x409a90: param_2[4] = 0x200;` `0x408f70: DAT_009ca830 = FUN_004508e0(pcVar2 + 2);` (`/x`) |
| 0x14 | 4 | u32 | screen height | `0x180` (384) | `0x409a90: param_2[5] = 0x180;` `0x40e1d0: DAT_009ca830 = 0x200; DAT_009ca834 = 0x180;` |
| 0x18 | 4 | u32 | fullscreen flag (1 = fullscreen) | `1` | `0x409a90: param_2[6] = 1;` `0x408f70: DAT_009ca838 = 1;` (`/FULL`) / `= 0` (`/WIN`) |
| 0x1C | 4 | u32 | colour-depth index 0..2, multiplies the byte stride by `(x*9)/2` | `2` | `0x409a90: param_2[7] = 2;` `0x40cc80: if ((-1 < DAT_009ca83c) && (DAT_009ca83c < 3)) { param_1 = param_1 + ((DAT_009ca83c * 9) / 2) * (uint)DAT_004b38a0; …` |
| 0x20 | 4 | u32 | unknown, never referenced by name | `0` | `0x409a90: param_2[8] = 0;` |
| 0x24 | 4 | float | unknown, never referenced by name | `1.0f` (`0x3ff00000`) | `0x409a90: param_2[9] = 0x3ff00000;` |
| 0x28 | 4 | float/0 | part of the display/gamma group | `0` | `0x409a90: param_2[10] = 0;` |
| 0x2C | 4 | float | gamma-ramp parameter | `1.0f` | `0x409a90: param_2[0xb] = 0x3ff00000;` |
| 0x30 | 4 | u32 | **volume A** (percent) | `100` | `0x409a90: if ((param_1 & 0x10) != 0) { param_2[0xc] = 100; }` `0x41edb0: … * DAT_009ca850;` |
| 0x34 | 4 | u32 | **volume B** (percent, 100 = normal) | `100` | `0x409a90: param_2[0xd] = 100;` `0x41d5f0: (DAT_009ca854 + -100) * 100;` |
| 0x38 | 4 | u32 | **joystick enabled** | `0` | `0x409a90: param_2[0xe] = 0;` `0x44d100: if ((DAT_009ca85c._3_1_ != 0) && (DAT_009ca858 != 0)) {…}` |
| 0x3C | 1 | u8 | joystick button index → Triangle | `0` | `0x409a90: *(undefined1 *)(param_2 + 0xf) = 0;` `0x403010: if ((uVar1 & 1 << ((byte)DAT_009ca85c & 0x1f)) != 0) { puVar2[3] = 0x10; }` |
| 0x3D | 1 | u8 | joystick button → Circle | `1` | `0x403010: … DAT_009ca85c._1_1_ … puVar2[3] = … \| 0x20;` |
| 0x3E | 1 | u8 | joystick button → Square | `2` | `0x403010: … DAT_009ca85c._2_1_ … \| 0x40;` |
| 0x3F | 1 | u8 | joystick button → Cross | `3` | `0x403010: … DAT_009ca85c._3_1_ … \| 0x80;` |
| 0x40 | 1 | u8 | joystick button → L2 | `4` | `0x403010: … DAT_009ca860 & 0x1f … DAT_004b1878 \| 0x100;` |
| 0x41 | 1 | u8 | joystick button → R2 | `5` | `0x403010: … DAT_009ca860._1_1_ … \| 0x200;` |
| 0x42 | 1 | u8 | joystick button → L1 | `6` | `0x403010: … DAT_009ca860._2_1_ … puVar2[3] \| 4;` |
| 0x43 | 1 | u8 | joystick button → R1 | `7` | `0x403010: … DAT_009ca860._3_1_ … puVar2[3] \| 8;` |
| 0x44 | 1 | u8 | joystick button → Select | `8` | `0x403010: … DAT_009ca864 & 0x1f … puVar2[3] \| 1;` |
| 0x45 | 1 | u8 | joystick button → Start | `9` | `0x403010: … DAT_009ca865 & 0x1f … puVar2[3] \| 2;` |
| 0x46 | 1 | u8 | **key ID** → Up | `0xC8` (200, `KEY_UPARROW`) | `0x409a90: *(undefined1 *)((int)param_2 + 0x46) = 200;` `0x4023e0: if ((&DAT_009ca8c0)[DAT_009ca866] != '\0') { … \| 0x10; }` |
| 0x47 | 1 | u8 | key ID → Down | `0xD0` (208, `KEY_DOWNARROW`) | `0x4023e0: … [DAT_009ca867] … \| 0x40;` |
| 0x48 | 1 | u8 | key ID → Right | `0xCD` (205) | `0x4023e0: … [DAT_009ca868 & 0xff] … \| 0x20;` |
| 0x49 | 1 | u8 | key ID → Left | `0xCB` (203) | `0x4023e0: … [DAT_009ca868 >> 8 & 0xff] … \| 0x80;` |
| 0x4A | 1 | u8 | key ID → L2 | `0x10` (16, `Q`) | `0x4023e0: … [DAT_009ca868 >> 0x10 & 0xff] … \| 1;` |
| 0x4B | 1 | u8 | key ID → R2 | `0x11` (17, `W`) | `0x4023e0: … [DAT_009ca868 >> 0x18] … \| 2;` |
| 0x4C | 1 | u8 | key ID → L1 | `0x12` (18, `E`) | `0x4023e0: … [DAT_009ca86c & 0xff] … \| 4;` |
| 0x4D | 1 | u8 | key ID → R1 | `0x13` (19, `R`) | `0x4023e0: … [DAT_009ca86c >> 8 & 0xff] … \| 8;` |
| 0x4E | 1 | u8 | key ID → Triangle | `0x1E` (30, `A`) | `0x4023e0: … [DAT_009ca86c >> 0x10 & 0xff] … \| 0x10;` |
| 0x4F | 1 | u8 | key ID → Circle | `0x1F` (31, `S`) | `0x4023e0: … [DAT_009ca86c >> 0x18] … \| 0x20;` |
| 0x50 | 1 | u8 | key ID → Cross | `0x20` (32, `D`) | `0x4023e0: … [DAT_009ca870 & 0xff] … \| 0x40;` |
| 0x51 | 1 | u8 | key ID → Square | `0x21` (33, `F`) | `0x4023e0: … [DAT_009ca870 >> 8 & 0xff] … \| 0x80;` |
| 0x52 | 1 | u8 | **unused** duplicate (TAB) | `0x0F` (15) | written by `0x409a90`, read nowhere |
| 0x53 | 1 | u8 | **unused** duplicate (ENTER) | `0x1C` (28) | written by `0x409a90`, read nowhere |
| 0x54 | 1 | u8 | key ID → Select | `0x0F` (15, `KEY_TAB`) | `0x4023e0: … [DAT_009ca874 & 0xff] … \| 1;` |
| 0x55 | 1 | u8 | key ID → Start | `0x1C` (28, `KEY_ENTER`) | `0x4023e0: … [DAT_009ca874 >> 8 & 0xff] … \| 8;` |
| 0x56 | 1 | u8 | display group, value `0x10` | `0x10` | `0x409a90: *(undefined1 *)((int)param_2 + 0x56) = 0x10;` |
| 0x57 | 1 | u8 | display group, value `1` | `1` | `0x409a90: *(undefined1 *)((int)param_2 + 0x57) = 1;` |
| 0x58 | 4 | 0/float | display/gamma group | `0` | `0x409a90: param_2[0x16] = 0;` |
| 0x5C | 4 | 0/float | display/gamma group | `0` | `0x409a90: param_2[0x17] = 0;` |
| 0x60 | 4 | 0/float | display/gamma group | `0` | `0x409a90: param_2[0x18] = 0;` |
| 0x64 | 4 | float | display/gamma group | `1.0f` | `0x409a90: param_2[0x19] = 0x3ff00000;` |
| 0x68 | 4 | 0/float | display/gamma group | `0` | `0x409a90: param_2[0x1a] = 0;` |
| 0x6C | 4 | float | display/gamma group | `1.0f` | `0x409a90: param_2[0x1b] = 0x3ff00000;` |
| 0x70 | 4 | float | palette/gamma ramp parameter | `0` | `0x409a90: param_2[0x1c] = 0;` `0x420d10: FUN_00424ef0((double)(int)DAT_009ca898,DAT_009ca890,DAT_009ca894);` |
| 0x74 | 4 | float | palette/gamma ramp parameter | `1.0f` | same line |
| 0x78 | 1 | u8 | palette/gamma ramp parameter | `0` | `0x409a90: *(undefined1 *)(param_2 + 0x1e) = 0;` |
| 0x79–0x7F | 7 | — | **padding, never written, never read** | left as-is | falls out of the 0x80 size minus the last written byte 0x78 |

### 4.2 The "palette table"

`config.pc` contains **no palette data**. What RE_NOTES calls "a palette table" is the
256-byte **gamma/level ramp the game builds at runtime** into `DAT_004D5D40`:

```
0x424ef0:  do { iVar1 = __ftol((double)((longdouble)local_4 * lVar2 + lVar3));
0x424ef0:        if (0xff < iVar1) { iVar1 = 0xff; }  if (iVar1 < 0) { iVar1 = 0; }
0x424ef0:        (&DAT_004d5d40)[local_4] = (char)iVar1;  local_4 = local_4 + 1; } while (local_4 < 0x100);
0x420d10:  local_8 = (float)(int)DAT_009ca898;  FUN_00424ef0((double)(int)local_8,DAT_009ca890,DAT_009ca894);
```
i.e. `ramp[i] = clamp(round(i * config[0x70] + config[0x78]), 0, 255)` with the third
argument (`config[0x74]`) also delivered on the x87 stack. `0x447b80:` rebuilds it on
every mode change. **Which of 0x70/0x74/0x78 is the slope and which is the offset is
UNKNOWN** — the decompiler shows `FUN_00424ef0` with 2 parameters while every call
site passes 3, so the register/stack split is ambiguous. A default of `0.70=0.0,
0x74=1.0f, 0.78=0` only makes sense if 0x74 is the slope (identity ramp), which is
PLAUSIBLE but not proven.

The 0x56/0x57 byte pair (`0x10`, `1`) is the only other display-group datum and has no
identified consumer. UNKNOWN.

---

## 5. `..\bin\bugs.ini` and the command line

### 5.1 bugs.ini (CONFIRMED)

Path `0x467704` = `"..\\bin\\bugs.ini"`, opened with mode `0x467700` = `"rt"`.
It is a **text file**. `FUN_00409E30` searches line by line for two keys:

```
0x409e30:  iVar1 = FUN_00405760("..\bin\bugs.ini","rt");  if (iVar1 == 0) { return 0; }
0x409e30:  pcVar3 = _strstr(local_150,s_Language_004676f4);     // "Language"
0x409e30:  FUN_00450d50(local_150,s_Language__i_004676e8,local_154);   // sscanf(buf,"Language=%i",buf2)
0x409e30:  pcVar3 = _strstr(local_150,s_FirstTime_004676dc);    // "FirstTime"
0x409e30:  FUN_00450d50(local_150,s_FirstTime__i_004676cc,local_154); // sscanf(buf,"FirstTime=%i",buf2)
0x409e30:  DAT_004b1a31 = local_154[0];
```
Strings in the image: `0x4676CC` `"FirstTime=%i"`, `0x4676DC` `"FirstTime"`,
`0x4676E8` `"Language=%i"`, `0x4676F4` `"Language"`.

**Finding: the `Language` key is dead.** Both `sscanf` calls write the *same*
4-byte `local_154[4]`, the second one overwrites the first, and only byte 0 of the
result is used (`DAT_004b1a31`). Language is really taken from `config.pc` offset 0x08.
PLAUSIBLE-to-CONFIRMED that no `Language=` line in bugs.ini has any effect.

`FUN_00409F60` rewrites the flag in place after the first run:

```
0x409f60:  /* read the whole file (0x400 = 1024 bytes) into a stack buffer */
0x409f60:  pcVar1 = _strstr(&stack0x00001000,s_FirstTime__00467714);   // "FirstTime="
0x409f60:  if (pcVar1 != (char *)0x0) { pcVar1[10] = (DAT_004b1a31 != '\0') + '0'; }
0x409f60:  /* write the 1024 bytes back  */
```
It patches the single character 10 bytes past `"FirstTime="` — i.e. the digit after
`FirstTime=` (offset 10 = 8 + "FirstTime=" is 10 chars). CONFIRMED.

**No `CheckGDI` key and no `DLL` key exist in bugs.ini.** A scan of the whole
0x400000–0x9DA000 image for `CheckGDI`/`checkgdi` returns nothing; the only
`dll`-adjacent strings are `/DLL:` (a command-line flag, §5.2) and `opengl32.dll`.
RE_NOTES is wrong on this point.

### 5.2 Command line (CONFIRMED for the parse; `0x408f70`)

`GetCommandLineA()` is scanned with `_strstr`, case-insensitively by trying both a
lower- and an upper-case spelling of each token. Both spellings are in the image
contiguously at `0x46754x`–`0x4676b4`. Every flag that is actually implemented:

| flag | effect | evidence |
| --- | --- | --- |
| `/B<cc>` | copies the 2 chars after the slash into a 3-byte buffer at `0x4B1A38`, NUL-terminates (`DAT_004b1a3a = 0`) | `0x408f70: pcVar2 = _strstr(_Str,"/B"); … _strncpy(&DAT_004b1a38,pcVar2 + 2,2); DAT_004b1a3a = 0;` |
| `/P:<token>` | copies the following token (up to a space) into `DAT_007C9360`; sets `DAT_004B1D04 = 2` | `0x408f70: pcVar2 = _strstr(_Str,"/P:"); … DAT_004b1d04 = 2;` |
| `/R:<token>` | same buffer; `DAT_004B1D04 = 1` | `0x408f70: … DAT_004b1d04 = 1;` |
| `/X<n>` | screen width ← `atoi` | `0x408f70: DAT_009ca830 = FUN_004508e0(pcVar2 + 2);` |
| `/Y<n>` | screen height ← `atoi` | `0x408f70: DAT_009ca834 = FUN_004508e0(pcVar2 + 2);` |
| `/FULL` | fullscreen (config+0x18 = 1) | `0x408f70: DAT_009ca838 = 1;` |
| `/WIN` | windowed (config+0x18 = 0) | `0x408f70: DAT_009ca838 = 0;` |
| `/OGL` or `/OPENGL` | renderer = 2 | `0x408f70: DAT_009ca824 = 2;` |
| `/SOFT` | renderer = 1 | `0x408f70: DAT_009ca824 = 1;` |
| `/SOFT8` | renderer = 0 | `0x408f70: DAT_009ca824 = 0;` |
| `/SOFTPAL` | renderer = 0 | `0x408f70: DAT_009ca824 = 0;` |
| `/SOFTRGB` | renderer = 1 | `0x408f70: DAT_009ca824 = 1;` |
| `/SOFT16` | renderer = 1 | `0x408f70: DAT_009ca824 = 1;` |
| `/SOFT24` | renderer = 1 | `0x408f70: DAT_009ca824 = 1;` |
| `/SKIP_INTRO` | clears `DAT_0045F2A8` (an "intro seen" byte) | `0x408f70: DAT_0045f2a8 = 0;` |
| `/NO_SKIP` | sets `DAT_004B1900 = 1`, clears `_DAT_0045F2A0`; **absent** the flag sets `DAT_004B1900 = 0` | `0x408f70: if (no NO_SKIP found) { DAT_004b1900 = 0; } else { _DAT_0045f2a0 = 0; DAT_004b1900 = 1; }` |
| `/NO_SYNC` | clears `DAT_0045F2A4` | `0x408f70: DAT_0045f2a4 = 0;` |
| `/CONS` | sets `_DAT_004B18E8 = 1` | `0x408f70: _DAT_004b18e8 = 1;` |
| `/FNTP` | sets `_DAT_004B1CE4 = 1` | `0x408f70: _DAT_004b1ce4 = 1;` |
| `/DLL:<name>` | **overrides the OpenGL driver module name** (default `"opengl32.dll"` at `0x4673F0`), token ends at space, `/` or NUL | `0x408f70: _strncpy(s_opengl32_dll_004673f0,pcVar2,in_ECX); s_opengl32_dll_004673f0[in_ECX] = '\0';` and `0x408f70:` `_strncpy(s_opengl32_dll_004673f0,pcVar2,in_ECX);` and the consumer `0x40e050:` `DAT_009ca724 = LoadLibraryA(*(LPCSTR *)(puVar4 + -4));` with `*(char **)(puVar4 + -4) = s_opengl32_dll_004673f0;` |
| `/PAL:<path>` | prepends `..\bze\` to the given name and appends it to the palette path, sets the palette index to `-1` | `0x408f70: _DAT_007c9120 = "..\\bze\\"; … DAT_004b1ce0 = 0xffffffff;` |
| `/PAL` or `/pal` | palette index ← `atoi(DAT_004b1a38)` (i.e. of the `/B` value) | `0x408f70: DAT_004b1ce0 = FUN_004508e0(&DAT_004b1a38);` |
| `/?` | palette index ← `0xffffff9c` (−100) | `0x408f70: DAT_004b1ce0 = 0xffffff9c;` |

Flags that exist as strings but whose *effects* are not implemented: **none found** —
every one of the 21 tokens above has a `DAT_` write. `/P:` and `/R:` only fill a buffer
plus a mode byte consumed by the movie/audio streamer (`0x4491c0:` `DAT_004b1d04`
branches copy pad bytes into a stream). `/CONS` sets `_DAT_004B18E8 = 1` and `/FNTP` sets `_DAT_004B1CE4 = 1`; a grep of the
whole decompile finds exactly **one** reference to each — the store itself — so both are
**set-but-never-read (dead) flags as far as this dump shows**. CONFIRMED for "no
reader in the dump"; whether the shipped binary reads them from a function the exporter
skipped is UNKNOWN (same caveat as `LAB_00402810`).

Ordering hazard: the renderer flags are tested in the order `/OGL`,`/OPENGL`, `/SOFT`,
`/SOFT8`, `/SOFTPAL`, `/SOFTRGB`,`/SOFT16`,`/SOFT24`, so **the last matching one in that
list wins**, not the first on the command line.

---

## 6. The save files

Two files, **two different sizes, and the sizes in RE_NOTES are swapped**.

| file | size | written by | read by | block |
| --- | --- | --- | --- | --- |
| `..\bin\Savegame%d.dat` | **0x140 = 320 bytes** | `0x4074f0` | `0x407190` | emulated PS1 RAM `DAT_0052FD00+0x10000` = `0x53FD00` |
| `..\bin\Savedata.dat` | **0x168 = 360 bytes** | `0x4074f0` | `0x4076f0` | live globals `DAT_004B28E0` |

Paths: `0x45F3B8` = `"..\\bin\\Savegame%d.dat"` (sprintf'd with the slot number),
`0x45F3D0` = `"..\\bin\\Savedata.dat"`. Write mode `0x45F3E4` = `"w+b"`,
read mode `0x45F3B4` = `"rb"`, create mode `0x45F3E8` = `"a"`.

**Nothing is compressed. Both files are flat uncompressed blobs.** No zlib/LZ
imports exist (import list has no compression API) and both routines are a single
`fread`/`fwrite` of a constant size.

Slot number: 1..6, taken from `byte[0xDF]` of the block itself.

```
0x4074f0:  FUN_00450420(local_20,"..\bin\Savegame%d.dat",*(undefined1 *)(DAT_0052fd00 + 0x100df));
0x4074f0:  iVar3 = FUN_00405760(local_20,"w+b");  FUN_00450a30(iVar3);
0x4074f0:  iVar5 = FUN_004505c0(DAT_0052fd00 + 0x10000,0x140,1,iVar3);  FUN_00450500(iVar3);
0x407190:  FUN_00450420(local_160,"..\bin\Savegame%d.dat",*(undefined1 *)(DAT_0052fd00 + 0x100df));
0x407190:  iVar2 = FUN_00405760(local_160,"rb");  iVar3 = FUN_004508f0(local_140,0x140,1,iVar2);
0x407190:  for (iVar2 = 0x50; iVar2 != 0; iVar2 = iVar2 + -1) { *puVar5 = *puVar4; … }   // 0x50 dwords = 0x140
0x4074f0:  iVar3 = FUN_00405760("..\bin\Savedata.dat","w+b");
0x4074f0:  iVar5 = FUN_004505c0(&DAT_004b28e0,0x168,1,iVar3);
0x4076f0:  iVar1 = FUN_00405760("..\bin\Savedata.dat","rb");  iVar3 = FUN_004508f0(&local_168,0x168,1,iVar1);
0x4076f0:  for (iVar2 = 0x5a; iVar2 != 0; iVar2 = iVar2 + -1) { *puVar5 = *puVar4; … }   // 0x5a dwords = 0x168
```

### 6.1 `Savegame%d.dat` — 320 bytes (`0x53FD00 + n`)

Cross-checked load/save agree: **the save writes 0x140 bytes from the block; the load
reads 0x140 bytes into the block; nothing else is added or stripped.**

| off | size | meaning | default / evidence |
| --- | --- | --- | --- |
| 0x00 | 4 | level-progress / trigger marker, **0 = "empty save"** | written `0x47` by a level script (`0x447b80:` `*(undefined4 *)(iVar2 + 0x10000) = 0x47; DAT_004b39bc = 1;`); read as the empty test at `0x4076f0:` `if (*(int *)(iVar1 + 0x10000) == 0) {…}` and `0x407190:` `else if (*(int *)(DAT_0052fd00 + 0x10000) == 0) { *(undefined1 *)(DAT_0052fd00 + 0x1004e) = 0x38; }` |
| 0x04 | 4 | additive byte-sum checksum over the whole 0x140 block | `0x4074f0: uVar2 = FUN_0042e5e0(DAT_0052fd00 + 0x10000,0x140); *(undefined4 *)(DAT_0052fd00 + 0x10004) = uVar2;` with `0x42e5e0: iVar1 = iVar1 + *param_1; param_1 = param_1 + 1;` |
| 0x08 | 2 | unknown | no other reference |
| 0x0A | 2 | pad edge mirror (`pressed`) — **saved and restored** | §2 |
| 0x0C | 2 | live pad state — **saved and restored** | §2 |
| 0x0E | 2 | previous pad state — **saved and restored** | §2 |
| 0x10 | 2 | pad state word for the game body — **saved and restored** | §2 |
| 0x12 | 2 | analog-left magnitude (`0x7f` / `0xff80`) | `0x4491c0: *(undefined2 *)(DAT_0052fd00 + 0x10012) = 0x7f;` |
| 0x14 | 2 | analog-up magnitude | `0x4491c0: *(undefined2 *)(DAT_0052fd00 + 0x10014) = 0x7f;` |
| 0x16 | 2 | camera X | `0x407190: *(undefined2 *)(DAT_0052fd00 + 0x10016) = 0;` (fresh) |
| 0x18 | 2 | camera X limit hi (`0xff`) | same fresh-save block |
| 0x1A | 2 | camera X target (`0x7f` = centre) — compared against the live stick | `0x4491c0: sVar1 = *(short *)(DAT_0052fd00 + 0x1001a);` |
| 0x1C | 2 | 0 on fresh | |
| 0x1E | 2 | `0xff` on fresh | |
| 0x20 | 2 | camera Y target (`0x7f`) — compared against the live stick | `0x4491c0: sVar1 = *(short *)(DAT_0052fd00 + 0x10020);` |
| 0x22,0x24 | 2+2 | 0 on fresh | |
| 0x26…0x2D | 8 | player/state u16s | |
| 0x2E…0x3D | 16 | **8 × u16 directional look vectors** | `0x4491c0:` ORed in per direction bit (`0x1002e`,`0x10030`,`0x10032`,`0x10034`,`0x10036`,`0x10038`,`0x1003a`,`0x1003c`) |
| 0x3E | 2 | **just-pressed mask** — saved and restored | §2 |
| 0x40…0x13F | 256 | **per-index progress table**, one byte per level/room index | `0x407190: do { *(undefined1 *)(iVar2 + 0x10040 + DAT_0052fd00) = 0; … } while (iVar3 < 0x100);` `0x44d100: uVar16 = *(uint)*(byte *)(uVar16 + 0x10040 + DAT_0052fd00);` |
| 0x41 | 1 | **lives / health** (6) | `0x407190: *(undefined1 *)(DAT_0052fd00 + 0x10041) = 6;` `0x437d90: *(char *)(DAT_0052fd00 + 0x10041) = *(char *)(DAT_0052fd00 + 0x10041) - *(char *)(param_1 + 0x1e);` |
| 0x42 | 1 | spare lives / continues (6) | `0x407190: *(undefined1 *)(DAT_0052fd00 + 0x10042) = 6;` |
| 0x43 | 1 | HUD counter (99) | `0x407190:` fresh block writes 0x10041/0x10042/0x1004e/0x10050/0x10040; 99 comes from `0x447b80:` `*(undefined1 *)(iVar2 + 0x10043) = 99;` and is shown by `0x449d80:` `FUN_0044a9a0(0,*(undefined1 *)(DAT_0052fd00 + 0x10043),1);` |
| 0x45 | 1 | **time in seconds** (single byte) | `0x4074f0: _DAT_004b28ea = (ushort)*(byte *)(DAT_0052fd00 + 0x10045);` `0x447b80: *(undefined1 *)(DAT_0052fd00 + 0x10045) = 0x7c;` (=124) |
| 0x47 | 1 | low byte of the 16-bit item/collectible count | `0x4074f0: sVar4 = (ushort)*(byte *)(DAT_0052fd00 + 0x10047) + (ushort)*(byte *)(DAT_0052fd00 + 0x1013c) * 0x100;` |
| 0x48 | 1 | flag byte, bits `0x1F` and `0x80` set by level scripts | `0x447b80: *(byte *)(iVar2 + 0x10048) = *(byte *)(iVar2 + 0x10048) \| 0x1f;` |
| 0x4E | 1 | trigger / script index, `0x38` on a fresh save | `0x407190: *(undefined1 *)(DAT_0052fd00 + 0x1004e) = 0x38;` / `= *(undefined1 *)(DAT_0052fd00 + 0x10000);` |
| 0x4F | 1 | "active script" flag; gates the whole pad→RAM path | `0x4491c0: if (*(char *)(DAT_0052fd00 + 0x1004f) == '\0') {` |
| 0x50 | 1 | **language index — NOT from the file** | `0x407190: uVar1 = *(undefined1 *)(DAT_0052fd00 + 0x10050); … *(undefined1 *)(DAT_0052fd00 + 0x10050) = uVar1; … = DAT_009ca828;` (save does the same: `0x4074f0:` / `0x4076f0:` `*(undefined1 *)(iVar1 + 0x10050) = DAT_009ca828;`) |
| 0x51 | 1 | 0 on a fresh save | `0x407190: *(undefined1 *)(DAT_0052fd00 + 0x10051) = 0;` |
| 0x64 | 1 | flag byte, bits `1,2,4,8,0x10` set by level scripts | `0x447b80: *(byte *)(DAT_0052fd00 + 0x10064) = … \| 2;` (×5) |
| 0x70…0x73 | 4 | cleared on level init | `0x4474b0:` `*(undefined1 *)(DAT_0052fd00 + 0x10070) = 0;` (×4) |
| 0x76 | 1 | cleared to 0 on every load, before use | `0x407190: *(undefined1 *)(DAT_0052fd00 + 0x10076) = 0;` |
| 0xDF | 1 | **slot number** (1..6), written into the block | `0x4074f0: FUN_00450420(local_20,"..\bin\Savegame%d.dat",*(undefined1 *)(DAT_0052fd00 + 0x100df));` |
| 0xE6 | 1 | set from a runtime global on level init | `0x42e7a0:` `*(undefined1 *)(DAT_0052fd00 + 0x100e6) = DAT_004b2374;` |
| 0xE7 | 1 | bit flags `0x80` and `0x01` (input-related) | `0x448eb0: if (((*(byte *)(DAT_0052fd00 + 0x100e7) & 0x80) != 0) && ((*(byte *)(DAT_0052fd00 + 0x100e7) & 1) != 0))` |
| 0xF6, 0xF8 | 1+1 | u8s, single reference each | UNKNOWN |
| 0x13C | 1 | **high byte of the 16-bit item count** (little-endian pair with 0x47) | `0x447b80: *(undefined1 *)(DAT_0052fd00 + 0x1013c) = 1;` with 0x47 = 0x4d ⇒ 0x14D = 333 |

No magic and no compression. The "checksum" at +0x04 is **written but never verified**:
`FUN_0042E5E0` has exactly one caller in the entire binary (`0x4074f0`), and the load
path tests only `fread`'s return value and `dword[0]`:

```
0x407190:  iVar3 = FUN_004508f0(local_140,0x140,1,iVar2);
0x407190:  if (iVar3 == 0) { DAT_004b227b = 4; }   // error 4 = read failed -> fresh template
0x407190:  else if (*(int *)(DAT_0052fd00 + 0x10000) == 0) { *(undefined1 *)(…+0x1004e) = 0x38; }
```
Note the checksum is computed *over* the four bytes that hold it, then stored, so it is
self-referential and could not be validated even if someone tried.

### 6.2 `Savedata.dat` — 360 bytes (`DAT_004B28E0 + n`)

Load and save agree exactly. The loader copies 0x168 bytes into the live block and
then unpacks **18 individual fields**, which pins the layout:

| off | size | meaning | evidence (load `0x4076f0`) |
| --- | --- | --- | --- |
| 0x00 | 4 | unknown (never read) | falls out of the 0x168 size minus the fields below |
| 0x04 | 4 | **slot-in-use bitmap**, bit (slot−1) | `DAT_004b2264._0_1_ = local_164;` (`local_164` = block+0x04) |
| 0x08 | 0x2C | slot 1 record | see below |
| 0x34 | 0x2C | slot 2 record | `DAT_004b228d = (undefined1)local_134;` (`local_134` = block+0x34) |
| 0x60 | 0x2C | slot 3 record | `local_108` = block+0x60 |
| 0x8C | 0x2C | slot 4 record | `local_dc` = block+0x8C |
| 0xB8 | 0x2C | slot 5 record | `local_b0` = block+0xB8 |
| 0xE4 | 0x2C | slot 6 record | `local_84` = block+0xE4 |
| 0x110…0x167 | 0x58 (88) | **never read and never written** — dead file space | no reference to `DAT_004B29F0`–`DAT_004B2A47` anywhere in the decompile; the only nearby symbol is `DAT_004b2a48`, one past the block |

Slot records: **stride 0x2C (44) bytes**, 6 of them, starting at 0x08
(`8 + 6*0x2C = 0x110`, which lands exactly on the dead tail). Each record, from the
writer:

```
0x4074f0:  cVar1 = *(char *)(DAT_0052fd00 + 0x100df);            // slot 1..6
0x4074f0:  if (cVar1 == '\x01') { _DAT_004b28e8 = sVar4; _DAT_004b28ea = (ushort)*(byte *)(DAT_0052fd00 + 0x10045); }
0x4074f0:  else if (cVar1 == '\x02') { _DAT_004b2914 = sVar4; _DAT_004b2916 = …0x10045; }
0x4074f0:  else if (cVar1 == '\x03') { _DAT_004b2940 = sVar4; _DAT_004b2942 = …; }
0x4074f0:  else if (cVar1 == '\x04') { _DAT_004b296c = sVar4; _DAT_004b296e = …; }
0x4074f0:  else if (cVar1 == '\x05') { _DAT_004b2998 = sVar4; _DAT_004b299a = …; }
0x4074f0:  else if (cVar1 == '\x06') { _DAT_004b29c4 = sVar4; _DAT_004b29c6 = …; }
```
so, with `DAT_004B28E0` = block base:

| slot | record offset | u16 field 1 (= `sVar4`) | u16 field 2 |
| --- | --- | --- | --- |
| 1 | 0x08 | time/gem value: `byte[0x47] + byte[0x13C]<<8` | `byte[0x45]` = seconds |
| 2 | 0x34 | " | " |
| 3 | 0x60 | " | " |
| 4 | 0x8C | " | " |
| 5 | 0xB8 | " | " |
| 6 | 0xE4 | " | " |

`0x4074f0:` `_DAT_004b28e4 = _DAT_004b28e4 | 1 << (*(char *)(DAT_0052fd00 + 0x100df) - 1U & 0x1f);`
(bit 4 set) … then the same bit is cleared with `^` after the write succeeds
(`0x4074f0:` `_DAT_004b28e4 = _DAT_004b28e4 ^ 1 << (…);`), so the in-RAM bitmap is
used as a dirty marker and ends up zero; the *saved file* therefore carries bit n set
for the slot just written.

Score display confirms the two u16s, from `0x449d80`:
`0x449d80:` `uVar5 = (uint)*(byte *)(DAT_0052fd00 + 0x1013c) * 0x100 + (uint)*(byte *)(DAT_0052fd00 + 0x10047);`
(the field-1 value, shown as a decimal number) and
`0x449d80:` `uVar6 = *(byte *)(DAT_0052fd00 + 0x10045) / 100;` (field 2, also a
decimal), plus the combined formula
`0x449d80:` `uVar6 = (((…byte(0x1013c) * 0x100 + …byte(0x10047) + …byte(0x10045)) * 100) / 0x1c9;`
⇒ **score = (count + seconds) * 100 / 457**.

### 6.3 What is NOT in either file (and is therefore recomputed)

* **`config.pc`** — renderer, resolution, language, volumes, all 26 bind bytes. Loaded
  once at startup (`0x405950:` `FUN_00409e30(); FUN_00409cc0();`).
* **`bugs.ini`'s `FirstTime`** — re-read every run; the flag byte is *not* in
  `config.pc`.
* **Language inside `Savegame%d.dat` offset 0x50** — present in the file but
  **overwritten on both save and load** with the current `config.pc` value:
  `0x4074f0:` / `0x407190:` / `0x4076f0:` `*(undefined1 *)(DAT_0052fd00 + 0x10050) = DAT_009ca828;`
  so the byte in the file is stale by construction.
* **`block[0x76]`** — explicitly cleared on load: `0x407190:` `*(undefined1 *)(DAT_0052fd00 + 0x10076) = 0;`
* **`block[0x4E]`** — recomputed: `= 0x38` if `dword[0]==0`, else `= byte[0x00]`.
* **The 64-byte array at `DAT_004B2260`** (per-level times / best scores, indexed
  0..0x3F) is zeroed on level init (`0x42e7a0:` 0x40 dwords) and only **partially**
  restored from `Savedata.dat`: the loader writes block+0x04 → element 4 (the bitmap)
  and block+0x08/0x0A/0x34/0x36/0x60/0x62/0x8C/0x8E/0xB8/0xBA/0xE4/0xE6 → elements
  0x2B..0x3F. **Elements 0x00..0x2A are never saved or loaded.**
* **All input state.** `DAT_009CA8C0[256]`, `DAT_004B3228` (edge mask), the three
  repeat counters `DAT_004B39B2` / `DAT_004B238A` / `DAT_004B28CC`, the analog
  accumulators `DAT_004B1860/64/78` and the DirectInput devices are all rebuilt from
  scratch each frame/level (`0x448eb0:` `FUN_00402ff0(&DAT_004b31c0,&DAT_004b3200);`
  `thunk_FUN_00402610();` then zeroing `0x1000A/0C/0E/10`).
  **Caveat:** the *pad bytes inside the save block* (`0x1000A/0C/0E/10/3E`) **are**
  saved and restored, so a button held at the moment of saving stays held after a load.
  A faithful port should zero these on load.
* **Level geometry, sprite state, object positions** — not in these files; they come
  from the `.BZE` level container via the chunk loader.

---

## 7. Open items / needs runtime confirmation

1. **Absolute address of the GetKeyboardState stack buffer** and the exact frame
   offset. Needs a disassembly of `0x4028a0`; the decompiler's `frame+0x10` for the
   argument contradicts its own `frame+0x0C+VK` reads.
2. **Body of `LAB_00402810`** (the DirectInput poller) is missing from
   `bugs_decompiled.c` — it has no function header, so the exporter skipped it.
   Re-run the Ghidra export with `createFunction` on that address, or disassemble
   0x402810–0x40289F.
3. **Which of config 0x70 / 0x74 / 0x78 is the gamma slope** vs the offset
   (`FUN_00424ef0` shows 2 params, every call passes 3).
4. **`LAB_00402000`** — the device-enumeration callback that decides which physical
   devices become `DAT_004B18C4` / `DAT_004B18C8`.
5. **The exact `DIDATAFORMAT`** — the struct at `0x44FC00` is all zeros in the image
   (except `dwcPOVs = 0xFFFFFFFF` at +0x18), so either it is filled at runtime or
   Ghidra mis-symbolised it. The 2-axes-at-0/4 + 32-bytes-at-0x30 read in `0x402180`
   is the only hard evidence.
6. **Shipped `config.pc` byte-exactness** — RE_NOTES reports `10 00 00 00` then zeros;
   that is consistent with `0x409cc0` accepting the file verbatim (size 128, `dword0 ==
   0x10`), which would leave renderer=0, width=0, height=0. Someone should hexdump the
   shipped file to confirm whether the other 124 bytes are really zero — if they are,
   the first run must rely on `FUN_0040DD40`'s `DAT_009ca824 == 2` fallback and on
   `FUN_0040E790` clamping the resolution.
7. **`bugs.ini` existence on a real install** — `FUN_00409E30` returns 0 if it is
   missing, and `FUN_00409F60` (the `FirstTime` rewriter) returns 0 too. Neither is
   fatal, but the first-run path depends on it.
