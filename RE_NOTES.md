# Bugs Bunny: Lost in Time (PC) - reverse engineering notes

Working dir: `/workspace/bblit`. Extracted game tree: `/tmp/iso` (see layout below).

## What this is

Windows port of the Behaviour Interactive PS1 platformer, published by
Infogrames (1999). Build traces: `D:\Projets\Bugs\src\Pcrogl.c`,
`D:\Projets\Bugs\src\pcrsoft8.c`. Registry:
`Software\Infogrames\Bugs Bunny Lost In Time`. VC++ 6.0 toolchain
(linker 5.00), PE32 i386.

## Binaries

| file | what it is |
| --- | --- |
| `DATAS/BIN/BUGS.EXE` | the game. 772,096 bytes, 6 sections. 576 functions decompiled to `bugs_decompiled.c` |
| `DATAS/BIN/HV3DFX.DLL` | 3Dfx OpenGL mini-ICD ("OpenGL / 3Dfx Interactive", "1.1.0 3Dfx stand-alone (Apr 29 1999)"). Glide->OpenGL shim, no game logic. 1238 functions in `hv3dfx_decompiled.c` |

Renderers in BUGS.EXE, chosen at runtime (global `DAT_004ac094`):
0/1 = software blitter (StretchDIBits, `pcrsoft8.c`), 2 = OpenGL
(`Pcrogl.c`, loads `opengl32.dll` via LoadLibraryA and wgl* dynamically),
plus a DirectDraw path for display. Sound: DirectSound. Input: ReadConsoleInputA +
GetKeyboardState. No Direct3D import; the installer offers DirectX 6.1 anyway.

README0.TXT (retail doc) confirms: default 512x384 fullscreen; OpenGL
auto-selected when the card accelerates it, else software renderer gated on
a 300 MHz CPU check; HV3DFX.DLL is the 3Dfx OpenGL shim for Voodoo
Graphics/2/3; `bugs.ini` keys `CheckGDI` and `DLL` override detection.

CLI flags (GetCommandLine scan, case-insensitive): `/SKIP_INTRO`,
`/SOFT24`, `/SOFT16`, `/SOFTRGB`, `/SOFTPAL`, `/SOFT8`, `/OPENGL`,
`/NO_SKIP`, `/NO_SYNC`. Window/class names: "Bugs Bunny", "BBLIT Game",
"BBLIT Res window". Config: `..\bin\config.pc` (FirstTime=%i,
Language=%i), optional `..\bin\bugs.ini`; saves `..\bin\Savegame%d.dat`,
`..\bin\Savedata.dat`.

## CD layout (ISO 9660 + Joliet, volume BBLIT)

- `DATAS/BIN/` - exe, dll, config, saves
- `DATAS/BZE/` - 167 `.BZE` level containers + one 8-bit `.BMP` per level
- `DATAS/TRACK/` - `TRACK2..33.XA` CD audio/XA music
- `DATAS/SPEECHES/` - `SPEECH00/01/03.XA` per-language speech banks
- `INSTALL/` - Acrobat, "Chat'N", DirectX 6.1, plus the old InstallShield 5/6 setup

The exe references PSX-era paths (`..\BZE\...BZE;1` with `;1` ISO version
suffixes, `MUSIC.XA`, `SPEECHES.XA` at volume root) that do not exist on this
disc: the port kept the PS1 file API and points the "CD" at the installed
`DATAS` folder, falling back file-by-file when entries are missing.

## BZE container format (verified against all 167 files)

All u32 LE. A .BZE is a tiled container:

```
sector 0 = directory:
  +0x00 u32 1                    constant
  +0x04 u32 N                    record count
  +0x08 u32 1                    constant
  +0x0C record k = [raw_size, aligned_size, chunk_id]   12 bytes each
then tiles, starting at byte 0x800, one per record in order:
  tile k = [ 0x800 + sum(aligned_size[0..k)) , + aligned_size[k] )
  tile header: 0x0b, type byte, type-specific fields
  payload = first raw_size bytes after the tile header
```

Invariants (checked on all 167 files / 946 tiles):
- every tile begins 0x0b
- `0x800 + sum(aligned_size) == filesize` exactly
- `aligned_size == align2048(raw_size)`
- chunk_id 0 terminates the directory but still carries a real tile
- ids 3 (speech) and 4 (music) in every file; 2 and 5..10 in levels

Semantics of id 3 and 4 confirmed in BUGS.EXE (`FUN_0042e7a0` loader,
`FUN_0041d630` music): raw XA-ADPCM streams spooled to `\SPEC0.DAT` /
`\MUSIC0.DAT`. Each 0x800-byte sector: 0x18 header, 0x7E4 payload, u32
at +0x7FC = byte-sum of payload, verified after read. Sector header
begins `'E','-'`, then a tagged record list (`0x01` 8B, `0x02` 8B,
`0x04` 8B, `D` 12B, `L`/`M` 0x30B language-picked [off,len] of 6,
`5` speech table open, `6` 3B entries, `7`/`8`/`A` arrays of 500/B8/14
byte strides, `B`-`D`,`F`,`L` object spawn fields), terminated by `'.'`.
After the first sector the loader seeks +0x2D000 into the stream
(single texture superblock) and continues reading tagged tables.

Parser: `tools/bze_parse.py` (list or `-x` extract).

## XA files

`TRACK*.XA` / `SPEECH*.XA` are single ISO 9660 files with raw CD-XA
sector content but no 2336/2352 sector framing left - stripped on
mastering. Music is standard CD-DA quality pulled through the same
XA-ADPCM streamer; the port never plays them via MCI, only through the
in-game reader.

## Tooling in this workspace

- `/workspace/tools/jdk-21.0.12.1+1` - Temurin 21 (runs; /tmp is noexec)
- `/workspace/tools/ghidra_12.1.4_PUBLIC` - Ghidra 12.1.4,
  `support/launch.sh` patched to avoid `/dev/fd` (this sandbox has no
  /dev/fd and no /proc-mounted fd); use `analyzeHeadless` normally
- project: `/workspace/bblit/ghidra_proj/BBLIT` - contains BUGS.EXE and
  HV3DFX.DLL analyzed
- scripts: `/workspace/tools/scripts/ExportAllDecompiled.java`
- `/tmp/lstest` binary copy test proved /tmp noexec; /workspace execs fine

## Regenerating the decompile dumps

```
export JAVA_HOME=/workspace/tools/jdk-21.0.12.1+1
cd /workspace/tools/ghidra_12.1.4_PUBLIC/support
./analyzeHeadless /workspace/bblit/ghidra_proj BBLIT -process BUGS.EXE \
  -scriptPath /workspace/tools/scripts \
  -postScript ExportAllDecompiled.java /workspace/bblit/bugs_decompiled.c -noanalysis
```

## CONFIG.PC default (128 bytes)

Shipped file is the default template, reader/writer lives around the
config load in BUGS.EXE (values: resolution pair, two floats 1.0, two
i32 100, key-bind bytes, palette table). File starts `10 00 00 00` then
zeros; interesting quirk: `file` reports it as "PSX image" (misfire).

## Tile type bytes (first byte after 0x0b, observed)

| type | seen in | payload head |
| --- | --- | --- |
| 0x00 | id 2,3,4 on screens | varies |
| 0x01 | id 0 on cutscene files | |
| 0x02..0x04 | level chunks 5..10, id 0 | `1f 00 1f 00` repeated (L01A 5,7,8,9,10,4) |
| 0x17 | id 6 (biggest level chunk) | `00 d8 00 40` |

L01A chunks 4,5,7,8,9,10 all begin `1f 00 1f 00` (31,0,31,0) - looks
like a sector/table count pair, same builder for all six.

## Open / next steps

- payload structure of chunk ids 2 and 5..10 (tile type bytes catalogued;
  chunks 4,5,7,8,9,10 open with a `1f 00 1f 00` run for ~0xc6 bytes then
  table data - likely count pairs / padding, decode pending)
- XA-ADPCM decoder for speech/music tiles
- save format: `..\bin\Savegame%d.dat`, `..\bin\Savedata.dat`
  (360/320B); shipped copies are all zeros, so nothing to reverse from
  until a real save exists
- BMP pairing: the `.BMP` next to each `.BZE` is the 8-bit palette /
  loading image for that level
- registry read `Software\Infogrames\...` supplies the install path
