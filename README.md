# bblit

Reverse-engineering workspace for **Bugs Bunny: Lost in Time** (PC, 1999,
Behaviour Interactive / Infogrames).

| path | what it is |
| --- | --- |
| `RE_NOTES.md` | findings so far: binaries, BZE container format, CD layout, CLI flags, open questions |
| `bugs_decompiled.c` | Ghidra decompile of `BUGS.EXE` (576 functions, VC++6, i386) |
| `hv3dfx_decompiled.c` | Ghidra decompile of `HV3DFX.DLL` (3Dfx OpenGL mini-ICD, 1238 functions, no game logic) |
| `tools/bze_parse.py` | parser for `.BZE` level containers (list contents or extract chunks) |
| `tools/iso_extract.py` | extract the game tree from the ISO |
| `linux/` | the 64-bit Linux port of `BUGS.EXE` (generated sources + WinAPI shims) |

Start with `RE_NOTES.md`.

## Building the Linux port

```
tools/build.sh              # gcc (default)
CC=clang tools/build.sh     # clang, same result
```

Both compilers build the tree clean from a fresh clone; the binary lands in
`linux/build/bblit`. Two source-level rules are enforced by the build:

- The generated game code reaches image data through absolute original-VA
  immediates, so the link must stay `-no-pie` with the text segment at
  `0x48000000`, out of the window `bblit_port_init` maps for the PE image.
  Both flags are set in `tools/build.sh`; the reasoning is in its header
  comment.
- Function-pointer casts use the unprototyped `(T (*)())` spelling, never
  `(T (*)(...))`. A bare `...` needs a named parameter in front of it under
  ISO C, so gcc accepts it only as an extension and clang rejects all ~400 of
  them. `tools/check_portable_casts.sh` runs first in the build and refuses to
  compile if the gcc-only form reappears.

The build was verified clean from a fresh clone on gcc 14.2.1 and clang 21.1.8
(x86-64, binutils 2.44). The binary starts, runs `bblit_port_init`, passes the
startup disc check, and gets through the CPU/OS probe in `sysinfo_dump`. It
does not yet run to completion: it now faults further on, inside the MSVC
stdio emulation (`FUN_00451a50` -> `FUN_00453d90`), not at startup. See
"LP64 frame slots" below and `analysis/01-mainloop-scene.md` §6.

## Regenerating the ported sources

`linux/bblit_game.c`, `linux/bblit_game.h`, `linux/data_syms.{c,h}` and
`linux/triage.txt` are generated and must not be hand-edited:

```
python3 tools/decomp2linux.py bugs_decompiled.c --outdir linux \
    --symbols tools/symbols.csv --renames tools/renames.json
python3 tools/fix_loop.py            # until the error count plateaus
python3 tools/gen_headers.py         # after fix_loop settles
sh tools/build.sh
```

Hand fixes live in two places, both applied automatically on every run:

- `tools/patches/<name>.c` replaces a whole function body (used for
  `winmain`, `find_cd_drive`, `game_vfprintf_core`). Each file opens with why
  the generated form cannot work on LP64.
- the `HAND_FIXES` table in `tools/fix_loop.py` for individual sites.

Verify a regeneration with `gcc -c -Ilinux linux/bblit_game.c`: it must report
0 errors before you trust the result. A tree that stalls at a nonzero count
means a hand fix was lost.

## LP64 frame slots (the recurring port bug)

Ghidra models the original i386 stack as **4-byte slots** and routes each
outgoing call argument through one:

```
*(undefined1 **)(puVar15 + -0x2c) = local_354;   /* 8 bytes on LP64 */
*(char **)(puVar15 + -0x28) = STR_CD_VOLUME_LABEL;
```

On a 64-bit host that lvalue is 8 bytes wide and **overwrites the neighbouring
slot**. In the disc check this destroyed the `__strcmpi` needle (it read back
as `0x00007ffd`, the high half of a stack address), so the scan never matched,
`winmain` spun in the retry dialog, and the accumulated corruption eventually
jumped to `RIP=0`. Measured `vlen` arriving as 32766 instead of `0x104`.

Two rules follow, and both are load-bearing:

- Do not narrow these slots to 4 bytes to "fix" them. Some slots must
  round-trip a full 64-bit host pointer (verified: `ogl_init` slot `-0x20`,
  `FUN_00453400` slot `-0xc`), and truncating those breaks the pointer.
- The fix that works is to stop routing the call through frame slots at all:
  call the shim directly with real buffers. Done for the disc scan
  (`cd_scan_once`, shared by `winmain` and `find_cd_drive`) and the CPU vendor
  check in `sysinfo_cpu_detect`.

### Open: pointer-slot widening in `bblit_port_init` is unsound

`bblit_port_init` widens referenced pointer slots from 4 to 8 bytes in place,
but the image packs them at **4-byte stride**: widening slot `a` writes
`[a, a+8)` and so destroys the slot at `a+4`. 182 of the 384 slots are
adjacent. Measured consequence: widening the read-only slot `0x4ac30c` zeroed
`0x4ac310` (`PTR_s_CyrixInstead_004ac310`), and `sysinfo_cpu_detect` then read
the CPU vendor needle as NULL. The current fix names that one needle by its
image address (`0x4ac318`) rather than working around the widening generally.

Two slots 4 bytes apart cannot both be 8 bytes wide in place, so this needs a
real answer before more of the game is brought up. Not yet attempted.

The decompiled sources and notes are for interoperability and research. No
game assets are hosted here: `.BZE`/`.XA` data, the ISO, and extracted
chunks are excluded via `.gitignore`.

## Current runtime state

Startup now gets past the disc check and the CPU/OS probe. The next fault is
in the MSVC stdio emulation: `sysinfo_dump` calls `FUN_00451a50`, which runs
`FUN_00453f00`/`FUN_00451600` to set up a `FILE` buffer at `DAT_004ae668`, and
`FUN_00453d90` faults storing a character through it (observed
`SIGSEGV si_addr=0x4` in `FUN_00453d90`). That is a new area, separate from
the frame-slot class above.
