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

Start with `RE_NOTES.md`.

The decompiled sources and notes are for interoperability and research. No
game assets are hosted here: `.BZE`/`.XA` data, the ISO, and extracted
chunks are excluded via `.gitignore`.
