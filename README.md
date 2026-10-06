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
(x86-64, binutils 2.44). The binary starts, runs `bblit_port_init`, and reaches
the game's startup path, but it does not yet run to completion: the startup
disc check still ends in a SIGSEGV. That is a port-runtime issue, not a build
one.

The decompiled sources and notes are for interoperability and research. No
game assets are hosted here: `.BZE`/`.XA` data, the ISO, and extracted
chunks are excluded via `.gitignore`.
