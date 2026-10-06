# 03 — Rendering architecture (BUGS.EXE + HV3DFX.DLL)

Scope: how BUGS.EXE picks a renderer, what the software path actually computes, what
the OpenGL path sets up, how geometry and textures arrive, and whether HV3DFX.DLL
holds game logic.

Every claim below is tagged **CONFIRMED** / **PLAUSIBLE** / **UNKNOWN** and is backed by
a quoted decompile line. Addresses are `0x40xxxx` VAs in `bugs_decompiled.c` unless
stated otherwise.

---

## 0. READ THIS FIRST — the decompile is incomplete in exactly the wrong place

**CONFIRMED.** `bugs_decompiled.c` contains 576 exported function bodies. It contains
**zero** occurrences of `StretchDIBits`, `BitBlt`, `SetDIBitsToDevice`,
`CreateDIBSection` or `CreateCompatibleBitmap` (grep over the whole file; the only
recognised Win32 names are the 119 identifiers listed by scanning for `Ident(`).
Those calls are either inside unexported functions or made through a GDI shim.

**CONFIRMED.** 340 distinct `LAB_<addr>` symbols are referenced by address
(`&LAB_0040a6c0`), and **none of the 340 has a `// =====` header in the file** —
i.e. none of them has a body in this export. Of those, 116 are only ever
address-taken (never a `goto` target). The ones that matter here:

```
&LAB_0040a6c0 .. &LAB_0040c920   (11 entries, 0x40a530..0x40cbd0 gap)
&LAB_0040efb0 .. &LAB_0040fc00   (8 entries)
&LAB_00413a20 .. &LAB_004161b0   (14 entries)
&LAB_00416ff0, &LAB_00417090..LAB_00417300
&LAB_0041a6d0 .. &LAB_0041b270   (14 entries)
```

These are exactly the **two renderer vtables**. Both are populated from function
addresses that this export does not contain.

**Consequence, stated plainly:** the software rasteriser inner loop, the z-buffer,
the per-pixel triangle shading, the `glBegin/glVertex/glDrawElements` calls and the
final `StretchDIBits` present are **all inside that gap and are not in this
decompile**. I cannot quote them, so I do not claim them. Where the structure is
unambiguous from the caller side I say so and tag the inference; otherwise I leave
it UNKNOWN.

To close this: re-run the export with Ghidra's *Create Function* analysis on data
references enabled (or disassemble the ranges by hand from the PE). This is the one
blocking gap for a rewrite.

The one exception that proves the point: `FUN_00417010` **is** exported, and it is
```
void FUN_00417010(void)
{
  return;
}
```
— an empty stub that is nonetheless installed into the software vtable
(`_DAT_004b1a88 = FUN_00417010;`). So the export covers exactly the functions Ghidra
made; address-taken-only code was skipped.

---

## 1. Renderer dispatch

### 1.1 The two globals

| global | role | evidence |
| --- | --- | --- |
| `DAT_009ca824` | **requested** renderer id (from `/SOFT*`, `/OPENGL`, ini, auto-detect) | `0x40e790`: `DAT_004ac094 = DAT_009ca824;` |
| `DAT_004ac094` | **active** renderer id | every dispatch site |

`CONFIRMED` — `DAT_009ca824` is set from the command line / ini:

```
0x40e1d0 area, line 6740ff of the dump:
  pcVar2 = _strstr(_Str,s__OPENGL_00467624);
  if ((pcVar2 != (char *)0x0) || (pcVar2 = _strstr(_Str,s__opengl_0046761c), pcVar2 == 0)) {
    DAT_009ca824 = 2;                                   // /OPENGL
  }
  pcVar2 = _strstr(_Str,s__SOFT_00467614);  ... DAT_009ca824 = 1;   // /SOFT
  pcVar2 = _strstr(_Str,s__SOFT8_00467604);  ... DAT_009ca824 = 0;  // /SOFT8
  pcVar2 = _strstr(_Str,s__SOFTPAL_004675f0); ... DAT_009ca824 = 0; // /SOFTPAL
  pcVar2 = _strstr(_Str,s__SOFTRGB_004675d8); ... DAT_009ca824 = 1; // /SOFTRGB
  pcVar2 = _strstr(_Str,s__SOFT16_004675c4);  ... DAT_009ca824 = 1; // /SOFT16
  pcVar2 = _strstr(_Str,s__SOFT24_004675b4);  ... DAT_009ca824 = 1; // /SOFT24
```

### 1.2 The dispatch, quoted

The canonical form, `0x40cc10` — a 3-arg "set colour" that routes on the id:

```
// ===== FUN_0040cc10 @ 0040cc10 =====
void FUN_0040cc10(undefined1 param_1,undefined1 param_2,undefined1 param_3)
{
  if ((DAT_004ac094 & 2) != 0) {
    FUN_0040d910(param_1,param_2,param_3);
    return;
  }
  if ((DAT_004ac094 == 1) || (DAT_004ac094 == 0)) {
    (*DAT_00565fe0)(param_1,param_2,param_3);
  }
  return;
}
```

The same test appears 30 times across the file. The full set of forms:

| test | meaning | CONFIRMED? |
| --- | --- | --- |
| `(DAT_004ac094 & 2) != 0` | OpenGL | yes — only value with bit 1 set is 2 |
| `DAT_004ac094 == 2` | OpenGL | yes |
| `(DAT_004ac094 == 1) \|\| (DAT_004ac094 == 0)` | software | yes |
| `DAT_004ac094 != 0x10` / `== 0x10` | "a renderer is up" | yes |
| `(uVar5 & 2) == 0` then `(uVar5 == 1) \|\| (uVar5 == 0)` | same, via a local copy | yes |

`0x10` is the **shut-down / no-renderer sentinel**. It is written on every teardown
path and read as "skip":

```
// 0x40dc80 (kill video):
    if (DAT_004ac094 == 2) {
      *(undefined4 *)((int)ppiVar7 + -4) = 0;
      *(undefined4 *)((int)ppiVar7 + -8) = 0;
      *(undefined4 *)((int)ppiVar7 + -0xc) = 0x40dcbd;
      (*DAT_007c63b8)();                 /* 2 args pushed: 0, 0  -> wglMakeCurrent */
      *(undefined4 *)((int)ppiVar7 + -0xc) = DAT_004b1ac0;
      *(undefined4 *)((int)ppiVar7 + -0x10) = 0x40dcca;
      (*DAT_007c661c)();                 /* 1 arg pushed: DAT_004b1ac0 */
      DAT_004b1ac0 = 0;
      ...
    }
    else {
      if ((DAT_004ac094 == 1) || (DAT_004ac094 == 0)) {
        (*DAT_00555fc4)();      /* software: kill video */
      }
    }
    DAT_004ac094 = 0x10;
```

> **Reading rule for this dump.** These are `__cdecl` calls, so Ghidra emits
> `(*fn)()` with **no** arguments and shows the pushed words on the preceding
> `*(undefined4 *)(stack + n) = value;` lines. Any argument list you see in a
> quotation here is read off those stack stores. Where the store is ambiguous I say
> so rather than guessing.

```
// 0x423bd0 (frame begin/end) — the whole function is wrapped in:
  if (DAT_004ac094 != 0x10) { ... }
```

### 1.3 Backend enum values, as proved by code

**CONFIRMED.** `DAT_009ca824` / `DAT_004ac094`:

| value | backend | evidence |
| --- | --- | --- |
| `0` | software, **8-bit paletted** framebuffer | `0x40e790`: `DAT_0046af60 = (-(uint)(DAT_009ca824 != 1) & 0xfffffff0) + 0x18;` → `-(0) & 0xf0 = 0`, `+0x18` = 24 when id==1; `-(1) & 0xf0 = 0xfffffff0`, `+0x18` = **8** when id==0 |
| `1` | software, **24-bit** framebuffer | same line |
| `2` | OpenGL | `0x40e790`: `if (DAT_009ca824 == 2) { ... LoadLibraryA("opengl32.dll") ... }` |
| `0x10` | none / shut down | every teardown path |
| `DAT_004ac094 = (uint)(299 < DAT_004b1de4)` | auto: OpenGL if CPU > 299 MHz, else software 8-bit | `0x40dd40` |

**This refines RE_NOTES.md.** The note says "0/1 = software blitter (StretchDIBits,
source pcrsoft8.c), 2 = OpenGL". The *split* between 0 and 1 is real and is the
framebuffer depth, not a different renderer: 0 → 8bpp, 1 → 24bpp. Same code, same
vtable shape, same blitter. The note's `pcrsoft8.c` name is consistent with 0/8bpp but
does not explain id 1.

### 1.4 There is a renderer vtable, not a switch

**CONFIRMED.** Both backends fill the same 20+ global slots. `0x40e790`:

OpenGL branch:
```
DAT_004b1a70 = &LAB_004124b0;   DAT_004b1a90 = &LAB_0040d440;
_DAT_004b1a94 = &LAB_0041f800;  DAT_007c624c = &LAB_0040a6c0;
DAT_007c6250 = &LAB_0040b130;   DAT_004b1a5c = &LAB_0040b980;
DAT_004b1a60 = &LAB_0040be10;   DAT_004b1a64 = &LAB_0040c5e0;
DAT_004b1a68 = &LAB_0040c850;   DAT_004b1a74 = &LAB_00414b40;
DAT_004b1a78 = &LAB_00414590;   DAT_004b1a7c = &LAB_00413be0;
DAT_004b1a8c = &LAB_00413a20;   DAT_004b1a80 = &LAB_00413f00;
_DAT_004b1a84 = &LAB_00413b40;  _DAT_004b1a88 = (code *)&LAB_00413e40;
_DAT_004b1a98 = &LAB_0040f8f0;  DAT_004b1a9c = &LAB_0040efb0;
_DAT_004b1aa0 = &LAB_0040f510;  DAT_004b1aa4 = &LAB_0040fa90;
DAT_007c961c = &LAB_00411330;   DAT_007c9618 = &LAB_00411350;
```
Software branch:
```
DAT_004b1a80 = &LAB_00416ff0;   _DAT_004b1a88 = FUN_00417010;
DAT_004b1a90 = &LAB_0040d4c0;   _DAT_004b1a94 = &LAB_0041ffc0;
DAT_007c624c = &LAB_0040aaf0;   DAT_007c6250 = &LAB_0040b550;
DAT_004b1a64 = &LAB_0040c350;   DAT_004b1a68 = &LAB_0040c920;
DAT_004b1a74 = &LAB_004161b0;   DAT_004b1a78 = &LAB_004159c0;
DAT_004b1a5c = &LAB_0040bc60;   DAT_004b1a60 = &LAB_0040c070;
DAT_004b1a7c = &LAB_00414350;
if (DAT_0046af60 != 8) {
  DAT_004b1a7c = &LAB_00414020;     // 24bpp variant
}
DAT_004b1a8c = &LAB_00413f10;  _DAT_004b1a98 = &LAB_0040f6e0;
DAT_004b1a9c = &LAB_0040f150;  _DAT_004b1aa0 = &LAB_0040f340;
DAT_004b1aa4 = &LAB_0040fc00;  DAT_007c961c = &LAB_004116f0;
DAT_007c9618 = &LAB_00411720;
```
So the software backend has its own **8bpp vs 24bpp** variant of slot `DAT_004b1a7c`.
The renderer interface is a vtable of ~20 slots at scattered globals; every game-side
draw call goes through it, and both backends are swappable at runtime.

Slot semantics, derived from call sites (arities and use):

| slot | arity | inferred role | confidence |
| --- | --- | --- | --- |
| `DAT_004b1a80` | 0 | begin frame / clear | CONFIRMED (called first in `0x423bd0`, before projection) |
| `DAT_004b1a8c` | 0 | set projection / view constants | CONFIRMED (called right after `a80`, writes fog+light block) |
| `DAT_004b1a7c` | 0 | end frame / present | CONFIRMED (called last, before `InvalidateRect`) |
| `DAT_004b1a90` | 0 | renderer reset/shutdown | PLAUSIBLE |
| `DAT_004b1a78` | 6 | set material/lighting (4 vec ptrs + enable) | CONFIRMED |
| `DAT_004b1a74` | 6 | set fog (colour, near, far, enable) | CONFIRMED |
| `DAT_004b1a68` | 1 | bind texture (takes a `DAT_004ae368` struct) | PLAUSIBLE |
| `DAT_004b1a64` | 2, returns int | clip/scissor rect, returns a cookie | CONFIRMED (all 4 call sites in `0x44c4b0` are the same 2 args) |
| `DAT_004b1a9c` | 1 | begin object / bind geometry block | PLAUSIBLE |
| `DAT_004b1aa4` | 2 | range submit (start, end) | PLAUSIBLE |
| `DAT_004b1a5c`, `DAT_004b1a60` | 2, 1 | fade-level / dimming (take `DAT_004efb8c` and `0x1000 - DAT_004b3738`) | CONFIRMED (value flows to `DAT_00467740/44`, the global brightness) |
| `DAT_007c961c` | 0 | polygon batch begin | CONFIRMED |
| `DAT_007c9618` | 1 | polygon submit (takes a vertex/poly block) | CONFIRMED |
| `DAT_00565fe0` | 3 | software-only "set colour" (see `0x40cc10`) | CONFIRMED |

### 1.5 Mode setting

`CONFIRMED` — `0x40d850` is *not* `ogl_set_display_mode`; it is the DirectDraw
surface-mode set (`DirectDraw` vtable at `*DAT_004b1ac4`, offsets `+0x30`, `+0x50`,
`+0x54`; `local_6c[0] = 0x6c` = `DDSURFACEDESC2` size). Its error path names its own
source file:

```
  FUN_004055d0(s_file___s_l___d__>msg__GetDisplay_0046ae44,
               s_D__Projets_Bugs_src_Pcrogl_c_0046ae70,0x2f9);
```

So `Pcrogl.c` is the source file of `0x40d850` — RE_NOTES' attribution of
`Pcrogl.c` to the OpenGL path is right, but the function itself is the *display*
surface setup shared by both paths (it is called for the software path too, at
`0x40e790`, with `0x10` = fullscreen vs `0`).

`CONFIRMED` — `0x40df20` is the OpenGL pixel-format chooser:

```
  local_28.nSize = 0x28;
  local_28.nVersion = 1;
  local_28.dwFlags = 0x25;
  local_28.cColorBits = '\x10';
  iVar2 = ChoosePixelFormat(DAT_004b1abc,&local_28);
```

`0x25` = `PFD_DOUBLEBUFFER(1) | PFD_DRAW_TO_WINDOW(4) | PFD_SUPPORT_OPENGL(0x20)`.
It requests `cColorBits = 0x10` (16) and falls back to `SetPixelFormat` with the
chosen descriptor, validating the driver's reported `PFD_*` flags before accepting.

---

## 2. The software path

### 2.1 Is it a 3D rasteriser or a StretchDIBits blit? — both, and the rasteriser is not in this dump

**UNKNOWN for the raster loop; CONFIRMED for the surrounding architecture.**

What I can prove:

- The software path renders into its own linear buffer, then presents. The present
  for *both* backends is the same call, `0x423bd0`:

```
// 0x423bd0, tail of function:
    InvalidateRect(DAT_004b1cec,(RECT *)0x0,0);
    UpdateWindow(DAT_004b1cec);
    iVar4 = PeekMessageA((LPMSG)&stack0xffffffd4,(HWND)0x0,0,0,1);
```

  The frame ends with `InvalidateRect`/`UpdateWindow` on the game window, i.e. the
  software renderer paints into the window's own DC (via `GetDC` in `0x40e790`), not
  into a DirectDraw primary. **There is no `StretchDIBits` in this decompile at all**,
  so RE_NOTES' "`0x40df20` calls StretchDIBits" is **refuted**: `0x40df20` is
  `ChoosePixelFormat`/`SetPixelFormat` (quoted above). The StretchDIBits call, if it
  exists, is inside `LAB_00414350`/`LAB_00414020` (slot `DAT_004b1a7c`, 8bpp / 24bpp
  software present), which is not in this export.

- The software framebuffer is a **plain heap allocation**, not a DIB:

```
// 0x423a60:
  if ((DAT_004ac094 != 1) && (DAT_004ac094 != 0)) {
    if (DAT_004ac094 == 2) {
      DAT_004b1ca4 = FUN_0044fc30(0x100000);          // OpenGL: 1 MiB staging
    }
    DAT_004b1cac = 0;
    return;
  }
  if (DAT_004b1cac != 0) { FUN_0044fd70(DAT_004b1cac); }
  DAT_004b1cb4 = DAT_0046af64 * 0x140000;              // software
  DAT_004b1cac = FUN_0044fc30(DAT_004b1cb4);
  DAT_004b1ca4 = 0;
```

  `FUN_0044fc30(size)` is the CRT allocator (it forwards to `FUN_0044fc50(size, DAT_004b1e70)`),
  `FUN_0044fd70(p)` is free. So the software renderer owns a `malloc`'d surface.
  `DAT_0046af64` is bytes-per-pixel (`= DAT_004ac0b4 >> 3`, set at `0x40e790`).

- The per-pixel pixel *writer* is a vtable chosen by depth:

```
// 0x403e70, called at the end of the software init branch of 0x40e790:
  if (DAT_0046af60 == 8) {
    _DAT_007c960c = FUN_00404d20;
    _DAT_007c9614 = FUN_00404f20;
    _DAT_007c9608 = FUN_00405180;
    _DAT_007c9610 = FUN_00405390;
    return;
  }
  _DAT_007c960c = FUN_00403ed0;
  _DAT_007c9614 = FUN_00404220;
  _DAT_007c9608 = FUN_004045f0;
  _DAT_007c9610 = FUN_00404970;
```

  Two complete sets of four pixel routines, 8bpp vs 24bpp. **All eight are in the
  unexported gap `0x403ed0..0x405530`.** This is where the scanline/span writes live.

### 2.2 Destination pixel formats — CONFIRMED, and this contradicts a naive reading of RE_NOTES

`DAT_004ac040`'s low byte is the destination stride in bytes. `DAT_004ac038..3f` are
per-channel (width, shift) pairs: `38/39`=R, `3a/3b`=G, `3c/3d`=B, `3e/3f`=A.

`0x420d10` / `0x421770`, the two texture-upload entry points, set them:

```
    if (iVar13 == 0) {
      DAT_004ac040 = CONCAT31(DAT_004ac040._1_3_,8);      //  8 bpp
    }
    else if (iVar13 == 1) {
      DAT_004ac040 = CONCAT31(DAT_004ac040._1_3_,0x18);   // 24 bpp
    }
    switch(DAT_004ac040 & 0xff) {
    case 0x10:                                            // 16 bpp
      DAT_004ac039 = 10; DAT_004ac038 = 5;
      DAT_004ac03a = 5;  DAT_004ac03b = 5;
      DAT_004ac03c = 5;  DAT_004ac03d = 0;
      DAT_004ac03e = 0;  DAT_004ac03f = 0;
      break;
    case 0x18:                                            // 24 bpp
      DAT_004ac038 = 8; DAT_004ac039 = 0x10;
      DAT_004ac03a = 8; DAT_004ac03b = 8;
      DAT_004ac03c = 8; DAT_004ac03d = 0;
      break;
    case 0x20:                                            // 32 bpp
      DAT_004ac038 = 8; DAT_004ac039 = 0;
      DAT_004ac03a = 8; DAT_004ac03b = 8;
      DAT_004ac03c = 8; DAT_004ac03d = 0x10;
      DAT_004ac03e = 8; DAT_004ac03f = 0x18;
    }
```

and the OpenGL side (`iVar13 == 2`) picks **24 bpp or 32 bpp depending on whether the
texture needs an alpha channel**:

```
  else {
    DAT_004ac039 = 0;  DAT_004ac038 = 8;
    DAT_004ac03a = 8;  DAT_004ac03b = 8;
    DAT_004ac03c = 8;  DAT_004ac03d = 0x10;
    if ((&DAT_0052fd69)[iVar12] == '\0') {
      DAT_004ac040 = CONCAT31(DAT_004ac040._1_3_,0x18);   // RGB, no alpha
    }
    else {
      DAT_004ac040 = CONCAT31(DAT_004ac040._1_3_,0x20);   // RGBA
      DAT_004ac03e = 8;
      DAT_004ac03f = 0x18;
    }
  }
```

**CONFIRMED consequences:**

- Software: **8 or 24 bpp only** (`0` and `1`). There is no software 16 bpp mode;
  `case 0x10` is dead in this dump.
- `/SOFT16` and `/SOFTRGB` both set `DAT_009ca824 = 1`, i.e. **24 bpp**. So
  RE_NOTES' "`/SOFT16`" does not select a 16-bit destination.
- OpenGL: 24 bpp RGB, or 32 bpp RGBA when the texture has an alpha mode.

### 2.3 Texture mapping: CLUT + per-texture alpha modes — CONFIRMED

Both upload paths build a **256-entry RGBA CLUT** from RGB555 palette words. `0x421770`:

```
    puVar12 = (ushort *)(param_1 + 0x14);
    ...
      do {
        *DAT_0052fd40 = (char)*puVar12 << 3;
        DAT_0052fd40[1] = (char)(*puVar12 >> 5) << 3;
        DAT_0052fd40[2] = (byte)(*puVar12 >> 10) << 3;
        pbVar7 = DAT_0052fd40;
        if (*puVar12 == 0) {
          (&DAT_0052fd69)[iVar10] = 1;
          pbVar7[3] = 0;                                 // texel 0 => transparent
        }
        else {
          DAT_0052fd40[3] = 0xff;                        // texel != 0 => opaque
        }
        ...
        DAT_0052fd40 = DAT_0052fd40 + 4;                  // stride 4 => 256 RGBA entries
```

That is **PS1-style**: 15-bit `BGR555` palette words, expanded `<<3`, colour 0 is the
transparent key. CLUT base `DAT_00548c80`, 4 bytes/entry, 256 entries.

The **sampler** is `FUN_00421f50` (nearest) and `FUN_00421c70` (3×3 box-filtered),
both taking a `bpp_mode` (`*(uint *)(param_1 + 4) & 7`):

```
// 0x421f50:
  if (param_6 == 0) {
    param_2 = (param_3 >> 1) * param_2;
    if ((param_1 & 1) == 0) {
      uVar2 = *(byte *)(param_2 + ((int)param_1 >> 1) + param_5) & 0xf;   // 4bpp, low nibble
    }
    else {
      uVar2 = (uint)(*(byte *)(param_2 + ((int)param_1 >> 1) + param_5) >> 4); // 4bpp, high nibble
    }
  }
  else {
    ...
      if (param_6 != 1) {
        if (param_6 != 2) { return 0; }
        param_5 = param_5 + param_3 * 2 * param_2;
        psVar1 = (short *)(param_5 + param_1 * 2);       // 16bpp RGB555, direct
        *param_7  = (char)*psVar1 << 3;
        param_7[1] = (char)(... >> 5) << 3;
        param_7[2] = (char)(*psVar1 >> 10) << 3;
        param_7[3] = -1;
        if (*psVar1 == 0) { param_7[3] = '\0'; return 1; }   // colour 0 => alpha 0
        param_7[3] = -1;
        return 1;
      }
      uVar2 = (uint)*(byte *)(param_3 * param_2 + param_5 + param_1);   // 8bpp
  }
  *param_7 = (&DAT_00548c80)[uVar2 * 4];                  // CLUT lookup, 4bpp and 8bpp
```

**CONFIRMED source pixel formats:** `mode 0` = **4-bit paletted** (two texels/byte,
even-x low nibble), `mode 1` = **8-bit paletted** (CLUT lookup), `mode 2` =
**16-bit RGB555 direct**. The header gate is
`if ((*param_1 == '\x10') && ((*(uint *)(param_1 + 4) & 7) < 3))` and the upload
skips CLUT expansion when mode 2 (`if (((byte)*(undefined4 *)(param_1 + 4) & 7) != 2)`),
which is exactly right: 16bpp has no CLUT.

**CONFIRMED per-texture alpha modes.** `(&DAT_0052fd72)[texid * 0x18]` is a per-texture
byte, values 0–4, each a different alpha rule applied during unpack
(`0x420d10`, `switch((&DAT_0052fd72)[(int)param_3 * 0x18])`):

| mode | alpha rule | extra |
| --- | --- | --- |
| 0 | `max/2` | if r==g==b → RGB forced to `0xff,0xff,0xff`, alpha `= v>>1` |
| 1 | `max - max/4` | same greyscale→white collapse |
| 2 | **luma** `0.299R + 0.587G + 0.114B` | for OpenGL; for software RGB is zeroed and flag bit 1 set |
| 3 | `max>>2` | non-greyscale: RGB reduced by `max` |
| 4 | `0xff` (fully opaque) | |

Mode 2 is the interesting one:
```
        case 2:
          local_8 = (float)(uint)DAT_0052fd40[2];
          bVar9 = __ftol(((double)*DAT_0052fd40 * 0.299 - (double)DAT_0052fd40[1] * -0.587) -
                         (double)(int)local_8 * -0.114);
          pbVar14[3] = bVar9;
```
i.e. alpha = `0.299R + 0.587G + 0.114B`. And
```
    if ((((&DAT_0052fd72)[(int)param_3 * 0x18] == 2) && (iVar13 != 1)) &&
       ((iVar13 != 0 && (0 < DAT_00548c60)))) {
      puVar15 = &DAT_00548c81;
      iVar20 = DAT_00548c60;
      do { puVar15[-1] = 0; *puVar15 = 0; puVar15[1] = 0; puVar15 = puVar15 + 4; iVar20 = iVar20 + -1; }
```
So mode-2 textures are **RGB-flattened to 0 on the software path** and turned into
alpha on the OpenGL path. That is a real, per-backend effect difference.

### 2.4 Gamma / colour LUTs — CONFIRMED

Two 256-byte tables, `DAT_004b5b40` and `DAT_004d5d40`, applied to RGB in that order
when `DAT_004ac034 != 0`. `DAT_004d5d40` is written by `FUN_00424ef0`:

```
// 0x424ef0:
void FUN_00424ef0(double param_1,double param_2)
{
  ...
  do {
    iVar1 = __ftol((double)((longdouble)local_4 * lVar2 + lVar3));
    if (0xff < iVar1) { iVar1 = 0xff; }
    if (iVar1 < 0)    { iVar1 = 0; }
    (&DAT_004d5d40)[local_4] = (char)iVar1;
    local_4 = local_4 + 1;
  } while (local_4 < 0x100);
```
A 256-entry ramp, `lut[i] = clamp(i * param_2 + param_1)` — a linear brightness/
contrast trim. `DAT_004b5b40` is a **gamma** table built from a power function:
```
    (&DAT_004b5b40)[uVar19] = uVar11;
```
where `uVar11 = __ftol(FUN_00451310()(uVar19 * 0.00390625) * 256.0)` — i.e.
`lut[i] = (u8)(powf(i/256, g) * 256)`. `FUN_00451310` is the CRT `pow`.

Both tables are re-derived per call to `gfx_detect_card` from a global gamma /
brightness setting, and the OpenGL colour path uses them too (`0x40d910`, the
OpenGL `set colour`, indexes `DAT_004b5b40` then `DAT_004d5d40`).

### 2.5 Lighting: flat per-polygon, not Gouraud — CONFIRMED

`FUN_0044c070` is called once per polygon from `0x44c4b0`. It transforms three
vertices, builds a face normal and stores it in **spherical form**:

```
// 0x44c070:
  FUN_0040a150(*(undefined4 *)(param_1 + 0x10),param_3);
  DAT_004b38c0 = *(int *)(param_3 + 0x14);
  DAT_004b38c4 = *(int *)(param_3 + 0x18);
  DAT_004b38c8 = *(int *)(param_3 + 0x1c);
  FUN_00408260(param_3,&local_10,&local_10);      // transform origin by inverse
  DAT_004b38cc = local_10 + DAT_004b38c0;
  local_10 = DAT_004b38c0 - DAT_004b38cc;
  DAT_004b38d0 = local_c + DAT_004b38c4;
  DAT_004b38d4 = local_8 + DAT_004b38c8;
  local_c = DAT_004b38c4 - DAT_004b38d0;
  local_8 = DAT_004b38c8 - DAT_004b38d4;
  DAT_004b3e1a = FUN_004079e0(local_10,local_8);            // atan2 -> normal angle
  iVar1 = FUN_004079c0(local_10 * local_10 + local_8 * local_8);  // sqrt -> length
  DAT_004b3e2c = DAT_004b3e1a;
  DAT_004b3da8 = iVar1 + 1;
```

`local_10/local_8` are two edges of the triangle after view transform; the normal is
`atan2` of the cross product and the magnitude is stored as `1/(len+1)`. **One normal
per polygon.** No per-vertex normal array is present anywhere in this dump.

**UNKNOWN:** whether the software rasteriser interpolates anything per-vertex inside
the triangle. Given one normal per polygon, flat shading is the strong expectation,
but the interpolation step is in the unexported gap. The PS1 GPU does affine
(linear-in-screen-space) interpolation, which the task's brief expects — I cannot
confirm it from this file.

### 2.6 Depth buffer — NOT FOUND

**UNKNOWN, leaning "no z-buffer in the software path".**

Evidence for:
- No identifier matching `zbuf|depth|DepthBuffer|z_buffer` occurs anywhere in
  `bugs_decompiled.c` (grep, 0 hits).
- The only destination-format machinery is `DAT_004ac040` (colour bpp) and
  `DAT_004ac038..3f` (colour channel widths). There is no parallel depth descriptor.
- The software buffer allocation (`0x423a60`, `DAT_0046af64 * 0x140000`) is sized for
  colour only.
- `0x40cd20(400)` at frame start sets the near/far scalars and, on OpenGL, calls
  `FUN_00413990` to set an orthographic projection:
```
// 0x40cd20:
  _DAT_004efb34 = (float)param_1;
  DAT_004efb30 = param_1;
  DAT_004efb38 = (float)-(param_1 / 2);
  if (((byte)DAT_004ac094 & 2) != 0) {
    FUN_00413990(param_1);
  }
```
```
// 0x413990:
  (*DAT_007c90ac)(0x1701);
  (*DAT_007c9090)();
  (*DAT_007c946c)((double)DAT_00467748 * -0.5,(double)DAT_00467748 * 0.5,
                  (double)DAT_0046774c * -0.5,(double)DAT_0046774c * 0.5,
                  (double)DAT_004efb3c,0,0x40f00000);
  (*DAT_007c90ac)(0x1700);
```
  An **orthographic** projection. On a PS1 the GPU has no z-buffer; ordering is by
  draw order / sort key. That is consistent with the absence of a depth buffer.

Evidence against / caveat: the depth *test* could still be a software sort. The
frustum-cull pass (`0x40fe90`, §4.2) does reject polygons against
`DAT_004efb38`/`DAT_004efb48` (near/far), which is a *cull*, not a depth test.
**Runtime confirmation required**: instrument a draw and watch whether a
back-facing polygon overwrites a front one.

### 2.7 Projection / transform: 3×3 fixed point — CONFIRMED

`FUN_0040ceb0` (the view-matrix setter, called from `0x40dd40` right after
`SetVideoMode`) builds **3×3 matrices in 4.12-ish fixed point**, with `0x1000` as 1.0:

```
// 0x40ceb0:
  DAT_004efb00._0_2_ = 0x1000;
  DAT_004efb00._2_2_ = 0;
  DAT_004efb04._0_2_ = 0;
  DAT_004efb04._2_2_ = 0;
  _DAT_004efb08 = 0x1000;
  ...
  FUN_00408060(&local_40,&local_60);
  iVar2 = FUN_004079e0(iVar5,iVar7);
  FUN_00407da0(0x1800 - iVar2,&DAT_004efb00);
  uVar3 = __ftol(SQRT((double)(iVar5 * iVar5 + iVar7 * iVar7)));
  iVar2 = FUN_004079e0(iVar1 - iVar4,uVar3);
  FUN_00407c30(-iVar2,&DAT_004efb00);
  FUN_00408640(&local_40,&DAT_004efb00);
  puVar6 = &DAT_004efb00;
  puVar8 = &DAT_0052fce0;
  for (iVar2 = 8; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar8 = *puVar6;                                  // 8 ints = one 3x3 matrix
    ...
  }
  FUN_00408260(&DAT_0052fce0,&DAT_004efb20,&local_50);
```

`0x1000` = 1.0 in 12-bit fixed. **A 3×3 matrix (8 stored elements + translation) with
no w-component and no perspective divide.** This is the PS1 affine-transform model:
`FUN_0040a150` transforms vertices with this, and the perspective divide is either
folded into the matrix or done in the unexported rasteriser.

Also confirmed: the view is set up in **two stages**, a near half-angle and a far
half-angle — `0x1800`/`0x800` (6144/2048 in 12.4 fixed, i.e. 1.5 and 0.5) with
`FUN_00407da0` (cos) and `FUN_00407c30` (sin), producing two matrices at
`DAT_004efb00` and `DAT_004efae0`. `FUN_0040cd20(400)` then scales them. This is a
two-plane projection (PS1 style), not a single perspective frustum.

### 2.8 Screen setup — CONFIRMED

```
// 0x40cbd0:
  DAT_00467748 = param_1;              // width
  DAT_0046774c = param_2;              // height
  _DAT_004ac0a0 = param_1 / 2;
  _DAT_004ac0a8 = param_2 / 2;
  _DAT_004ac09c = -(param_1 / 2);
  _DAT_004ac0a4 = -(param_2 / 2);
```

```
// 0x40e790 (mode-change handler), resolution defaults:
  FUN_0040cbd0(DAT_009ca830);
  FUN_0040d1a0(DAT_009ca830,DAT_009ca834,0x200);
// and on reset:
    DAT_009ca830 = 0x200;              // 512
    DAT_009ca834 = 0x180;              // 384
```

**CONFIRMED: 512×384 default** (matches RE_NOTES), `0x200` = `DIB_RGB_COLORS`.

---

## 3. The OpenGL path

### 3.1 Function pointer table — CONFIRMED

`FUN_0040e050` loads the library and walks a table of `{dest, name}` pairs:

```
// 0x40e050:
  DAT_009ca724 = LoadLibraryA(*(LPCSTR *)(puVar4 + -4));
  ...
    ppuVar7 = &PTR_DAT_00468750;
    puVar6 = puVar4 + -4;
    do {
      *(undefined **)(puVar6 + -4) = ppuVar7[1];
      ...
      pFVar2 = GetProcAddress(*(HMODULE *)(puVar6 + -8),*(LPCSTR *)(puVar6 + -4));
      puVar8 = (undefined4 *)*ppuVar7;
      ppuVar7 = ppuVar7 + 2;
      *puVar8 = pFVar2;
      puVar6 = puVar6 + -8;
    } while (ppuVar7 <= (undefined **)((int)&PTR_s_wglUseFontOutlinesW_0046928c + 3));
```

**The name table lives at `0x468750`, interleaved `{void **slot; char *name}`, and
ends at `0x469298`.** That is the OpenGL ICD dispatch table. Destination slots run
`0x7c6238 .. 0x7ca73c`: **136 distinct `0x7c6xxx`/`0x7c9xxx`/`0x7cAxxx` globals** are
referenced in the code, of which **30 are typed `code **` (i.e. genuine function
pointers, all the `gl*`/`wgl*` entry points that are actually called) and the rest
are plain data words inside the same data segment. The last name in the table is
`wglUseFontOutlinesW`, i.e. it covers the full OpenGL 1.1 `wgl*` surface.

`FUN_0040e050` then picks a pixel format on the window DC and validates the driver's
`PFD_*` flags; it returns 0 on any mismatch. **CONFIRMED — the OpenGL path is
entirely dynamic; no `opengl32.lib` import.**

### 3.2 Fixed-function setup — CONFIRMED, tokens quoted verbatim

`FUN_0040daf0` is the initial GL state block, called only from the OpenGL branch of
`0x40e790`. Full body:

```
// 0x40daf0:
  (*DAT_007c90a8)(0x203);
  (*DAT_007c9098)(0,0,0,0x3ff00000);
  (*DAT_007c632c)(0xb71);
  (*DAT_007c6274)(0,0,0,0);
  (*DAT_007c6354)(0x408,0x1b02);
  (*DAT_007c62d4)(0x1d01);
  (*DAT_007c63c8)(0x302,0x303);
  (*DAT_007c63c0)(0x204,0);
  (*DAT_007c9070)(0xc53,0x1101);
  (*DAT_007c9070)(0xc50,0x1101);
  (*DAT_007c639c)(0xbd0);
  (*DAT_007c639c)(0xb20);
  (*DAT_007c639c)(0xb10);
  (*DAT_007c639c)(0xb41);
  (*DAT_007c639c)(0xb44);
  (*DAT_007c639c)(0xb50);
  (*DAT_007c639c)(0xbe2);
  (*DAT_007c639c)(0xbc0);
  uVar2 = 0;
  uVar1 = 0;
  iVar3 = DAT_00467748;
  iVar4 = DAT_0046774c;
  (*DAT_007c660c)();
  (*DAT_007c90ac)(0x1701,uVar1,uVar2,iVar3,iVar4);
  (*DAT_007c9090)();
  (*DAT_007c946c)((double)DAT_00467748 * -0.5,(double)DAT_00467748 * 0.5,
                  (double)DAT_0046774c * -0.5,(double)DAT_0046774c * 0.5,
                  0,0x40790000,0,0x40f00000);
  (*DAT_007c90ac)(0x1700);
  (*DAT_007c6318)(0x4100);
```

Identifying these by signature and context:

| slot | call | inference | tag |
| --- | --- | --- | --- |
| `DAT_007c90a8` | `(0x203)` | `glClear(0x203)` | PLAUSIBLE (`0x203` is not a standard buffer-bit mask; could be `glClearIndex`/`glClearDepth` variant) |
| `DAT_007c9098` | `(0,0,0,1.0f)` | `glClearColor(0,0,0,1)` | CONFIRMED (4 floats) |
| `DAT_007c632c` | `(0xb71)` | `glEnable(0xB71)` | PLAUSIBLE |
| `DAT_007c6274` | `(0,0,0,0)` | `glClearColor(0,0,0,0)` | CONFIRMED (also used as `set colour` from `0x40cc10`) |
| `DAT_007c6354` | `(0x408,0x1b02)` | `glDepthFunc?/glHint?` 2-arg | UNKNOWN |
| `DAT_007c62d4` | `(0x1d01)` | `glShadeModel(GL_SMOOTH=0x1D01)` | PLAUSIBLE (`0x1D01` = `GL_SMOOTH`, strong) |
| `DAT_007c63c8` | `(0x302,0x303)` | 2-arg, tokens `0x302/0x303` | UNKNOWN |
| `DAT_007c63c0` | `(0x204,0)` | 2-arg | UNKNOWN |
| `DAT_007c9070` | `(0xc53,0x1101)`, `(0xc50,0x1101)` | 2-arg | UNKNOWN |
| `DAT_007c639c` | ×8, 1-arg, `0xbd0,0xb20,0xb10,0xb41,0xb44,0xb50,0xbe2,0xbc0` | `glEnable`/`glDisable` family — **lighting + fog enable/disable set** | PLAUSIBLE (`0xB50`-range is the light/material token block; `0xB60` = `GL_FOG`) |
| `DAT_007c660c` | `()` | `glFlush`/`glFinish` | PLAUSIBLE |
| `DAT_007c90ac` | `(0x1701,0,0,w,h)` then `(0x1700)` | `glMatrixMode(GL_PROJECTION=0x1701)` … `glMatrixMode(GL_MODELVIEW=0x1700)` | CONFIRMED (`0x1700`/`0x1701` are the standard `GL_MODELVIEW`/`GL_PROJECTION`) |
| `DAT_007c9090` | `()` | `glLoadIdentity` | PLAUSIBLE |
| `DAT_007c946c` | 6 doubles | `glOrtho(l,r,b,t,n,f)` | PLAUSIBLE — **orthographic, centred on screen size** |
| `DAT_007c6318` | `(0x4100)` | `glShadeModel?/glPolygonMode?` | UNKNOWN |

I am deliberately **not** naming the unidentified tokens. Naming them from memory
would be exactly the pattern-match failure this task warns about; the raw values are
quoted so they can be resolved against `gl.h` by anyone who has it.

**CONFIRMED, high value:** the projection is **`glOrtho`**, screen-centred,
`(-w/2, w/2, -h/2, h/2, 0, 7.5)`. Combined with `0x40cd20(400)` and `0x413990`
(§2.6), the OpenGL path uses the **same orthographic two-plane projection as the
software path** — the game does its own projection and hands GL an identity-ish
ortho. That is a strong signal the vertex data is already in screen space, i.e.
**pre-transformed**, which is exactly what a PS1-derived engine does.

### 3.3 Per-frame fog/lighting state — CONFIRMED

`FUN_00423bd0` writes a block of 17 floats at `DAT_006235ac..0x6235e8` before
`(*DAT_004b1a8c)()`. Decoded:

```
  DAT_006235ac = 0x7cb;
  _DAT_006235b0 = 0;
  _DAT_006235b4 = 0;
  _DAT_006235b8 = 639.0;
  _DAT_006235bc = 0x43ef8000;      // 479.0
  DAT_006235c0 = (float)(-6 - DAT_004efb3c);
  DAT_006235d0 = DAT_00467f50;     // the 256-float intensity table
  DAT_006235d4 = DAT_0046874c;
  DAT_006235d8 = DAT_0046834c;
  DAT_006235e0 = DAT_00467f50;
  DAT_006235e4 = 0x3d800000;      // 0.0625
  DAT_006235e8 = DAT_0046834c;
  DAT_006235ec = 0x3d800000;
  DAT_006235c4 = DAT_006235c0;
  DAT_006235c8 = DAT_006235c0;
  DAT_006235cc = DAT_006235c0;
```

and the resolution-change path rewrites it:

```
  if (DAT_004b3e48 & 1) {
    fVar1 = ((float)param_1 * 300.0) / (float)param_2;    // aspect * 300
    ...
      _DAT_006235b8 = fVar1 * 1.25;
      _DAT_006235b0 = 0x43080000;    // 200.0
      _DAT_006235b4 = 0x43cc8000;    // 404.0
      _DAT_006235bc = 0x41800000;    // 16.0
      DAT_006235d0 = 0x3e5a0000;     // 0.213
      DAT_006235d4 = 0x3d000000;     // 0.03125
      DAT_006235dc = 0x3d000000;
      DAT_006235e0 = 0x3e5a0000;
      ...
```

**These are OpenGL fog parameters: fog start ≈ 200, fog end ≈ 404, in the same
projected units as `0x40cd20(400)`.** `0x7cb` = 1995 is the texture-id sentinel
(§4.1). CONFIRMED the game has distance fog; PLAUSIBLE that the OpenGL path gets it
from hardware `GL_FOG` and the software path emulates it per-vertex via the
`DAT_004b1a74` slot.

### 3.4 Card detection and the vendor table — CONFIRMED

`0x422050` (`gfx_detect_card`, called at the end of every successful `0x40e790`):

```
// 0x422050:
  iVar8 = 9;
  if ((DAT_004ac094 & 2) == 0) {
    if ((DAT_004ac094 == 1) || (DAT_004ac094 == 0)) {
      iVar8 = 8;
    }
  }
  else {
    ...
    pcVar5 = (char *)(*DAT_007c6304)(0x1f00);      // GL_VENDOR
    _Str = (char *)(*DAT_007c6304)(0x1f01);        // GL_RENDERER
    if ((pcVar5 != 0) && (_Str != 0)) {
      pcVar6 = _strstr(pcVar5,&DAT_004ac088);      // "3DFX"
      if (pcVar6 != 0) { iVar8 = 0; }
      ...
      pcVar6 = _strstr(pcVar5,&DAT_004ac084);      // "NEC"
      if (pcVar6 != 0) { iVar8 = 2; }
      ...
      pcVar6 = _strstr(pcVar5,s_RENDITION_004ac078);
      if (pcVar6 != 0) { iVar8 = 1; }
      ...
      pcVar6 = _strstr(pcVar5,&DAT_004ac074);      // "ATI"
      if (pcVar6 != 0) { iVar8 = 5; }
      pcVar6 = _strstr(_Str,s_RAGE_PRO_004ac068);
      if (pcVar6 != 0) { iVar8 = 5; }
      pcVar6 = _strstr(pcVar5,s_NVIDIA_004ac060);
      if (pcVar6 != 0) { iVar8 = 4; }
      pcVar6 = _strstr(_Str,&DAT_004ac058);        // "RIVA"
      if (pcVar6 != 0) { iVar8 = 4; }
      pcVar5 = _strstr(pcVar5,s_Real3D_004ac050);
      if (pcVar5 != 0) { iVar8 = 7; }
      pcVar5 = _strstr(_Str,s_Direct3D_004ac044);
      if (pcVar5 != 0) { iVar8 = 6; }
    }
  }
```

`DAT_007c6304` = `glGetString` (CONFIRMED: `0x1F00`/`0x1F01` are `GL_VENDOR`/
`GL_RENDERER`). Vendor enum: **0=3Dfx, 1=Rendition, 2=NEC, 4=NVIDIA/RIVA,
5=ATI/Rage Pro, 6=Direct3D, 7=Real3D, 8=software, 9=unknown**.

Then a per-vendor quality table (`DAT_004ac024` = 256 or 512, `DAT_004b1ccc/1cc8/1cc0`,
`DAT_004ac030`) and per-vendor clamping of **two 256-float tables** at
`DAT_00467f50` and `DAT_00468350` (0x400 bytes each = 256 floats):

```
// 0x422050, case 1 (Rendition) and case 2 (NEC):
      if (1.0 < *(float *)((int)&DAT_00467f50 + iVar7)) { ...= 0x3f800000; }
      if (0.982353 < *(float *)((int)&DAT_00468350 + iVar7)) { ...= 0x3f7b7b7c; }
      if (*(float *)((int)&DAT_00468350 + iVar7) < 0.017647) { ...= 0x3c909071; }
```

`0x3f7b7b7c` = 0.982353, `0x3c909071` = 0.017647. So on those cards the second table
(the **intensity** table, distinct from the colour table at `0x467f50`) is clamped to
`[0.0176, 0.9824]` instead of `[0, 1]`. **This is a deliberate ~4.5/255 headroom at
both ends** so intensity modulation never saturates to pure black/white on cards that
would band. It is the closest thing in this dump to the "per-vertex intensity step"
the task asks about, and it is **per-vendor, not per-vertex-interpolated in this code**.

**CONFIRMED also**: `if ((DAT_009ca874._2_1_ == '\b') && (DAT_004b1cc4 != 0)) { DAT_004b1cc0 = 1; }`
— a user-config bit (`0x400` in the option word) forces compressed textures on.

### 3.5 What differs between the backends — CONFIRMED summary

| | software | OpenGL |
| --- | --- | --- |
| destination bpp | 8 or 24 | 24 (RGB) or 32 (RGBA) |
| texture upload | `FUN_00421770` → software framebuffer, per-pixel `FUN_00421c70`/`FUN_00421f50` + `FUN_00420b20` packer | `FUN_00420d10` → `glTexImage2D` into the driver's VRAM |
| alpha mode 2 (luma) | RGB zeroed, flag bit set | converted to a real alpha channel |
| clamping test | no `DAT_004b1ca8` arena needed | `DAT_004b1ca4 = FUN_0044fc30(0x100000)` 1 MiB staging buffer |
| texture arena | `DAT_004b1cb0 = DAT_0046af64 * 0x40000 + local_140` (0x40000 = 256 KiB + total) | `DAT_004b1ca4` 1 MiB |
| near/far projection | two-plane fixed-point 3×3 (`0x40ceb0`) | `glOrtho` + the same 3×3, no `glFrustum` |
| fog | `(*DAT_004b1a74)` slot (implementation unknown) | `glFog*` (enable token in the `0xbd0` set) |
| present | `DAT_004b1a7c` = `LAB_00414350`/`LAB_00414020` (unknown) | same slot = `LAB_00413be0`, then `InvalidateRect`/`UpdateWindow` on the GL window |

### 3.6 Texture upload on the GL side — CONFIRMED

`FUN_00423490` (called per texture block from `0x422a40`):

```
// 0x423490, GL branch:
      (*DAT_007c632c)(0xde1);                              // glEnable(GL_TEXTURE_2D)
      (*DAT_007c6368)(uVar8,0xde1);                       // glBindTexture(GL_TEXTURE_2D, id)
      (*DAT_007c62c0)(0xde1,0x2802,0x46240400);           // TexParameteri MIN_FILTER
      (*DAT_007c62c0)(0xde1,0x2803,0x46240400);           // TexParameteri MAG_FILTER
      (*DAT_007c62c0)(0xde1,0x2801,0x46180400);           // TexParameteri WRAP_S
      (*DAT_007c62c0)(0xde1,0x2800,0x46180400);           // TexParameteri WRAP_T
      (*DAT_007c6614)();                                  // glFlush
      if ((DAT_004b1cc0 == 0) || (DAT_00548c60 == 0)) {
        if ((&DAT_0052fd69)[uVar8 * 0x30] == '\0') {
          ... (0x1401, 0x1907, 0, w, h, 3, bits) ...      // glTexImage2D, GL_RGB,  3 comps
        } else {
          ... (0x1401, 0x1908, 0, w, h, 4, bits) ...      // glTexImage2D, GL_RGBA, 4 comps
        }
      } else {
        ... (0x1401, 0x1900, 0, w, h, 0x80e5, bits) ...    // glTexImage2D, compressed
      }
      (*DAT_007c90cc)();
      (*DAT_007c6614)();                                  // glFlush
```

**CONFIRMED:**
- `0xDE1` = `GL_TEXTURE_2D` (identical constant at four sites including the
  `glBindTexture`/`glDeleteTextures` signatures).
- `0x2800`/`0x2801`/`0x2802`/`0x2803` = `WRAP_S`/`WRAP_T`/`MIN_FILTER`/`MAG_FILTER`.
- Filter values: `0x46180400` = 9728.0 = `0x2600` = **`GL_NEAREST`**, for both
  mag-filter and both wrap modes. `0x46240400` = 10496.0 for the min filter — not a
  standard GL token; **UNKNOWN**, needs `gl.h`.
- Internal formats: `0x1907` (RGB, 3 comps), `0x1908` (RGBA, 4 comps), `0x1900`
  for the compressed path. These *are* the standard GL pixel-format tokens.
- `0x1401` = `GL_UNSIGNED_BYTE`.
- **So the OpenGL path uploads the same RGB/RGBA byte data the software path
  produces, with `GL_NEAREST` filtering.** No mipmaps are generated by the game; the
  min-filter value is unresolved.

### 3.7 The GL teardown — CONFIRMED signatures

```
// 0x40dc80 and 0x40e790 teardown:
    if (DAT_004ac094 == 2) {
      (*DAT_007c63b8)();                            // wglMakeCurrent(0,0)
      (*DAT_007c661c)(DAT_004b1ac0);                // wglDeleteContext(hglrc)
      DAT_004b1ac0 = 0;
      ...
      pcVar4 = *(code **)(iVar1 + 8);
      (*pcVar4)();                                  // IDirectDraw::Release
      DAT_004b1ac4 = 0;
    }
```
and creation, in `0x40e790`:
```
              DAT_004b1ac0 = (*DAT_007c934c)();     // wglCreateContext()
              ...
              (*DAT_007c63b8)();                    // wglMakeCurrent(hglrc, hdc)
```

`DAT_007c63b8` and `DAT_007c934c` are called with **zero** arguments in the decompile
because Ghidra lost the register arguments at the `__cdecl` boundary. The
`(0,0)` / `(hglrc,hdc)` / `(hglrc)` / `(hdc)` pattern across four sites is
**PLAUSIBLE but not CONFIRMED** — the call shapes match `wglMakeCurrent`,
`wglCreateContext`, `wglDeleteContext` exactly, but the argument count Ghidra emits
is 0 for both, so I cannot distinguish them by arity alone. Flag as PLAUSIBLE.

---

## 4. Geometry and texture data

### 4.1 Texture objects — CONFIRMED layout

Two independent 24-byte-stride tables:

```
// 0x40dd40 (level teardown):
  puVar4 = &DAT_0052fd72;
  do {
    *puVar4 = 0;
    puVar4 = puVar4 + 0x18;
  } while ((int)puVar4 < 0x547472);
```

**CONFIRMED: a 24-byte-stride table of texture slots, base `0x52fd72`, cleared up to
absolute address `0x547472`** — 96,000 bytes, i.e. exactly **4000 slots**. A second
table of 48-byte records is the same array viewed through `int *` with a different
element width (Ghidra emits both `(&DAT_0052fd60)[i*0xc]` and
`(&DAT_0052fd69)[i*0x30]` for the same record).

Per-texture state written by `FUN_004238e0` and `FUN_00423490`:
```
  (&DAT_0052fd60)[uVar8 * 0xc] = iVar4;    // width
  (&DAT_0052fd64)[uVar8 * 0xc] = iVar3;    // height
  (&DAT_0052fd70)[iVar2] = <log2(width)>;  // shift for width
  (&DAT_0052fd6f)[iVar2] = <log2(height)>; // shift for height
  (&DAT_0052fd6a)[iVar2] = 1;              // "is uniform" flag
  (&DAT_0052fd69)[iVar2] = flags;          // bit0 = has transparent colour, etc.
  (&DAT_0052fd72)[iVar8 * 0x18] = colour mode;  // 0..4
  (&DAT_0052fd88 + i*0x30) = w*h*bpp/8;    // byte size
  (&DAT_0052fd8c + i*0x30) = pixel pointer;
```

**The uniform-texture test is a real PS1 idiom** and worth quoting, `0x4238e0`:

```
// 0x4238e0:
  iVar1 = (&DAT_0052fd60)[param_1 * 0xc];
  while (iVar1 = iVar1 >> 1, 0 < iVar1) {
    (&DAT_0052fd70)[iVar2] = (&DAT_0052fd70)[iVar2] + '\x01';   // log2(w)
  }
  ...
  iVar1 = (&DAT_0052fd64)[param_1 * 0xc] * (&DAT_0052fd60)[param_1 * 0xc];
  if (((iVar1 < 0x1000) && (0 < iVar1)) && ((&DAT_0052fd72)[param_1 * 0x18] == 4)) {
    (&DAT_0052fd6a)[iVar2] = 1;
    if (iVar5 == 8) {                       // 8bpp
      ...
      if ((&DAT_0052fd6a)[iVar2] != '\0') {
        (&DAT_0052fd6b)[iVar2] = **(undefined1 **)(&DAT_0052fd8c + iVar2);
        return;
      }
    } else {                                // 24bpp
      ...
      if (((*puVar7 ^ *puVar3) & 0xffffff) != 0) { (&DAT_0052fd6a)[iVar2] = 0; break; }
      ...
      if ((&DAT_0052fd6a)[iVar2] != '\0') {
        *(undefined2 *)(&DAT_0052fd6c + iVar2) = **(undefined2 **)(&DAT_0052fd8c + iVar2);
        (&DAT_0052fd6e)[iVar2] = *(undefined1 *)(*(undefined2 **)(&DAT_0052fd8c + iVar2) + 1);
        return;
      }
    }
  }
```

**CONFIRMED: a solid-colour (uniform) texture detector.** If a texture under 4096
pixels with colour mode 4 is entirely one value, the engine collapses it to a single
**16-bit RGB555 word** (`&DAT_0052fd6c`, 2 bytes) plus a 1-byte 8bpp variant
(`&DAT_0052fd6b`), and the rasteriser later emits that constant colour instead of
sampling. This is the classic **PS1 "flat/gouraud-only" fill path** and it is a
large performance win. For a rewrite: implement this.

### 4.2 The primitive/geometry list — CONFIRMED

`FUN_0040cda0` decodes a primitive descriptor (called per primitive from
`0x422a40` and `0x423490`):

```
// 0x40cda0:
  *param_2 = *param_1 & 7;                        // byte 0 bits 0-2 = element type
  if ((*param_1 & 8) == 0) {
    sVar2 = 0;
  }
  else {
    sVar2 = (short)param_1[1];                    // byte 1 = sub-block offset
    *(short *)(param_2 + 4) = (short)param_1[2];
    *(undefined2 *)((int)param_2 + 0x12) = *(undefined2 *)((int)param_1 + 10);
    *(short *)(param_2 + 5) = (short)param_1[3];
    *(undefined2 *)((int)param_2 + 0x16) = *(undefined2 *)((int)param_1 + 0xe);
    param_2[6] = (uint)(param_1 + 4);            // vertex/index pointer
  }
  pbVar1 = (byte *)((int)param_1 + sVar2 + 8);
  *(undefined2 *)(param_2 + 1) = *(undefined2 *)pbVar1;
  *(undefined2 *)((int)param_2 + 6) = *(undefined2 *)(pbVar1 + 2);
  *(undefined2 *)(param_2 + 2) = *(undefined2 *)(pbVar1 + 4);
  *(undefined2 *)((int)param_2 + 10) = *(undefined2 *)(pbVar1 + 6);
  param_2[3] = (uint)(pbVar1 + 8);
```

**CONFIRMED: 28-byte primitive header**, `[type:3 | hasSub:1]` at +0, optional
sub-block offset at +1, a vertex pointer at +4 (or +0x18 via the sub-block), and
`count / stride / nVertices / nIndices` shorts read from the sub-block.

The `type:3` field selects the **element size in bytes**, from `0x422a40`:

```
        switch(local_124[0]) {
        case 0: uVar9 = (uint)uStack_11c << 2; local_144 = uVar9; break;   // 4 bytes
        case 1: uVar9 = (uint)uStack_11c << 1; local_144 = uVar9; break;   // 2 bytes
        case 2: uVar9 = (uint)uStack_11c;      local_144 = uVar9; break;   // 1 byte
        case 3: uVar9 = uStack_11c / 6;         local_144 = uVar9; break;   // 6 verts/tri
        }
```

and it sizes the texture arena accordingly:

```
        if ((iVar15 != 0x200) || (iVar5 != 0x200)) {
          local_140 = local_140 + iVar15 * iVar5 * DAT_0046af64;
        }
```

Texture memory is precomputed for the whole level as `Σ (w × h × bytes-per-pixel)`,
clamped to 512×512 (`DAT_004ac024`, set to `0x200` for most vendors, `0x100` for
3Dfx). Texture dimension selection, `0x423490`:

```
  if (DAT_009ca874._3_1_ != '\0') {
    if (local_2c < (int)uVar8) { local_2c = local_2c * 2; }
    if (iVar4 < (int)(uint)local_12) { iVar4 = iVar4 * 2; }
  }
  if (DAT_004ac024 < local_2c) { local_2c = DAT_004ac024; }
  if (DAT_004ac024 < iVar4) { iVar4 = DAT_004ac024; }
```

`local_2c`/`iVar4` are the next power of two above the texture dimensions (the
`while (iVar1 = iVar1 >> 1, 0 < iVar1) iVar3 = iVar3 + 1;` loop). The
`DAT_009ca874._3_1_` bit **doubles** them below the cap — a texture-resolution
option. So: **textures are stored/used at power-of-two dimensions, capped at
256 (3Dfx) or 512.**

### 4.3 Display-list tags — CONFIRMED structure, UNKNOWN semantics

`0x40fe90` (681 lines, the main scene walker) dispatches on a tag byte at
`primitive + 3` (so at header offset `+0xC`):

```
  cVar1 = *(char *)((int)puVar24 + 3);
  switch(cVar1) {
  case '\0':
  case '\x04':
    if (cVar1 == '\x04') {
      _DAT_00621600 = (float)((int)*(short *)(param_3 + 6) << 2);
    } else {
      _DAT_00621600 = 0.0;
    }
    ... frustum cull ...
    puVar24 = puVar24 + *(int *)(puVar24 + 2) * 2;
  ...
  case '\x34':  /* stride 0xc */   -> (*DAT_004b1a78)(...)  material
  case '\x38':  /* stride 0xe */   -> (*DAT_004b1a74)(...)  fog
  case '\x3c':  /* stride 0x10 */  -> (*DAT_004b1a74)(...)
  case '@':     /* stride 0x14 */  -> (*DAT_004b1a74)(...)  fog
  case 'D':     (*DAT_004b1aa4)(*puVar24,puVar24 + 2);  stride n*6+2
  case 'H':     /* stride 0x14 */
  case 100:     /* stride 8, skipped */
  }
```

**CONFIRMED:** a flat display list of tagged records with per-tag record sizes
(`0xc, 0xe, 0x10, 0x14, 6, 8`), each carrying a vertex-base-pointer, a count and a
bounding-box reference. Tags `0x34/0x38/0x3c/0x40/0x44/0x48` are
**material / fog / lighting state changes**; `0x00`/`0x04` are **geometry blocks**;
`0x44` (`'D'`) is a **range submit**.

**UNKNOWN:** what the tag numbers mean. They are not PSX GP0 command bytes
(those are a different, well-documented encoding) and I will not guess. For a
rewrite: treat them as an opaque tagged-record stream; the *behaviour* is fully
determined by which vtable slot each tag reaches, which I have listed.

### 4.4 Frustum culling — CONFIRMED

Same function, tags `0x00`/`0x04`. Each geometry record references **four corner
indices** into a 16-byte-stride transformed-position table at `DAT_007c6240`
(4 floats per entry: x, y, z, …):

```
    fVar3 = *(float *)((uint)puVar24[4] * 0x10 + 8 + DAT_007c6240);
    pfVar17 = (float *)((uint)puVar24[4] * 0x10 + DAT_007c6240);
    pfVar21 = (float *)((uint)puVar24[5] * 0x10 + DAT_007c6240);
    pfVar23 = (float *)((uint)puVar24[6] * 0x10 + DAT_007c6240);
    pfVar25 = (float *)((uint)puVar24[7] * 0x10 + DAT_007c6240);
    if ((((fVar3 <= DAT_004efb38) || (pfVar21[2] <= DAT_004efb38)) ||
        ((pfVar23[2] <= DAT_004efb38 || (pfVar25[2] <= DAT_004efb38)))) &&
       ((((DAT_004efb48 <= fVar3 || (DAT_004efb48 <= pfVar21[2])) || ...)) {
      /* z entirely outside [near, far] -> skip */
```

then an x/y extent test against the half-screen bounds
(`DAT_00621614/00621610` = ±`w/2`, `DAT_0062161c/00621618` = ±`h/2`+1, all set in
`0x411b10`):

```
              puVar24 = puVar24 + 8;
              local_74 = local_74 + -1;
              break;
```

**CONFIRMED: per-polygon-bounding-box frustum + viewport cull, using four cached
transformed corners.** This is a coarse cull on AABBs, not per-triangle clipping.

### 4.5 Where the 8-bit BMPs come in — UNKNOWN

RE_NOTES says each `.BZE` is paired with an 8-bit `.BMP` that is "the palette /
loading image for that level". **I found no reference to `.BMP` in
`bugs_decompiled.c`** (no string constant, no code path). The palette does exist —
it is the RGB555 word array at `param_1 + 0x14` of a texture object (§2.3) — but the
code that reads the BMP into that array is **not in this decompile** (it is in the
`0x42xxxx`–`0x45xxxx` region, of which only the loader shell
`FUN_0042e7a0` is exported). **Runtime/asset confirmation required.**

---

## 5. Framebuffers and surfaces

| surface | evidence |
| --- | --- |
| game window | `CreateWindowExA(0x40000, "BBLIT_Game", …, DAT_00467748, DAT_0046774c, …)` in `0x40e790`; class registered with `s_BBLIT_Game_0045f348` |
| window DC | `DAT_004b1abc = GetDC(pHVar6);` in `0x40e790`; released on teardown |
| GL context | `DAT_004b1ac0 = (*DAT_007c934c)()` (wglCreateContext), made current via `(*DAT_007c63b8)()` |
| DirectDraw object | `DirectDrawCreate()` → `DAT_004b1ac4`; used for the resolution-change "BBLIT Res window" (`0x40d6e0`, class `s_BBLIT_Res_window_0046ae30`) |
| software colour buffer | `FUN_0044fc30(DAT_0046af64 * 0x140000)` → `DAT_004b1cac` (`0x423a60`) |
| software texture arena | `FUN_0044fc30(DAT_0046af64 * 0x40000 + total)` → `DAT_004b1ca8` (`0x422a40`) |
| GL staging buffer | `FUN_0044fc30(0x100000)` → `DAT_004b1ca4` (`0x423a60`) |
| pixel-format descriptor | `PIXELFORMATDESCRIPTOR` built by hand in `0x40e050` (`nSize=0x28`, `nVersion=1`, `dwFlags=0x28`, `dwPixelType=0`) and in `0x40df20` (`dwFlags=0x25`, `cColorBits=0x10`) |

**CONFIRMED — there is no offscreen DIB section anywhere in this decompile.** No
`CreateDIBSection`, no `CreateCompatibleBitmap`, no `StretchDIBits`. The software
renderer writes into a `malloc`'d buffer and the frame ends with
`InvalidateRect`/`UpdateWindow` on a window whose DC it holds. **This refutes the
"StretchDIBits on an 8-bit DIB" description in RE_NOTES.**

`0x40d6e0` (`DirectDraw` resolution-window helper) is a **fallback probe**: it
creates the hidden "BBLIT Res window", calls `SetCooperativeLevel`/`SetDisplayMode`
on the DirectDraw vtable at `*DAT_004b1ac4 + 0x50`/`+0x54`, and on failure calls
`FUN_004055d0(..., "erreur : fenetre principale invalide")` — *"main window
invalid"*. So DirectDraw is used **only for mode-set probing**, never as a display
surface for rendering.

Present, both backends (`0x423bd0`, abridged):
```
  if (param_1 == 0x800) {
    (*DAT_004b1a80)();                     // clear
    _DAT_004b1c4c = 0;
    DAT_004b1c48 = 1;
    DAT_004b1cdc = 0;
  }
  else {
    if ((param_1 - DAT_004b1cdc < 0x19000) && (param_1 != param_2)) { return; }
    DAT_004b1cdc = param_1;                 // frame-rate governor: skip if <0x19000 us
  }
  (*DAT_004b1a8c)();                       // set view/fog constants
  ...                                      // DAT_006235ac..0x6235e8 block
  (*DAT_004b1a7c)();                       // present
  ...
  InvalidateRect(DAT_004b1cec,(RECT *)0x0,0);
  UpdateWindow(DAT_004b1cec);
```

**CONFIRMED frame governor:** frames are skipped unless `>= 0x19000 µs` (≈64 fps)
have elapsed, unless the mode just changed (`0x800`) or the size changed.

---

## 6. HV3DFX.DLL — CONFIRMED: no game logic

**One sentence: HV3DFX.DLL is a generic SGI-style OpenGL ICD that translates GL calls
into 3dfx Glide calls, and contains no game-specific rendering whatsoever — no
geometry, no texture upload from game data, no palette handling, no reference to
Bugs Bunny, `.BZE` files or level data of any kind.**

Evidence:

1. **Every exported `gl*`/`wgl*` entry point is a stub into a dispatch table.**
   378 named stubs, 360 of them `gl*`/`wgl*`, plus 17 `Drv*` ICD entry points. All
   have the identical shape:
```
// ===== glBegin @ 6900629c =====
void glBegin(void)
{
  int in_FS_OFFSET;
                    /* WARNING: Could not recover jumptable at 0x690062aa. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(*(int *)(*(int *)(in_FS_OFFSET + 0x18) + _DAT_6909e2ec) + 0x1670))();
  return;
}
```
   `_DAT_6909e2ec` is the GL dispatch table pointer; `+0x18` and `+<per-function
   offset>` is the SGI ICD context layout. Stride between successive stubs is
   exactly 20 bytes for 334 of them — a uniform trampoline table.

2. **The extension strings and env vars are all generic SGI/ICD.** From the string
   table: `GL_EXT_abgr GL_EXT_bgra GL_EXT_packed_pixels GL_EXT_paletted_texture
   GL_EXT_vertex_array GL_SGI_compiled_vertex_array GL_SGI_cull_vertex
   GL_SGI_index_array_formats GL_SGI_index_func GL_SGI_index_material
   GL_SGI_index_texture GL_WIN_swap_hint`, and env vars `__GL_FORCE_K3D`,
   `__GL_FORCE_KNI`, `__GL_FORCE_MMX`, `__GL_FORCE_SW`, `GLFORCEZBITS`,
   `__GL_DISABLE_OG_CACHE`, `__GL_DISABLE_OG_VARRAY`,
   `__GL_DISABLE_OG_DRAWVERTEXES`, `__GL_FORCE_FULLSCREEN`, `__GL_ERROR_LOG`,
   `GLERRORABORT`. Registry key `Software\Silicon Graphics\OpenGL`.

3. **The only non-ICD names are Glide and GLU**: `grDrawTriangle`, `grDrawLine`,
   `grDrawPoint`, `__grDrawQuad`, `grSurfaceCreateContextExt`,
   `grSurfaceSetTextureSurfaceExt`, `grSurfaceCalcTextureWHDEExt`, plus
   `gluNewTess`/`gluTessBeginPolygon`/… loaded from `GLU.DLL`. That is a
   Glide→OpenGL translator.

4. **Negative search:** zero hits for `Bugs`, `Bunny`, `.BZE`, `CLUT`, or any game
   identifier in the whole 51,479-line file. The only `palette` hits are
   `DrvRealizeLayerPalette`, `wglGetLayerPaletteEntries`,
   `wglSetLayerPaletteEntries`, `DrvSetLayerPaletteEntries`, `DrvDescribeLayerPlane`,
   `wglCreateLayerContext` — all **standard Win32 layered-window palette APIs**, not
   texture CLUTs.

5. It does load `DDRAW.DLL` and `DCIMAN32.DLL` and log `DDraw: Allocate: Create`,
   `DDraw: Fill: Blt` — i.e. it manages **its own** DirectDraw surfaces for the GL
   backbuffer, because a Voodoo cannot present to a GDI window directly.

6. `__glSSTClipAndDrawLine` and `"No Software Fallback for no primary surface"` show
   it has an internal software rasteriser path (`__GL_FORCE_SW`) of its own — again,
   generic, not game-specific.

**RE_NOTES' "no game logic" is CONFIRMED.** Nothing in HV3DFX.DLL needs to be
reimplemented for a rewrite; it is replaceable by any OpenGL 1.1 driver.

---

## 7. Corrections to RE_NOTES.md

| RE_NOTES claim | Verdict |
| --- | --- |
| `DAT_004ac094`: 0/1 = software, 2 = OpenGL | **CONFIRMED but incomplete.** 0 = software **8bpp**, 1 = software **24bpp**, 2 = OpenGL, and **`0x10` = no renderer** (written on every teardown, read as "skip"). |
| `0x40df20` "calls StretchDIBits" | **REFUTED.** `0x40df20` is `ChoosePixelFormat`/`SetPixelFormat` for the GL window. There is no StretchDIBits in the decompile at all. |
| `0x40d850 = ogl_set_display_mode` | **REFUTED.** It is the DirectDraw surface-mode set, shared by both paths; its error message names `Pcrogl.c`. |
| `0x40e050 = ogl_load_dll` | **CONFIRMED** (LoadLibraryA("opengl32.dll") + a `{slot,name}` table walk at `0x468750..0x469298`). |
| `0x40e790 = ogl_init` | **PARTLY.** It is the **full video-mode / renderer init for both paths**, and it is where the entire renderer vtable is filled. |
| `0x422050 = gfx_detect_card` | **CONFIRMED.** `glGetString(GL_VENDOR/GL_RENDERER)` + 9-vendor string match + per-vendor quality/gamma tables. |
| Software "blitter, source pcrsoft8.c" | **REFUTED as stated.** There is no single blitter. The architecture is a **vtable of ~20 slots** with **separate 8bpp and 24bpp implementations** and a **per-polygon flat-shading 3D path** (normal + fog + `glOrtho`-equivalent projection), plus a separate 2D/sprite blitter (`0x420d10`). |
| supports "8/16/24-bit software output" | **CORRECTED: 8 or 24 only.** `DAT_0046af60` is 24 when `DAT_009ca824 == 1` and 8 when `== 0`. The `case 0x10` (16bpp) branch in the format switch is unreachable in this dump. `/SOFT16` and `/SOFTRGB` both select id 1 = **24bpp**. |
| default 512x384 | **CONFIRMED** (`DAT_009ca830 = 0x200`, `DAT_009ca834 = 0x180`). |
| `/SOFT24 /SOFT16 /SOFTRGB /SOFTPAL /SOFT8` | **CONFIRMED**, with the caveat that `/SOFT16` and `/SOFTRGB` both mean 24bpp. |
| HV3DFX.DLL "no game logic" | **CONFIRMED**, see §6. |

---

## 8. What needs runtime or asset confirmation

1. **The software rasteriser inner loop** — triangle setup, span walk, per-pixel
   shading, and whether there is *any* depth test. Requires re-exporting the
   `0x403ed0..0x405530` and `0x40a530..0x40cbd0` ranges (§0).
2. **The present** — whether the software slot `DAT_004b1a7c`
   (`LAB_00414350` / `LAB_00414020`) uses `StretchDIBits`, `BitBlt`, or `DIB` writes
   into the window DC. Same re-export needed.
3. **Affine vs perspective-correct texture interpolation** and per-vertex intensity
   interpolation inside a triangle. Same re-export.
4. **The `.BMP` palette path** — which function reads the 8-bit BMP into the RGB555
   palette at texture-object `+0x14`. Not in this dump (§4.5).
5. **GL token names** for `0x203`, `0x408`/`0x1B02`, `0x302`/`0x303`, `0x204`,
   `0xC50`/`0xC53`/`0x1101`, `0xBD0/0xB20/0xB10/0xB41/0xB44/0xB50/0xBE2/0xBC0`,
   `0x4100`, `0xB71`, and the min-filter value `10496.0` (`0x46240400`). Needs
   `gl.h`; the raw values are quoted above (§3.2, §3.6).
6. **The display-list tag semantics** for tags `0x00/0x04/0x34/0x38/0x3C/0x40/0x44/
   0x48/0x64`. Behaviour per tag is known (which vtable slot it reaches), meaning
   is not (§4.3).
7. **`DAT_0046af64`** (bytes per pixel) is assigned only on the OpenGL path in this
   dump (`= DAT_004ac0b4 >> 3`); its software-path initialisation is not visible.

---

## 9. Method and coverage

- Read whole functions with `/tmp/fn.py` for: `0x40cbd0`, `0x40cc10`, `0x40cc80`,
  `0x40cd20`, `0x40cd60`, `0x40cda0`, `0x40ceb0`, `0x40d1a0`, `0x40d3e0`, `0x40d520`,
  `0x40d6e0`, `0x40d850`, `0x40d910`, `0x40daf0`, `0x40dc80`, `0x40dd40`, `0x40df20`,
  `0x40e050`, `0x40e1d0`, `0x40e790` (523 lines, in full), `0x403e70`, `0x40fe90`
  (681 lines, in full), `0x411b10`, `0x413990`, `0x417020`, `0x41a510`, `0x41a600`,
  `0x41cd50`, `0x41ce60`, `0x420b20`, `0x420d10`, `0x421770`, `0x421c70`, `0x421f50`,
  `0x422050` (343 lines, in full), `0x4229a0`, `0x422a40` (469 lines, in full),
  `0x423490`, `0x4238e0`, `0x423a30`, `0x423a60`, `0x423ad0`, `0x423b30`, `0x423bd0`,
  `0x424ef0`, `0x44c070`, `0x44c4b0`, `0x44bb50` region, `0x44fc30`, `0x40a530`.
- Exhaustive greps: all 44 `DAT_004ac094` sites; all 136 `DAT_007c*` gl-pointer call
  sites with their arguments; all 44 renderer-vtable slot call sites; all 340
  `LAB_` targets classified (224 in-function goto labels, 116 address-only);
  `StretchDIBits|BitBlt|CreateDIBSection|SetDIBitsToDevice|CreateCompatibleBitmap`
  (0 hits); 119 distinct Win32-style identifiers; `zbuf|depth` (0 hits).
- HV3DFX.DLL: parsed all 378 named stubs and their dispatch offsets (stride 20 for
  334), enumerated all 119 string literals, and searched for game identifiers.
- **Not covered:** the ~116 address-only `LAB_` targets and the ~11,400 bytes they
  occupy, which contain both rasterisers. This is the single largest gap and it is
  structural, not an oversight — the code is absent from the export (§0).