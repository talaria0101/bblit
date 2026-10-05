/* ghidra_types.h -- base types and helpers so Ghidra decompiler output compiles
 * on a 64-bit Linux host. Part of the bblit Linux port (see linux/README.md).
 *
 * The original binary is PE32 i386.  In Ghidra's output model:
 *   undefined      = 1 byte
 *   undefined2/4/8 = 2/4/8 byte opaque scalar
 * All are modelled here as exact-width unsigned types; the game code treats
 * them as raw storage.
 */
#ifndef BBLIT_GHIDRA_TYPES_H
#define BBLIT_GHIDRA_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef uint8_t  undefined;
typedef uint8_t  undefined1;
typedef uint8_t  byte;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef uint32_t undefined5;
typedef unsigned int int3;      /* Ghidra 3-byte scalar; modeled 32-bit here */
typedef unsigned int uint3;
typedef unsigned long long unkuint10;   /* Ghidra edge sizes seen in signatures */
/* x87 registers are 80-bit (10 bytes); a 64-bit view truncates fstpt stores */
typedef struct { uint64_t lo; uint16_t hi; } __attribute__((packed)) unkbyte10;
typedef uint8_t  unkbyte1;
typedef uint16_t unkbyte2;
typedef uint32_t unkbyte4;
typedef uint64_t unkbyte8;

typedef int8_t   int8;
typedef int16_t  int16;
typedef int32_t  int32;
typedef int64_t  int64;
typedef uint8_t  uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef unsigned char  uchar;
typedef long double    longdouble;
typedef long           LSTATUS;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;
typedef long long      longlong;
typedef unsigned long long ulonglong;

/* exact-width storage for generated data symbols (see data_syms.h) */
typedef uint8_t  data_u8;
typedef uint16_t data_u16;
typedef uint32_t data_u32;
typedef uint64_t data_u64;

/* Ghidra renders a read/write of a sub-record inside a symbol as
 * `sym._off_size_`; decomp2linux.py rewrites that to DATAPART(sym,off,size)
 * with size in bytes. */
#define DATAPART_PASTE2(a,b)  a##b
#define DATAPART_PASTE(a,b)   DATAPART_PASTE2(a,b)
#define DATAPART_UINT_1       uint8_t
#define DATAPART_UINT_2       uint16_t
#define DATAPART_UINT_4       uint32_t
#define DATAPART_UINT_8       uint64_t
#define DATAPART_UINT(size)   DATAPART_UINT_##size
#define DATAPART(base,off,size) \
    (*(DATAPART_UINT(size) *)((unsigned char *)&(base) + (ptrdiff_t)(off)))

/* Generic code pointer. Calls through vtables land here. */
/* Old-style unprototyped function pointer: lets every vtable call site
 * `(**(code **)vtbl_off)(obj, args...)` compile with its own arg list.
 * Build with -std=gnu17 (default on GCC 14) since C23 removed unprototyped fns. */
typedef long (*code)();
typedef void (*codev)();
typedef long (*codef_t)();
typedef void (*code_t)();

/* Ghidra casts a data address to `code *` when it has no better type. */
typedef void *(*ptr_code)(void);

/* ---- Ghidra CONCATxx helpers --------------------------------------------
 * Ghidra emits CONCATab(hi, lo) where a = total width, b = low-part width:
 * the low part occupies the low b bytes, the high part fills the rest.
 * Example CONCAT44(hi16, lo16) builds a 32-bit value.
 */
#define CONCAT11(b,a)  ((uint8_t)((uint8_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT21(b,a)  ((uint16_t)((uint16_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT22(b,a)  ((uint16_t)((uint16_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT31(b,a)  ((uint32_t)((uint32_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT32(b,a)  ((uint32_t)((uint32_t)(b) << 16 | (uint16_t)(a)))
#define CONCAT41(b,a)  ((uint32_t)((uint32_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT44(b,a)  ((uint32_t)((uint32_t)(b) << 16 | (uint16_t)(a)))
#define CONCAT81(b,a)  ((uint64_t)((uint64_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT84(b,a)  ((uint64_t)((uint64_t)(b) << 32 | (uint32_t)(a)))
#define CONCAT88(b,a)  ((uint64_t)((uint64_t)(b) << 32 | (uint32_t)(a)))
#define CONCAT61(b,a)  ((uint64_t)((uint64_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT62(b,a)  ((uint64_t)((uint64_t)(b) << 16 | (uint16_t)(a)))
#define CONCAT63(b,a)  ((uint64_t)((uint64_t)(b) << 24 | (uint32_t)(a)))
#define CONCAT52(b,a)  ((uint32_t)((uint32_t)(b) << 16 | (uint16_t)(a)))
#define CONCAT42(b,a)  ((uint32_t)((uint32_t)(b) << 16 | (uint16_t)(a)))
#define CONCAT43(b,a)  ((uint32_t)((uint32_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT34(b,a)  ((uint32_t)((uint32_t)(b) << 16 | (uint16_t)(a)))
#define CONCAT24(b,a)  ((uint32_t)((uint32_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT26(b,a)  ((uint32_t)((uint32_t)(b) << 16 | (uint16_t)(a)))
#define CONCAT28(b,a)  ((uint32_t)((uint32_t)(b) << 24 | (uint8_t)(a)))
#define CONCAT12(b,a)  ((uint16_t)((uint16_t)(b) << 8 | (uint8_t)(a)))
#define CONCAT13(b,a)  ((uint16_t)((uint16_t)(b) << 12 | (uint16_t)((a) & 0xFFF)))
#define CONCAT14(b,a)  ((uint16_t)((uint16_t)(b) << 12 | (uint16_t)((a) & 0xFFF)))
#define CONCAT16(b,a)  ((uint16_t)((uint16_t)(b) << 4 | (uint16_t)((a) & 0xF)))
#define CONCAT17(b,a)  ((uint16_t)((uint16_t)(b) << 8 | (uint16_t)((a) & 0xFF)))
#define CONCAT36(b,a)  ((uint32_t)((uint32_t)(b) << 16 | (uint16_t)(a)))
#define CONCAT38(b,a)  ((uint32_t)((uint32_t)(b) << 24 | (uint8_t)(a)))

/* SUBnnn(v) = sign-extended sub-field read; SEXT = sign extension */
#define SEXT44(v)     ((int32_t)(v))
#define SEXT88(v)     ((int64_t)(v))
#define SEXT84(v)     ((int64_t)(int32_t)(v))
#define SEXT48(v)     ((int32_t)(v))
#define ZEXT(para)    (para)

/* Ghidra SUBab(v[,pad]) extracts the low b bytes of v, sign-extended to a
 * bytes.  Emitted as functions so both 1-arg and Ghidra's 2-arg spellings work. */
static inline int8_t   SUB41(long long v, ...) { return (int8_t)v; }
static inline int16_t  SUB42(long long v, ...) { return (int16_t)v; }
static inline int32_t  SUB44(long long v, ...) { return (int32_t)v; }
static inline int8_t   SUB21(long long v, ...) { return (int8_t)v; }
static inline int16_t  SUB22(long long v, ...) { return (int16_t)v; }
static inline long long SUB87(long long v, ...) { return (long long)(v & 0xffffffffffffLL); }
static inline long long SUB84(long long v, ...) { return (long long)(int32_t)v; }
static inline long long SUB104(long long v, ...) { return (long long)(int32_t)v; }
static inline int16_t  SUB82(long long v, ...) { return (int16_t)v; }

/* Ghidra ROUND/SQRT helper comments materialize as these when x87 ops are
 * rendered textually; provide real ones. */
#include <math.h>
#define ROUND(v)  ((double)floor((v) + 0.5))
#ifndef SQRT
#define SQRT(v)   sqrt(v)
#endif

/* Ghidra float predicates: ABS(x) = |x| on the x87 long double, NAN(x) = the
 * "is NaN" comparison flag.  math.h's own NAN macro takes no argument. */
#define ABS(v)   fabsl(v)
#undef NAN
#define NAN(v)   isnan(v)

/* VC++6 float->int conversion helper (__ftol).  On x86-64 the native SSE
 * conversion replaces the x87 helper; decomp2linux.py rewrites call sites. */
int32_t vc6_ftol(double v);

#endif /* BBLIT_GHIDRA_TYPES_H */

#include <stdbool.h>
