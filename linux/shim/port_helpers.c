/* port_helpers.c -- small helpers the decompile-to-C transform emits. */
#include "winshim.h"
#include <string.h>

void data_wr3(void *base, long off, unsigned long v) {
    unsigned char *p = (unsigned char *)base + off;
    p[0] = (unsigned char)(v);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
}
unsigned long data_rd3(void *base, long off) {
    const unsigned char *p = (const unsigned char *)base + off;
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16);
}
/* Ghidra renders cross-function label references as &LAB_x; the port resolves
 * them through this table (filled by linux/fixups.c). */
void *lab_addr(const char *name);
void *lab_addr(const char *name) { (void)name; return 0; }

/* Ghidra occasionally names an unmapped register as data (register0x...);
 * the single site in this binary uses it as a scratch pointer. */
void *reg_scratch;

/* Ghidra renders a bit-cast of a float expression to a pointer on functions with
 * broken return paths; keep the bit pattern.  f-variant takes a float, d-variant
 * a double, so the returned bits are the original variable's bits. */
unsigned long flt_bitsf(float v);
unsigned long flt_bitsf(float v) {
    unsigned int u;
    __builtin_memcpy(&u, &v, sizeof u);
    return u;
}
unsigned long flt_bitsd(double v);
unsigned long flt_bitsd(double v) {
    unsigned long u;
    __builtin_memcpy(&u, &v, sizeof u);
    return u;
}
