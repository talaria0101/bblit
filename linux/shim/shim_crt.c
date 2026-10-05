/* shim_crt.c -- VC++6 CRT support replaced by native implementations. */
#include "winshim.h"
#include <math.h>

int32_t vc6_ftol(double v) {
    /* x87 ftol: truncate toward zero, 32-bit wraparound */
    return (int32_t)(long long)(v < 0 ? v - 0.0 : v);
}

/* 64-bit math helpers VC++6 emitted as calls; x86-64 does them natively. */
longlong __allmul(longlong a, longlong b) { return a * b; }
longlong __alldiv(longlong a, longlong b) { return a / b; }
longlong __allrem(longlong a, longlong b) { return a % b; }
ulonglong __aulldiv(ulonglong a, ulonglong b) { return a / b; }
ulonglong __aullrem(ulonglong a, ulonglong b) { return a % b; }
longlong __allshl(longlong a, int shift) { return a << shift; }
longlong __allshr(longlong a, int shift) { return a >> shift; }
ulonglong __aullshr(ulonglong a, int shift) { return a >> shift; }

/* CRT string functions that were statically linked into the exe */
#include <string.h>
char *_strstr(const char *h, const char *n) { return (char *)strstr(h, n); }
char *_strrchr(const char *s, int c) { return (char *)strrchr(s, c); }
char *_strncpy(char *d, const char *s, size_t n) { return strncpy(d, s, n); }
int __strcmpi(const char *a, const char *b) { return strcasecmp(a, b); }
int _stricmp(const char *a, const char *b) { return strcasecmp(a, b); }
