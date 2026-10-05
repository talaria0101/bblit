/* winapi_stubs.c -- stub implementations for WinAPI calls reachable from the
 * decompiled game code.  Real behavior lands per-call as the port matures. */
#include "winshim.h"

BOOL GetVersionExA(LPOSVERSIONINFOA vi) {
    if (!vi || vi->dwOSVersionInfoSize < 20) return 0;
    vi->dwMajorVersion = 4;
    vi->dwMinorVersion = 0;
    vi->dwBuildNumber = 950;
    vi->dwPlatformId = 1; /* VER_PLATFORM_WIN32_WINDOWS */
    vi->szCSDVersion[0] = 0;
    return 1;
}
int LCMapStringW(LCID lcid, DWORD flags, LPCWSTR src, int srclen, LPWSTR dst, int dstlen) {
    (void)lcid; (void)flags;
    if (dst == 0) return srclen;
    int n = srclen < dstlen ? srclen : dstlen;
    for (int i = 0; i < n; i++) dst[i] = src[i];
    return n;
}
BOOL GetStringTypeW(DWORD type, LPCWSTR src, int srclen, LPWORD chartype) {
    (void)type; (void)src;
    for (int i = 0; i < srclen; i++) chartype[i] = 0;
    return 1;
}

/* VC6 CRT x87 error paths (FUN_00456557 / FUN_00456589 in BUGS.EXE).  Their
 * decompiled bodies are dropped as CRT by the generator; these stubs keep the
 * link.  Only reached on x87 stack-overflow/inexact error paths. */
long double __math_exit(void) { return 0; }
long double __startOneArgErrorHandling(void) { return 0; }
