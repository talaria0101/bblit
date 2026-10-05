/* port_main.c -- Linux entry for the ported game.
 *
 * bblit_port_init() maps the original PE image (data, rdata, imports' thunk
 * tables) at its fixed base 0x400000, plants jump trampolines at the original
 * .text function addresses so the image's pointer slots and vtables reach the
 * ported 64-bit functions, and widens the 4-byte pointer slots to 8-byte
 * pointers.  After that, winmain is the game's WinMain.
 */
#include "data_syms.h"
#include "bblit_game.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    bblit_port_init();
    /* WinMain(hInst=NULL-ish, hPrev=NULL, lpCmdLine=NULL, nShowCmd=SW_SHOW) */
    return (int)winmain(0, 0, 0, 1);
}
