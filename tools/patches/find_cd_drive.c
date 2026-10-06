/* find_cd_drive @ 00405850 -- hand-port maintained in tools/patches, spliced into
 * linux/bblit_game.c by tools/fix_loop.py.
 *
 * Hand ported, and only here, because the disc scan is the gate the whole
 * port has to get past.  Two reasons the generated form cannot be used as-is:
 *
 *  1. LP64 frame slots.  Ghidra models the i386 stack as 4-byte slots and
 *     routes each outgoing call argument through one:
 *         *(undefined1 **)(puVar6 + -0x28) = STR_CD_VOLUME_LABEL;
 *         *(undefined1 **)(puVar6 + -0x2c) = puVar6 + 0x100;
 *     On a 64-bit host that lvalue is 8 bytes wide, so it overwrites the
 *     neighbouring slot.  The store to -0x2c destroys the low half of the
 *     4-byte pointer stored at -0x28, and __strcmpi is then handed a stack
 *     address as its needle (measured: needle 0x00007ffd, never matching).
 *     The same overlap corrupts vlen (measured 32766, not 0x104) and the
 *     three DWORD out-pointers, which then clobber each other in turn.
 *     Consequence, measured: the scan never matches, winmain spins in the
 *     retry dialog, and the frame corruption eventually jumps to RIP=0
 *     (SIGSEGV after ~43k iterations).
 *
 *  2. Argument buffers addressed relative to the frame pointer.  The
 *     decompile passes GetDriveTypeA/GetVolumeInformationA pointers such as
 *     `puVar6 + 0x20` and `puVar6 + 0x1c`.  Those are frame slots holding
 *     arguments to a call the decompiler folded away, not strings: nothing
 *     ever writes "X:\" there, so the root path the API is handed is
 *     garbage.  The original builds it before the loop; the decompile does
 *     not show where.
 *
 * Both are fixed by calling the shim directly with real local buffers, which
 * is also what the rest of the surrounding hand fixes already do.
 */
/* cd_scan_once -- one pass of the disc check, shared by winmain's two
 * passes and by find_cd_drive: walk drive letters from STR_CD_DRIVE_ROOT to
 * 'z', keep the ones the shim reports as DRIVE_CDROM (5) whose volume
 * label is BBLIT, and publish the match in DAT_004b1928.  Returns 1 on
 * match, 0 if the walk finished with nothing.
 *
 * Hand ported.  See the header of tools/patches/find_cd_drive.c for the
 * full reason; the short version is that Ghidra routes every outgoing
 * argument of GetDriveTypeA/GetVolumeInformationA through a 4-byte i386
 * frame slot, and the generated LP64 code writes those slots 8 bytes wide,
 * so consecutive arguments overwrite each other.  Measured effect before
 * this fix: vlen arrived as 32766 instead of 0x104 and the BBLIT needle as
 * a stack address, so the comparison never matched. */
int cd_scan_once(void)
{
  char root[8];
  char label[0x104];
  char fsbuf[0x104];
  DWORD serial;
  DWORD maxlen;
  DWORD flags;
  char c;

  for (c = (char)STR_CD_DRIVE_ROOT; c <= 'z'; c = c + '\x01') {
    root[0] = c;
    root[1] = ':';
    root[2] = '\\';
    root[3] = '\0';
    if (GetDriveTypeA(root) != 5) {
      continue;
    }
    serial = 0;
    flags = 0;
    maxlen = 0x104;
    label[0] = '\0';
    fsbuf[0] = '\0';
    if (!GetVolumeInformationA(root, label, 0x104, &serial, &maxlen, &flags,
                              fsbuf, 0x104)) {
      continue;
    }
    if (__strcmpi(label, STR_CD_VOLUME_LABEL) != 0) {
      continue;
    }
    DAT_004b1928 = c;
    _DAT_004b1929 = (data_u32 *)(uintptr_t)(STR_CD_DATAS_DIR);
    _DAT_004b192d = (data_u32 *)(uintptr_t)(DAT_0045f358);
    DAT_004b1931 = (data_u32 *)(uintptr_t)(DAT_0045f35c);
    return 1;
  }
  return 0;
}

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 find_cd_drive(void) {
  char root[8];
  char label[0x104];
  char fsbuf[0x104];
  DWORD serial;
  DWORD maxlen;
  DWORD flags;
  UINT UVar2;
  BOOL BVar3;
  int iVar4;
  undefined4 uVar5;
  char c;

  uVar5 = 0;
  SetErrorMode(1);
  c = (char)STR_CD_DRIVE_ROOT;
  if ('z' < c) {
    SetErrorMode(1);
    return uVar5;
  }
  do {
    root[0] = c;
    root[1] = ':';
    root[2] = '\\';
    root[3] = '\0';
    UVar2 = GetDriveTypeA(root);
    if (UVar2 == 5) {
      serial = 0;
      flags = 0;
      maxlen = 0x104;
      label[0] = '\0';
      fsbuf[0] = '\0';
      BVar3 = GetVolumeInformationA(root, label, 0x104, &serial, &maxlen,
                                    &flags, fsbuf, 0x104);
      if (BVar3 != 0) {
        iVar4 = __strcmpi(label, STR_CD_VOLUME_LABEL);
        if (iVar4 == 0) {
          DAT_004b1928 = c;
          _DAT_004b1929 = (data_u32 *)(uintptr_t)(STR_CD_DATAS_DIR);
          _DAT_004b192d = (data_u32 *)(uintptr_t)(DAT_0045f358);
          DAT_004b1931 = (data_u32 *)(uintptr_t)(DAT_0045f35c);
          uVar5 = 1;
          SetErrorMode(1);
          return uVar5;
        }
      }
    }
    c = c + '\x01';
    if ('z' < c) {
      SetErrorMode(1);
      return 0;
    }
  } while( true );
}