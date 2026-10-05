#!/usr/bin/env python3
"""fix_loop.py -- drive gcc, parse its errors on linux/bblit_game.c, and apply
targeted textual fixes to the generated sources until the error count stops
falling.  Fixes are of a few mechanical classes:

  A. function returning void but result used  -> retype prototype+definition to
     `long` (Ghidra often emits void when the true ABI returns eax)
  B. int/pointer conversion on DAT_/function-address sites -> explicit
     (uintptr_t)/(void*) casts at the offending column
  C. stack0x/extraout declarations that conflict -> unify to void*

Each pass prints the delta.  Stops when two consecutive passes change nothing.
"""
import re, subprocess, sys, collections, os

GAME = 'linux/bblit_game.c'
HDR  = 'linux/bblit_game.h'

def gcc_errors():
    r = subprocess.run(['gcc','-m64','-c','-w','-O0','-Ilinux',GAME,'-o','/tmp/bblit_game.o'],
                       capture_output=True, text=True)
    errs = []
    lines = r.stderr.split('\n')
    for i,l in enumerate(lines):
        m = re.match(r'linux/bblit_game\.c:(\d+):(\d+): error: (.*)', l)
        if m:
            ln, col, msg = int(m.group(1)), int(m.group(2)), m.group(3)
            # source line may appear nearby as ' 1234 | code' or directly after
            src = ''
            for j in range(i+1, min(i+6, len(lines))):
                ms = re.match(r'\s*\d+\s*\|\s(.*)', lines[j])
                if ms:
                    src = ms.group(1); break
            if not src and ln-1 < len(srclines_cache):
                src = srclines_cache[ln-1]
            errs.append((ln, col, msg, src))
    return errs

srclines_cache = []

def fix_void_value_used(errs, srclines, protolines):  # noqa: args unused now
    """FUN_x used as value but declared void -> change ret type to long in both."""
    names = set()
    for ln, col, msg, src in errs:
        if 'void value not ignored' in msg or 'invalid use of void expression' in msg:
            # search a window around the error line for the callee
            lo = max(0, ln-6); hi = min(len(srclines), ln+3)
            for j in range(hi-1, lo-1, -1):
                m = re.search(r'\b(FUN_[0-9A-Fa-f]{8}|DirectDraw\w*|DirectSound\w*|PeekMessageA|GetMessageA)\s*\(', srclines[j])
                if m:
                    nm = m.group(1)
                    if nm.startswith('FUN_'):
                        names.add(nm)
                    break
    changed = 0
    for name in names:
        # definition
        for i,l in enumerate(srclines):
            m = re.match(r'(\s*)void(\s+' + re.escape(name) + r'\s*\()', l)
            if m:
                srclines[i] = m.group(1) + 'long' + m.group(2) + l[m.end():]
                changed += 1
                break
        # prototype
        for i,l in enumerate(protolines):
            m = re.match(r'(\s*)void(\s+' + re.escape(name) + r'\s*\()', l)
            if m:
                protolines[i] = m.group(1) + 'long' + m.group(2) + l[m.end():]
                changed += 1
                break
        # 'return;' inside that function is fine (returns void->long? no!)
        # gcc allows 'return;' only in void fns. Convert bare returns in that fn.
        # find definition range
        start = None
        for i,l in enumerate(srclines):
            if re.match(r'\s*long\s+' + re.escape(name) + r'\s*\(', l):
                start = i; break
        if start is not None:
            depth = 0; seen = False
            for j in range(start, len(srclines)):
                depth += srclines[j].count('{') - srclines[j].count('}')
                if '{' in srclines[j]: seen = True
                if seen and depth <= 0: break
                srclines[j] = re.sub(r'(?m)^(\s*)return;\s*$', r'\1return 0;', srclines[j])
    return changed

def fix_int_ptr_conversions(errs, srclines):
    """assignment int<-ptr / ptr<-int on DAT_/funcref lines -> explicit casts."""
    changed = 0
    for ln, col, msg, src in errs:
        if 'makes integer from pointer without a cast' in msg:
            # RHS ptr used as int: LHS = RHS
            l = srclines[ln-1] if ln-1 < len(srclines) else (src or '')
            m = re.search(r'=\s*(.+?)(;|$)', l)
            if not m: continue
            rhs = m.group(1).rstrip()
            if re.search(r'\b(?:_?DAT_[0-9A-Fa-f]{8}|FUN_[0-9A-Fa-f]{8}|[a-zA-Z_]\w*)\b', rhs):
                new = l[:m.start(1)] + '(uintptr_t)(' + rhs + ')' + l[m.end(1):]
                if new != l:
                    srclines[ln-1] = new
                    changed += 1
        elif 'makes pointer from integer without a cast' in msg:
            l = srclines[ln-1] if ln-1 < len(srclines) else (src or '')
            m = re.search(r'=\s*(.+?)(;|$)', l)
            if not m: continue
            rhs = m.group(1).rstrip()
            if rhs.startswith('(') or rhs == '0': continue
            new = l[:m.start(1)] + '(void *)(uintptr_t)(' + rhs + ')' + l[m.end(1):]
            if new != l:
                srclines[ln-1] = new
                changed += 1
    return changed

def find_call_span(srclines, ln, col):
    """return (start,end) offsets of the callee identifier starting at col-1."""
    l = srclines[ln-1]
    # find identifier left of col that is the callee
    m = None
    for m2 in re.finditer(r'\b(FUN_[0-9A-Fa-f]{8})\s*\(', l):
        if m2.start(1) <= col-1 <= m2.end(1)+1 or True:
            pass
    # pick the call whose arg-list spans col
    for m2 in re.finditer(r'\b(FUN_[0-9A-Fa-f]{8})\s*\(', l):
        i = m2.end()-1; depth=0; closed=False
        while i < len(l):
            if l[i]=='(': depth+=1
            elif l[i]==')':
                depth-=1
                if depth==0: closed=True; break
            i+=1
        if closed and m2.start(1) <= col <= i+1:
            return m2.start(1), m2.end(1), i  # idstart, idend, closeparen
    return None

def fix_arglist_arity(errs, srclines):
    changed = 0
    for ln, col, msg, src in errs:
        if 'too few arguments' in msg or 'too many arguments' in msg:
            sp = find_call_span(srclines, ln, col)
            if not sp: continue
            a,b,c = sp
            l = srclines[ln-1]
            new = '((long (*)())' + l[a:c+1] + ')' + l[c+1:]
            if new != l:
                srclines[ln-1] = new
                changed += 1
    return changed

def fix_ptr_assign(errs, srclines):
    changed = 0
    for ln, col, msg, src in errs:
        if 'from incompatible pointer type' in msg and 'assignment' in msg:
            l = srclines[ln-1]
            m = re.search(r'=\s*(.+?);', l)
            if not m: continue
            rhs = m.group(1).rstrip()
            if rhs.startswith('(') or 'uintptr_t' in rhs: continue
            new = l[:m.start(1)] + '(void *)(uintptr_t)(' + rhs + ')' + l[m.end(1):]
            if new != l:
                srclines[ln-1] = new
                changed += 1
    return changed

def main():
    global srclines_cache
    srclines = open(GAME).read().split('\n')
    srclines_cache = srclines
    protolines = open(HDR).read().split('\n')
    for it in range(12):
        errs = gcc_errors()
        print(f'pass {it}: {len(errs)} errors')
        n1 = fix_void_value_used(errs, srclines, protolines)
        n2p = fix_int_ptr_conversions(errs, srclines)
        n3p = fix_arglist_arity(errs, srclines)
        n4p = fix_ptr_assign(errs, srclines)
        print(f'  DBG n1={n1} n2={n2p} n3={n3p} n4={n4p}')
        if n1 + n2p + n3p + n4p == 0:
            print('  no more mechanical fixes')
            break
        open(GAME,'w').write('\n'.join(srclines))
        if n1:
            open(HDR,'w').write('\n'.join(protolines))
        continue
        n1 = fix_void_value_used(errs, srclines, protolines)
        if n1:
            open(GAME,'w').write('\n'.join(srclines))
            open(HDR,'w').write('\n'.join(protolines))
            continue
        n2 = fix_int_ptr_conversions(errs, srclines)
        if n2:
            open(GAME,'w').write('\n'.join(srclines))
            continue
        n3 = fix_arglist_arity(errs, srclines)
        print(f'  DBG n3={n3}')
        if n3:
            open(GAME,'w').write('\n'.join(srclines))
            continue
        n4 = fix_ptr_assign(errs, srclines)
        if n4:
            open(GAME,'w').write('\n'.join(srclines))
            continue
        print('  no more mechanical fixes')
        break
        open(GAME,'w').write('\n'.join(srclines))
        open(HDR,'w').write('\n'.join(protolines))
    errs = gcc_errors()
    print(f"final: {len(errs)} errors")
    c = collections.Counter(re.sub(r"'[^']*'", "X", m) for _, _, m, _ in errs)
    for k,v in c.most_common(12):
        print(f'{v:5d}  {k}')

if __name__ == '__main__':
    main()
