#!/usr/bin/env python3
"""fix_loop.py -- drive gcc over linux/bblit_game.c and apply mechanical fixes
until the error count stops falling.

Pipeline per run:
  1. reconcile linux/bblit_game.h against the definitions in bblit_game.c
     (the old header used unprototyped `long f();` guesses; regenerated
     prototypes come verbatim from the definitions)
  2. one-shot text rewrites: `thunk_FUN_x(...)` call -> `FUN_x(`,
     invalid `X.DATAPART(a,b,c)` member-macro form, `(*)(...)` casts
  3. parse gcc diagnostics fully (primary + note chain), resolve the true
     bblit_game.c site for errors reported inside data_syms.h macros
  4. apply fix classes:
       A. void fn whose value is used          -> retype to long (+ bare returns)
       B. int<-ptr / ptr<-int on assign & args -> (uintptr_t)/(void*)(uintptr_t)
       C. incompatible pointer assign/arg      -> (void *)(uintptr_t)(rhs)
       D. bad float/double/longdouble casts of pointer slots -> u32_as_f/d/ld
       E. float assigned to a data_u32* slot   -> (void *)(uintptr_t)flt_bitsf((float)(rhs))
       F. arity mismatch on a call             -> ((long (*)())FUN)(args)
  5. loop until no fix applies; print per-class census of what remains

Generated files only: bblit_game.c / bblit_game.h.  Hand-fixes belong in
triage.txt follow-up, not here.
"""
import re, subprocess, sys, collections

GAME = 'linux/bblit_game.c'
HDR  = 'linux/bblit_game.h'

DIAG = re.compile(r'^(\S+?):(\d+):(\d+):\s+(error|note|warning):\s*(.*)$')

# ---------------------------------------------------------------- gcc driver
def run_gcc():
    r = subprocess.run(['gcc','-c','-Ilinux','-fno-diagnostics-show-caret',
                        GAME,'-o','/tmp/bblit_game.o'],
                       capture_output=True, text=True)
    return parse(r.stderr)

def count_errors(diags):
    """errors only.  Warnings are counted separately: -Wint-to-pointer-cast
    alone is thousands and is by design of the address-identity port."""
    return [d for d in diags if d['kind'] == 'error']

def parse(text):
    diags, cur = [], None
    for line in text.split('\n'):
        m = DIAG.match(line)
        if not m:
            continue
        f, ln, col, kind, msg = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4), m.group(5)
        if kind == 'note':
            if cur is not None:
                cur['notes'].append((f, ln, col, msg))
        else:
            if cur is not None:
                diags.append(cur)
            cur = {'file': f, 'ln': ln, 'col': col, 'msg': msg, 'kind': kind, 'notes': []}
    if cur is not None:
        diags.append(cur)
    return diags

def site_of(d):
    """True (line, col) in bblit_game.c for a diagnostic."""
    if d['file'].endswith('bblit_game.c'):
        return (d['ln'], d['col'])
    for f, ln, col, msg in d['notes']:
        if f.endswith('bblit_game.c') and msg.startswith('in expansion of macro'):
            return (ln, col)
    return None

# ------------------------------------------------------------ line utilities
def ident_span(l, col):
    """(start,end) of identifier containing 0-based col, else None."""
    for m in re.finditer(r'[A-Za-z_][A-Za-z0-9_]*', l):
        if m.start() <= col < m.end():
            return m.start(), m.end()
    return None

def depth_scan(l):
    d = 0
    out = []
    for ch in l:
        if ch in '([': d += 1
        elif ch in ')]': d -= 1
        out.append(d)
    return out

def find_top_assign(l, after):
    """span (rhs_start, rhs_end) of the top-level `=` RHS after index `after`."""
    depth = depth_scan(l)
    i = after
    while i < len(l):
        if depth[i] == 0 and l[i] == '=' and (i+1 >= len(l) or l[i+1] != '=') \
           and (i == 0 or l[i-1] not in '=!<>=+-*/%&|^'):
            j = i + 1
            while j < len(l) and l[j] in ' \t': j += 1
            k = len(l)
            while k > j and (l[k-1] in ' \t;'): k -= 1
            if k > j:
                return j, k
        i += 1
    return None

def call_args_span(l, name, near):
    """per-argument (start,end) spans of the `name(...)` call best matching
    index `near`, or None."""
    best = None
    for m in re.finditer(r'\b' + re.escape(name) + r'\s*\(', l):
        i = m.end() - 1
        d = 0
        while i < len(l):
            if l[i] == '(': d += 1
            elif l[i] == ')':
                d -= 1
                if d == 0:
                    break
            i += 1
        if i >= len(l):
            continue
        if best is None or (m.end() <= near <= i):
            best = (m.start(), m.end(), i)
            if m.end() <= near <= i:
                break
    if best is None:
        return None
    name_start, a, b = best
    depth = depth_scan(l)
    args, cur = [], a
    i = a
    while i < b:
        if depth[i] == 1 and l[i] == ',':
            args.append((cur, i))
            cur = i + 1
        i += 1
    args.append((cur, b))
    return args, name_start, b

def wrap_span(l, s, e, prefix, suffix):
    return l[:s] + prefix + l[s:e] + suffix + l[e:]

# --------------------------------------------------------------- fix classes
def fix_void_value_used(diags, lines, protolines):
    names = set()
    for d in diags:
        if 'void value not ignored' in d['msg'] or 'invalid use of void expression' in d['msg']:
            st = site_of(d)
            if not st: continue
            ln, col = st
            for j in range(ln-1, max(-1, ln-7), -1):
                m = re.search(r'\b(FUN_[0-9A-Fa-f]{8})\s*\(', lines[j])
                if m:
                    names.add(m.group(1))
                    break
    changed = 0
    for name in names:
        for i, l in enumerate(lines):
            m = re.match(r'(\s*)void(\s+' + re.escape(name) + r'\s*\()', l)
            if m:
                lines[i] = m.group(1) + 'long' + m.group(2) + l[m.end():]
                changed += 1
                break
        for i, l in enumerate(protolines):
            m = re.match(r'(\s*)void(\s+' + re.escape(name) + r'\s*\()', l)
            if m:
                protolines[i] = m.group(1) + 'long' + m.group(2) + l[m.end():]
                changed += 1
                break
        start = next((i for i, l in enumerate(lines)
                      if re.match(r'\s*long\s+' + re.escape(name) + r'\s*\(', l)), None)
        if start is not None:
            depth, seen = 0, False
            for j in range(start, len(lines)):
                depth += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]: seen = True
                if seen and depth <= 0: break
                lines[j] = re.sub(r'^(\s*)return;\s*$', r'\1return 0;', lines[j])
    return changed

def fix_conversions(diags, lines):
    changed = 0
    for d in diags:
        msg = d['msg']
        st = site_of(d)
        if not st: continue
        ln, col = st
        if not (1 <= ln <= len(lines)): continue
        l = lines[ln-1]
        m = re.search(r"passing argument (\d+) of '([^']+)'", msg)
        if m and ('makes integer from pointer' in msg or 'makes pointer from integer' in msg
                  or 'incompatible pointer type' in msg):
            n, name = int(m.group(1)), m.group(2)
            got = call_args_span(l, name, col-1)
            if not got or n-1 >= len(got[0]): continue
            args, _, _ = got
            s, e = args[n-1]
            s2 = s
            while s2 < e and l[s2] in ' \t': s2 += 1
            e2 = e
            while e2 > s2 and l[e2-1] in ' \t': e2 -= 1
            if e2 <= s2: continue
            if 'makes integer from pointer' in msg:
                new = wrap_span(l, s2, e2, '(uintptr_t)(', ')')
            else:
                new = wrap_span(l, s2, e2, '(void *)(uintptr_t)(', ')')
            if new != l:
                lines[ln-1] = new
                changed += 1
            continue
        if 'assignment to' in msg and ('makes integer from pointer' in msg or
                                       'makes pointer from integer' in msg or
                                       'incompatible pointer type' in msg):
            sp = ident_span(l, col-1)
            after = sp[1] if sp else max(0, col-1)
            rhs = find_top_assign(l, after)
            if not rhs: continue
            s, e = rhs
            if 'makes integer from pointer' in msg:
                new = wrap_span(l, s, e, '(uintptr_t)(', ')')
            else:
                new = wrap_span(l, s, e, '(void *)(uintptr_t)(', ')')
            if new != l:
                lines[ln-1] = new
                changed += 1
    return changed

CAST_HELPERS = {'float':'u32_as_f', 'double':'u32_as_d', 'longdouble':'u32_as_ld'}
BADCAST = re.compile(r'\(\s*(float|double|longdouble)\s*\)\s*(\*?\s*[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?)')

def fix_bad_float_casts(diags, lines):
    changed = 0
    for d in diags:
        if 'pointer value used where a floating-point was expected' not in d['msg']:
            continue
        st = site_of(d)
        if not st: continue
        ln, col = st
        if not (1 <= ln <= len(lines)): continue
        l = lines[ln-1]
        for m in BADCAST.finditer(l):
            if m.start() <= col-1 <= m.end() or abs(m.start()-(col-1)) < 30:
                helper = CAST_HELPERS[m.group(1)]
                operand = m.group(2).replace(' *', '*').replace('* ', '*')
                new = l[:m.start()] + helper + '((uintptr_t)(' + operand + '))' + l[m.end():]
                if new != l:
                    lines[ln-1] = new
                    changed += 1
                break
    return changed

def fix_float_to_slot(diags, lines):
    changed = 0
    for d in diags:
        m = re.search(r"assignment to .* from type '(float|double|longdouble)'", d['msg'])
        if not m:
            continue
        st = site_of(d)
        if not st: continue
        ln, col = st
        if not (1 <= ln <= len(lines)): continue
        l = lines[ln-1]
        rhs = find_top_assign(l, max(0, col-1))
        if not rhs: continue
        s, e = rhs
        typ = m.group(1)
        if typ == 'double':
            new = wrap_span(l, s, e, '(void *)(uintptr_t)flt_bitsd(', ')')
        elif typ == 'longdouble':
            new = wrap_span(l, s, e, '(void *)(uintptr_t)flt_bitsd((double)(', '))')
        else:
            new = wrap_span(l, s, e, '(void *)(uintptr_t)flt_bitsf((float)(', '))')
        if new != l:
            lines[ln-1] = new
            changed += 1
    return changed

def fix_arity(diags, lines):
    changed = 0
    for d in diags:
        if 'too few arguments' not in d['msg'] and 'too many arguments' not in d['msg']:
            continue
        m = re.search(r"of '([^']+)'", d['msg'])
        if not m: continue
        st = site_of(d)
        if not st: continue
        ln, col = st
        if not (1 <= ln <= len(lines)): continue
        l = lines[ln-1]
        name = m.group(1)
        got = call_args_span(l, name, col-1)
        if not got: continue
        args, name_start, close = got
        new = '((long (*)())' + l[name_start:close+1] + ')' + l[close+1:]
        if new != l:
            lines[ln-1] = new
            changed += 1
    return changed

# ------------------------------------------------------- one-shot rewrites
def oneshot(lines):
    n = 0
    for i, l in enumerate(lines):
        new = re.sub(r'\bthunk_(FUN_[0-9A-Fa-f]{8})\s*\(', r'\1(', l)
        new = re.sub(r'(\w+)\.DATAPART\((\w+)\s*,', r'DATAPART(\1.\2,', new)
        new = new.replace('(*)...', '(*)()')
        if new != l:
            lines[i] = new
            n += 1
    return n

# ------------------------------------------------------ header reconciliation
DEF_START = re.compile(r'^(undefined\d*|uint\d*|u?int\d*|char|short|long|longlong|ulonglong|'
                       r'float|double|longdouble|bool|uchar|ushort|ulong|void|code|float2|double2|'
                       r'[A-Za-z_]\w*\s*\*)'
                       r'\s+\*?([A-Za-z_]\w*)\s*\(')

def reconcile_header(lines):
    defs = []
    i = 0
    while i < len(lines):
        l = lines[i]
        m = DEF_START.match(l)
        if m:
            buf = [l]
            j = i
            joined = buf[0]
            while (('{' not in joined) or (joined.count('(') > joined.count(')'))) and j + 1 < len(lines):
                j += 1
                buf.append(lines[j])
                joined = ' '.join(x.strip() for x in buf)
            jm = re.match(r'^(.*?)\b([A-Za-z_]\w*)\s*\((.*?)\)\s*\{', joined)
            if jm and jm.group(2) != 'if':
                defs.append((jm.group(1).strip(), jm.group(2), jm.group(3).strip()))
                i = j + 1
                continue
        i += 1
    out = ['/* bblit_game.h -- prototypes regenerated from bblit_game.c definitions. */',
           '#ifndef BBLIT_GAME_H', '#define BBLIT_GAME_H', '',
           '#include "ghidra_types.h"', '#include "data_syms.h"', '#include "winshim.h"', '']
    for ret, name, params in defs:
        # unprototyped on purpose: the original is untyped 32-bit machine code,
        # and arg-type checking at call sites only manufactures errors.  The
        # return type is kept so `void value not ignored` stays detectable.
        out.append(f'{ret} {name}();')
    out.append('')
    out.append('#endif')
    open(HDR, 'w').write('\n'.join(out) + '\n')
    return len(defs)

# ----------------------------------------------------------------------- main
def main():
    lines = open(GAME).read().split('\n')
    n = oneshot(lines)
    ndef = reconcile_header(lines)
    print(f'oneshot rewrites: {n}; header prototypes: {ndef}')
    open(GAME, 'w').write('\n'.join(lines))

    prev = None
    for it in range(15):
        diags = run_gcc()
        errs = count_errors(diags)
        total = len([d for d in errs
                     if d['file'].endswith(('bblit_game.c', 'data_syms.h', 'ghidra_types.h'))])
        print(f'pass {it}: {total} errors')
        if total == 0:
            break
        if prev is not None and total >= prev:
            print('  plateau')
            break
        prev = total
        lines = open(GAME).read().split('\n')
        protolines = open(HDR).read().split('\n')
        n1 = fix_void_value_used(diags, lines, protolines)
        n2 = fix_conversions(diags, lines)
        n3 = fix_bad_float_casts(diags, lines)
        n4 = fix_float_to_slot(diags, lines)
        n5 = fix_arity(diags, lines)
        print(f'  fixes: void={n1} conv={n2} fltcast={n3} fltslot={n4} arity={n5}')
        open(GAME, 'w').write('\n'.join(lines))
        open(HDR, 'w').write('\n'.join(protolines))
        if n1 + n2 + n3 + n4 + n5 == 0:
            print('  no mechanical fixes applied; remaining census below')
            break

    diags = run_gcc()
    census = collections.Counter()
    for d in count_errors(diags):
        m = d['msg']
        m = re.sub(r"'[^']*'", "'X'", m)
        m = re.sub(r'FUN_[0-9A-Fa-f]{8}', 'F', m)
        m = re.sub(r'DAT_[0-9A-Fa-f]{8}', 'D', m)
        m = re.sub(r'0x[0-9a-fA-F]+', 'N', m)
        census[(d['file'].split('/')[-1], m)] += 1
    print('\nremaining error census (file, class) -> count:')
    for (f, m), c in census.most_common(30):
        print(f'  {c:5d}  {f}: {m}')

if __name__ == '__main__':
    main()
