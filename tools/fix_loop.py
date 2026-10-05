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
                m = re.search(r'\b(FUN_[0-9A-Fa-f]{8}|\w+)\s*\(', lines[j])
                if m:
                    names.add(m.group(1))
                    break
    changed = 0
    for name in names:
        done = False
        for i, l in enumerate(lines):
            m = re.match(r'(\s*)void(\s+' + re.escape(name) + r'\s*\()', l)
            if m:
                lines[i] = m.group(1) + 'long' + m.group(2) + l[m.end():]
                changed += 1
                done = True
                break
        for i, l in enumerate(protolines):
            m = re.match(r'(\s*)void(\s+' + re.escape(name) + r'\s*\()', l)
            if m:
                protolines[i] = m.group(1) + 'long' + m.group(2) + l[m.end():]
                changed += 1
                break
        if done:
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

# ---------------------------------------------------------- type-aware engine
PROMOTABLE = {'char','short','int8','int16','sbyte','byte','ubyte','uchar','ushort',
              'uint16','undefined1','undefined2','bool','float'}

def type_kind(t):
    """kind of a type string: ptr, int, float, other."""
    t = t.strip()
    if '*' in t or t.startswith(('LP', 'PCTSTR', 'LPC', 'HANDLE', 'HWND', 'HDC', 'HGLRC',
                                 'HMODULE', 'HINSTANCE', 'HGLOBAL', 'HRSRC', 'HGDIOBJ',
                                 'HBITMAP', 'HCURSOR', 'HBRUSH', 'HPALETTE', 'HFONT',
                                 'HACCEL', 'HHOOK', 'HKEY', 'HDWP', 'HIMC', 'HKL', 'code')):
        return 'ptr'
    if t in ('float','double','longdouble','float2','double2') or 'float' in t or 'double' in t:
        return 'float'
    return 'int'

def cast_for(dst_t, src_t):
    """C wrapper pair converting src-shaped expr into dst type.
    Bit-preserving for the dword/pointer overlap the x86 code relied on."""
    dk, sk = type_kind(dst_t), type_kind(src_t)
    dst_t = dst_t.strip()
    if dk == 'ptr' and sk == 'ptr':
        return '(' + dst_t + ')(', ')'
    if dk == 'ptr' and sk == 'int':
        return '(' + dst_t + ')(uintptr_t)(', ')'
    if dk == 'int' and sk == 'ptr':
        return '(uintptr_t)(', ')'
    if dk == 'float' and sk == 'ptr':
        base = 'u32_as_ld' if 'longdouble' in dst_t else ('u32_as_d' if 'double' in dst_t else 'u32_as_f')
        return base + '((uintptr_t)(', '))'
    if dk == 'ptr' and sk == 'float':
        if 'double' in src_t:
            return '(' + dst_t + ')(uintptr_t)flt_bitsd((double)(', '))'
        return '(' + dst_t + ')(uintptr_t)flt_bitsf((float)(', '))'
    if dk == 'int' and sk == 'float':
        # original stored float bits into a dword slot view
        return '(int)(uintptr_t)flt_bitsf((float)(', '))'
    if dk == 'float' and sk == 'int':
        base = 'u32_as_ld' if 'longdouble' in dst_t else ('u32_as_d' if 'double' in dst_t else 'u32_as_f')
        return base + '((uintptr_t)(', '))'
    return None

def note_expected(d):
    """(expected_type, actual_type) from the gcc expected/actual note."""
    for f, ln, col, msg in d['notes']:
        m = re.search(r"expected '([^']+)' but argument is of type '([^']+)'", msg)
        if m:
            return m.group(1), m.group(2)
    return None, None

def assign_types(d):
    """(dst_type, src_type) from an assignment-to message."""
    m = re.search(r"assign(?:ment|ing) to (?:type )?'([^']+)'", d['msg'])
    if not m:
        return None, None
    dst = m.group(1)
    m2 = re.search(r"from (?:type |incompatible pointer type )?'([^']+)'", d['msg'])
    if not m2:
        m2 = re.search(r"from type '([^']+)'", d['msg'])
    src = m2.group(1) if m2 else None
    return dst, src

def fix_conversions(diags, lines):
    changed = 0
    for d in diags:
        msg = d['msg']
        st = site_of(d)
        if not st: continue
        ln, col = st
        if not (1 <= ln <= len(lines)): continue
        l = lines[ln-1]
        m = re.search(r"passing argument (\d+) to '([^']+)'", msg) or \
            re.search(r"passing argument (\d+) of '([^']+)'", msg)
        if m and ('makes integer from pointer' in msg or 'makes pointer from integer' in msg
                  or 'incompatible pointer type' in msg or 'from type' in msg
                  or 'discards qualifiers' in msg):
            name = m.group(2)
            got = call_args_span(l, name, col-1)
            if not got:
                continue
            args, a_open, a_close = got
            if not (a_open <= col-1 <= a_close):
                continue
            def is_wrapped(t):
                t = t.strip()
                return t.startswith('(uintptr_t)') or t.startswith('(void *)')
            # prefer the message's argument index; fall back to the argument
            # containing the reported column; never re-wrap an already-wrapped
            # argument (gcc reports these errors once per call, and repeated
            # passes would stack casts on argument 1)
            n = int(m.group(1))
            idx = (n - 1) if (n - 1) < len(args) else None
            if idx is not None and is_wrapped(l[args[idx][0]:args[idx][1]]):
                idx = None
            if idx is None:
                for i, (s_, e_) in enumerate(args):
                    if s_ <= col-1 < e_ and not is_wrapped(l[s_:e_]):
                        idx = i
                        break
            if idx is None:
                for i, (s_, e_) in enumerate(args):
                    if not is_wrapped(l[s_:e_]):
                        idx = i
                        break
            if idx is None:
                continue
            s, e = args[idx]
            s2 = s
            while s2 < e and l[s2] in ' \t': s2 += 1
            e2 = e
            while e2 > s2 and l[e2-1] in ' \t': e2 -= 1
            if e2 <= s2: continue
            et, at = note_expected(d)
            if et:
                pair = cast_for(et, at or "int")
            else:
                pair = ('(uintptr_t)(', ')') if 'makes integer from pointer' in msg \
                    else ('(void *)(uintptr_t)(', ')')
            if not pair: continue
            if ',' in l[s2:e2]:
                # comma expression: bind it before casting
                prefix, suffix = pair[0] + '(', ')' + pair[1]
                new = l[:s2] + prefix + '(' + l[s2:e2] + ')' + suffix + l[e2:]
            else:
                prefix, suffix = pair
                new = wrap_span(l, s2, e2, prefix, suffix)
            if new != l:
                lines[ln-1] = new
                changed += 1
            continue
        if 'assignment to' in msg or 'when assigning to type' in msg:
            dst, src = assign_types(d)
            # the error column sits at/near the offending '='; prefer the '='
            # nearest the column (for/while headers hold several)
            depth = depth_scan(l)
            cands = [i for i, c in enumerate(l)
                     if c == '=' and (i+1 >= len(l) or l[i+1] != '=')
                     and (i == 0 or l[i-1] not in '=!<>=+-*/%&|^')]
            if not cands:
                continue
            best = min(cands, key=lambda i: abs(i - (col-1)))
            j = best + 1
            while j < len(l) and l[j] in ' \t': j += 1
            k = len(l)
            while k > j and l[k-1] in ' \t;': k -= 1
            # RHS ends at the operator's own nesting level: a for/while header
            # holds several statements, so ';' at the header depth ends it
            level = depth[best]
            q = j
            while q < k and not (l[q] == ';' and depth[q] <= level):
                q += 1
            k2 = q
            while k2 > j and l[k2-1] in ' \t': k2 -= 1
            j, k = j, k2
            s, e = j, k
            if k <= j: continue
            if dst and src:
                pair = cast_for(dst, src)
            else:
                pair = ('(uintptr_t)(', ')') if 'makes integer from pointer' in msg \
                    else ('(void *)(uintptr_t)(', ')')
            if not pair: continue
            if ',' in l[s:e]:
                # comma expression: bind it before casting.  The '=' RHS runs
                # to end of line, which inside a condition includes closing
                # brackets that belong to OUTER expressions: cut at the comma
                # expression's own depth, not the raw line end.
                depth = depth_scan(l)
                op_level = depth[best]
                cut = e
                while cut > s and depth[cut-1] < op_level and l[cut-1] in ')]':
                    cut -= 1
                seg = l[s:cut]
                # a comma at the RHS's own level makes it a comma expression;
                # commas BELOW our depth (e.g. inside an outer condition or a
                # function call argument list) do not
                own_comma = any(c == ',' and depth[s + i] == op_level + 1
                                for i, c in enumerate(seg))
                if not own_comma:
                    # commas live only in the outer tail; wrap the segment
                    new = l[:s] + pair[0] + '(' + seg + ')' + pair[1] + l[e:]
                else:
                    # cast only the comma expression's FIRST element; the
                    # rest of the expression keeps working on the cast value
                    tail = l[cut:e]
                    rel = seg.find(',')
                    first = seg[:rel].rstrip()
                    rest = seg[rel:]           # ', rest...'
                    new = (l[:s] + pair[0] + first + pair[1]
                           + ' ' + rest.strip() + tail + l[e:])
            else:
                new = wrap_span(l, s, e, pair[0], pair[1])
            if new != l:
                lines[ln-1] = new
                changed += 1
    return changed

CAST_HELPERS = {'float':'u32_as_f', 'double':'u32_as_d', 'longdouble':'u32_as_ld'}
BADCAST = re.compile(r'\(\s*(float|double|longdouble)\s*\)\s*(\*?\s*[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?)')

def wrap_designator(l, name, col, rettype='long'):
    """name( -> ((rettype (*)())name)( at the occurrence nearest col.
    Works across multi-line arglists since only the designator changes."""
    best = None
    for m in re.finditer(r'(?<![\w.(])' + re.escape(name) + r'\s*\(', l):
        if best is None or abs(m.start() - (col-1)) < abs(best.start() - (col-1)):
            best = m
    if best is None:
        return None
    s = best.start()
    e = s + len(name)
    return l[:s] + '((%s (*)())%s)' % (rettype, name) + l[e:]

def fix_calls(diags, lines):
    changed = 0
    for d in diags:
        msg = d['msg']
        if not ('too few arguments' in msg or 'too many arguments' in msg
                or 'non-compatible type' in msg):
            continue
        m = re.search(r"to function '([^']+)'", msg) or re.search(r"of '([^']+)'", msg)
        if not m: continue
        name = m.group(1)
        if name.startswith(('expected', 'argument')): continue
        st = site_of(d)
        if not st: continue
        ln, col = st
        if not (1 <= ln <= len(lines)): continue
        l = lines[ln-1]
        new = wrap_designator(l, name, col)
        if new and new != l:
            lines[ln-1] = new
            changed += 1
    return changed

def operand_span(l, op_idx, side):
    """span of the operand left or right of the operator at op_idx."""
    n = len(l)
    if side > 0:
        i = op_idx + 1
        while i < n and l[i] in ' \t': i += 1
        if i >= n: return None
        start = i
        depth = 0
        end = i
        while i < n:
            c = l[i]
            if c in '([': depth += 1
            elif c in ')]':
                if depth == 0: break
                depth -= 1
            elif depth == 0 and c in '+-*/%<>=&|^,;?':
                if i > start:
                    break
                # possible unary sign: consume it and continue
                if c in '+-' and i+1 < n and l[i+1] not in ' \t':
                    i += 1
                    end = i
                    continue
                break
            i += 1
            end = i
        while end > start and l[end-1] in ' \t': end -= 1
        return (start, end) if end > start else None
    else:
        i = op_idx - 1
        while i >= 0 and l[i] in ' \t': i -= 1
        if i < 0: return None
        end = i + 1
        depth = 0
        while i >= 0:
            c = l[i]
            if c in ')]': depth += 1
            elif c in '([':
                if depth == 0: break
                depth -= 1
            elif depth == 0 and c in '+-*/%<>=&|^,;?:!':
                break
            i -= 1
        start = i + 1
        # also stop at a top-level comma: a comma expression is not one operand
        j = end - 1
        d3 = depth_scan(l)
        while j >= start:
            if l[j] == ',' and d3[j] == d3[op_idx]:
                start = j + 1
                break
            j -= 1
        while start < end and l[start] in ' \t': start += 1
        return (start, end) if end > start else None

MACRO_DEF = re.compile(r'#define\s+(\w+)\s+\(\s*\*\s*\(\s*([A-Za-z_][A-Za-z0-9_ \t]*\**)\s*\*\s*\)\s*(0x[0-9A-Fa-f]+)')

def load_macro_types(hdrs=('linux/data_syms.h',)):
    mt = {}
    for h in hdrs:
        try:
            txt = open(h).read()
        except FileNotFoundError:
            continue
        for m in MACRO_DEF.finditer(txt):
            mt[m.group(1)] = m.group(2).replace(' ', '')
    return mt

def fix_binary_ops(diags, lines):
    changed = 0
    for d in diags:
        msg = d['msg']
        if 'invalid operands to binary' not in msg and 'wrong type argument to unary minus' not in msg:
            continue
        st = site_of(d)
        if not st: continue
        ln, col = st
        if not (1 <= ln <= len(lines)): continue
        l = lines[ln-1]
        p = min(len(l)-1, max(0, col-1))
        if 'unary minus' in msg:
            while p < len(l) and l[p] != '-':
                p += 1
            if p >= len(l): continue
            sp = operand_span(l, p, +1)
            if not sp: continue
            new = wrap_span(l, sp[0], sp[1], '(int)(uintptr_t)(', ')')
            if new != l:
                lines[ln-1] = new
                changed += 1
            continue
        if l[p] not in '+-*/%<>&|^':
            # scan nearby for the operator
            for q in range(max(0,p-3), min(len(l), p+4)):
                if l[q] in '+-*/%<>&|^':
                    p = q
                    break
            else:
                continue
        # types appear as (have 'A' {aka ...} and 'B' {aka ...}); the aka
        # text between them defeats a single regex, so take the two pieces
        # separately
        ma = re.search(r"\(\s*have\s+'([^']+)'", msg)
        mb = re.search(r"\s+and\s+'([^']+)'", msg)
        types = [ma.group(1), mb.group(1)] if (ma and mb) else []
        if len(types) < 2:
            continue
        if '*' in types[0]:
            side = -1
        elif '*' in types[1]:
            side = +1
        else:
            continue
        other = types[1] if side < 0 else types[0]
        sp = operand_span(l, p, side)
        if not sp: continue
        operand = l[sp[0]:sp[1]]
        mt = load_macro_types()
        is_float_slot = False
        for name in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', operand):
            if name in mt and 'float' in mt[name]:
                is_float_slot = True
        if is_float_slot:
            pre, post = 'u32_as_f((uintptr_t)(', '))'
        elif type_kind(other) == 'float':
            base = 'u32_as_ld' if 'longdouble' in other else ('u32_as_d' if 'double' in other else 'u32_as_f')
            pre, post = base + '((uintptr_t)(', '))'
        else:
            pre, post = '(uintptr_t)(', ')'
        new = wrap_span(l, sp[0], sp[1], pre, post)
        if new != l:
            lines[ln-1] = new
            changed += 1
    return changed

def fix_misc(diags, lines):
    """switch on non-integer; bad float casts of pointer slots."""
    changed = 0
    for d in diags:
        msg = d['msg']
        st = site_of(d)
        if not st: continue
        ln, col = st
        if not (1 <= ln <= len(lines)): continue
        l = lines[ln-1]
        if 'switch quantity not an integer' in msg:
            i = l.find('switch(')
            if i < 0: i = l.find('switch (')
            if i >= 0:
                j = l.find('(', i)
                k = l.rfind(')')
                if j >= 0 and k > j:
                    inner = l[j+1:k].strip()
                    new = l[:j+1] + '(uintptr_t)(' + inner + ')' + l[k:]
                    if new != l:
                        lines[ln-1] = new
                        changed += 1
            continue
        if 'pointer value used where a floating-point was expected' in msg:
            for m2 in BADCAST.finditer(l):
                if m2.start() <= col-1 <= m2.end() or abs(m2.start()-(col-1)) < 40:
                    helper = CAST_HELPERS[m2.group(1)]
                    operand = m2.group(2).replace(' *', '*').replace('* ', '*')
                    new = l[:m2.start()] + helper + '((uintptr_t)(' + operand + '))' + l[m2.end():]
                    if new != l:
                        lines[ln-1] = new
                        changed += 1
                    break
            continue
    return changed

def join_statements(lines):
    """Merge continuation lines so every statement is one physical line.
    A line is continued when it does not end a statement: decompiled C
    statements always end in one of ; { } or a case label's colon.  Any other
    ending (an operator, comma, open paren) means the statement continues on
    the next line.  Skips preprocessor lines.  Returns (lines, removed)."""
    out = []
    removed = 0
    def ends_statement(t):
        t = t.rstrip()
        if not t:
            return True
        if (t.endswith((';', '{', '}', ':', '*/')) or t.startswith('#')
                or t.startswith('//')):
            return True
        return False
    for l in lines:
        if out and not ends_statement(out[-1]):
            out[-1] = out[-1].rstrip() + ' ' + l.strip()
            removed += 1
        else:
            out.append(l)
    return out, removed

# ------------------------------------------------------- one-shot rewrites
def oneshot(lines):
    lines, n_join = join_statements(lines)
    n = n_join
    return lines, n
    # &stackXXXXXX in assignments/views: port needs an integer-roundtrip so the
    # void* slot lvalue accepts it (gcc14 rejects implicit conversions)
    for i, l in enumerate(lines):
        new = re.sub(r'(?<![\w.])&stack0x[0-9a-fA-F]+\b',
                     lambda m: '((void *)(uintptr_t)' + m.group(0) + ')', l)
        if new != l:
            lines[i] = new
            n += 1
    for i, l in enumerate(lines):
        new = re.sub(r'\bthunk_(FUN_[0-9A-Fa-f]{8})\s*\(', r'\1(', l)
        new = re.sub(r'(\w+)\.DATAPART\((\w+)\s*,', r'DATAPART(\1.\2,', new)
        new = new.replace('(*)...', '(*)()')
        if new != l:
            lines[i] = new
            n += 1
    return n

# ------------------------------------------------------ header reconciliation
# Generic: any column-0 line shaped `<type stuff> <name>(` opens a definition.
DEF_START = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t]*\**[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(')

def reconcile_header(lines):
    defs = []
    i = 0
    while i < len(lines):
        l = lines[i]
        m = DEF_START.match(l)
        if m and not l.startswith((' ', '\t', '#', '/')):
            buf = [l]
            j = i
            joined = buf[0]
            while (('{' not in joined) or (joined.count('(') > joined.count(')'))) and j + 1 < len(lines):
                j += 1
                buf.append(lines[j])
                joined = ' '.join(x.strip() for x in buf)
            jm = re.match(r'^(.*?)\b([A-Za-z_]\w*)[ \t]*\((.*?)\)[ \t]*\{', joined)
            if jm and jm.group(2) not in ('if', 'for', 'while', 'switch', 'return'):
                defs.append((jm.group(1).strip(), jm.group(2), jm.group(3).strip()))
                i = j + 1
                continue
        i += 1
    out = ['/* bblit_game.h -- prototypes regenerated from bblit_game.c definitions. */',
           '#ifndef BBLIT_GAME_H', '#define BBLIT_GAME_H', '',
           '#include "ghidra_types.h"', '#include "data_syms.h"', '#include "winshim.h"', '']
    for ret, name, params in defs:
        out.append(f'{ret} {name}({params});')
    out.append('')
    out.append('#endif')
    open(HDR, 'w').write('\n'.join(out) + '\n')
    return len(defs)

# ----------------------------------------------------------------------- main
def main():
    lines = open(GAME).read().split('\n')
    lines, n = oneshot(lines)
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
        n3 = fix_calls(diags, lines)
        n4 = fix_binary_ops(diags, lines)
        n5 = fix_misc(diags, lines)
        print(f'  fixes: void={n1} conv={n2} calls={n3} binop={n4} misc={n5}')
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
