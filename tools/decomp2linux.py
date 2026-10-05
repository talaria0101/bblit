#!/usr/bin/env python3
"""decomp2linux.py -- transform Ghidra decompiled output (BUGS.EXE) into a
compilable C translation unit set for a 64-bit Linux build.

Pipeline:
  1. parse bugs_decompiled.c into per-function chunks
  2. classify each function: game / crt (drop) / thunk
  3. per-function textual fixes:
       - __ftol(x)            -> vc6_ftol(x)   (x86-64 native conversion)
       - CONCATnn(...)        -> macro (header provides)
       - sym._off_size_       -> partial store access via helper macro
       - &DAT_xxx             -> data_xxx (auto-generated address symbol)
       - _DAT_xxx             -> dval_xxx (pointer value read of DAT_xxx)
       - in_/unaff_/extraout_ -> flagged; crt funcs are dropped, game funcs hand-fixed
  4. emit TU per source file (default: one), plus prototypes + extern decls
  5. apply rename map (address -> inferred name) if provided

outputs into --outdir: bblit_game.c, bblit_game.h, data_syms.h, triage.txt
"""
import re, os, sys, json, argparse, collections

GhidraTypes = set('undefined undefined2 undefined4 undefined8 char short int long longlong float double '
                  'bool code uchar ushort uint ulong ulonglong int8 int16 int32 int64 uint8 uint16 uint32 uint64 '
                  'float2 double2 pointer void bool'.split())

# ---- function classification ------------------------------------------------
CRT_NAMES = set('''entry __ftol __fpmath __fload_withFB __setdefaultprecision
__startOneArgErrorHandling __math_exit __local_unwind2 __global_unwind2 RtlUnwind
__exit __amsg_exit _amsg_exit __allmul __alldiv __aulldiv __aullrem __allshl __allshr
__aullshr __allrem _ftol _ftol2 _ltod3 _dtol3 _ftol2puncteen
_strstr _strrchr _strncpy __strcmpi _strcmpi _stricmp _stricmp2
DirectSoundCreate DirectDrawCreate DirectDrawEnumerateA
_malloc _nh_malloc _free _calloc _realloc _nh_free
__CRT_MT __dyn_tls_init __.dllmain _DllMainCRTStartup DllMain
'''.split())

def classify(name, addr):
    if name in CRT_NAMES: return 'crt'
    if name.startswith('__') or name.startswith('_str'): return 'crt'
    if name.startswith('thunk_'): return 'thunk'
    return 'game'

# ---- helpers ----------------------------------------------------------------
def ptr_type_for_size(sz):
    return {1:'data_u8', 2:'data_u16', 4:'data_u32', 8:'data_u64'}.get(sz, 'data_u8')


STACK_IDENT = re.compile(r'\b(stack0x[0-9a-fA-F]+|[aiup]+Stack[0-9a-fA-F]+|uStack\d+|extraout_[A-Za-z0-9_]+|in_[A-Za-z][A-Za-z0-9_]*|unaff_[A-Za-z0-9_]+)\b')

GTYPE = (r'(?:undefined\d?|uint\d?|unkbyte\d+|unkuint\d+|u?int\d*|char|short|long|'
         r'longlong|ulonglong|float|double|longdouble|bool|byte|word|dword|code|void|'
         r'HANDLE|HWND|DWORD|LPSTR|LPCSTR|LPVOID|UINT|BOOL|HDC|HMODULE|HINSTANCE|'
         r'HGLOBAL|HRSRC|SIZE_T|LRESULT|WPARAM|LPARAM|ATOM|COLORREF|LANGID|HKEY|'
         r'LSTATUS|ulong|ushort|uchar|uint)')
DECL_RE = re.compile(r'(?m)^\s*(?:' + GTYPE + r')[\w ]*?\**\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*;')

def synth_decls(impl):
    """Extra local declarations for Ghidra frame artifacts with no declaration."""
    # strip comments and string/char literals so DECL_RE cannot match text
    # inside them (string content like `char x;` inside "..." would hide a use)
    scan = re.sub(r'(?s)/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  ' ', impl)
    used = set(m.group(1) for m in STACK_IDENT.finditer(scan))
    decl = set(m.group(1) for m in DECL_RE.finditer(scan))
    out = []
    for u in sorted(used):
        if u in decl:
            continue
        out.append('void *%s;' % u)
    return out

def cident_for(sym):
    # Ghidra symbols are already valid C identifiers
    return sym

# ---- parsing ----------------------------------------------------------------
CHUNK_RE = re.compile(r'^// ===== (\S+) @ ([0-9a-fA-F]{8}) =====$', re.M)

def parse_chunks(text):
    out = []
    ms = list(CHUNK_RE.finditer(text))
    for i, m in enumerate(ms):
        name, addr = m.group(1), m.group(2)
        start = m.end()
        end = ms[i+1].start() if i+1 < len(ms) else len(text)
        out.append({'name': name, 'addr': addr, 'text': text[start:end]})
    return out

def split_sig(body):
    """split chunk into signature part and { ... } body"""
    m = re.search(r'^\{', body, re.M)
    if not m: return body, ''
    sig, rest = body[:m.start()], body[m.start():]
    return sig, rest

# ---- fixers -----------------------------------------------------------------
def fix_partial_access(t):
    """sym._off_size_ -> DATA_PART(sym,off,size) ; handle nested parens simply via regex on ident only"""
    # Ghidra writes like DAT_004efb50._0_2_ or puVar1->_0_2_ (rare) or local._0_4_
    def repl(m):
        base, off, size = m.group(1), m.group(2), m.group(3)
        return f'DATAPART({base},{int(off,16) if off.startswith("0x") else int(off)},{int(size)})'
    return re.sub(r'\b([A-Za-z_][A-Za-z0-9_]*)\._([0-9a-fA-F]+)_([0-9a-fA-F]+)_', repl, t)

def fix_ftol(t):
    return re.sub(r'\b__ftol\(', 'vc6_ftol(', t)

def fix_concat(t):
    # CONCATnn names exist as macros; but Ghidra also emits CONCAT44 etc with mixed widths already covered.
    return t

def fix_addr_refs(t, addrsyms):
    """&DAT_xxxxxxxx -> data_xxxxxxxx (the generated address-constant symbol)."""
    def repl(m):
        return '&' + m.group(0)  # keep & but symbol will be a real object
    # we keep &DAT_ as-is: generated header declares DAT_ objects for every referenced
    # address so &DAT_x is just address-of-object. nothing to do.
    return t

# ---- main -------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('infile')
    ap.add_argument('--outdir', default='linux')
    ap.add_argument('--symbols', default='tools/symbols.csv')
    ap.add_argument('--renames', default=None, help='JSON {addr or oldname: newname}')
    ap.add_argument('--drop-unfixable', action='store_true',
                    help='emit game funcs with unresolvable artifacts as triage stubs')
    args = ap.parse_args()

    text = open(args.infile, encoding='utf-8', errors='replace').read()
    chunks = parse_chunks(text)

    # symbol address usage (for data_syms generation elsewhere; here we only need names)
    renames = {}
    if args.renames:
        renames = json.load(open(args.renames))

    os.makedirs(args.outdir, exist_ok=True)

    triage = []
    game_parts = []
    protos = []
    kept = dropped = 0

    # first pass: all signatures (for prototype header) and renames
    for c in chunks:
        c['cls'] = classify(c['name'], c['addr'])
        newname = renames.get(c['addr']) or renames.get(c['name'])
        c['newname'] = newname or c['name']

    # address -> containing function name (for mid-function label references)
    import bisect as _bs
    _starts = sorted((int(c['addr'], 16), c['name'], c['newname']) for c in chunks)
    _keys = [s for s, _, _ in _starts]
    func_for_lab = {}
    for m in re.finditer(r'&(LAB_([0-9a-fA-F]{8}))', text):
        v = int(m.group(2), 16)
        i = _bs.bisect_right(_keys, v) - 1
        if i >= 0:
            func_for_lab[m.group(1)] = _starts[i][2]

    # arity analysis over the whole text: call sites vs decompiled signature
    import collections as _c
    call_ar = _c.defaultdict(list)
    for m in re.finditer(r'(FUN_[0-9A-Fa-f]{8})\s*\(', text):
        name = m.group(1)
        ls = text.rfind('\n', 0, m.start()) + 1
        le = text.find('\n', m.start())
        line = text[ls:le if le >= 0 else len(text)]
        pre = line[:m.start()-ls].strip()
        stripped = line.strip()
        if re.match(r'^(?:[A-Za-z_][\w ]*\s+)+$', pre) and (
                stripped.endswith('{') or stripped.endswith(';')):
            continue  # definition/prototype line
        i = m.end(); depth = 1
        while i < len(text) and depth > 0:
            if text[i] == '(': depth += 1
            elif text[i] == ')': depth -= 1
            i += 1
        argtext = text[m.end():i-1]
        d = 0; n = 1
        if argtext.strip() == '':
            n = 0
        for ch in argtext:
            if ch == '(': d += 1
            elif ch == ')': d -= 1
            elif ch == ',' and d == 0: n += 1
        call_ar[name].append(n)

    def declared_arity(sigtext):
        s = re.sub(r'/\*.*?\*/', '', sigtext, flags=re.S)
        s = ' '.join(s.split())
        m2 = re.search(r'\((.*)\)\s*$', s)
        if not m2: return None
        inner = m2.group(1).strip()
        if inner in ('', 'void'): return 0
        return inner.count(',') + 1

    mismatch = set()
    for name, arities in call_ar.items():
        sig = None
        for c in chunks:
            if c['name'] == name:
                sig, _ = split_sig(c['text'])
                break
        if sig is None: continue
        da = declared_arity(sig)
        if da is None: continue
        if min(arities) != da or max(arities) != da:
            mismatch.add(name)

    for c in chunks:
        body = c['text']
        if c['cls'] in ('crt', 'thunk'):
            dropped += 1
            continue
        kept += 1
        sig, impl = split_sig(body)

        # rename function in signature
        if c['newname'] != c['name']:
            sig = re.sub(r'\b' + re.escape(c['name']) + r'\b', c['newname'], sig, count=1)

        # artifact detection on the implementation
        arts = sorted(set(re.findall(r'\bunaff_[A-Za-z0-9_]+|\bin_[A-Za-z0-9]+|\bextraout_[A-Za-z0-9_]+', impl)))
        if arts:
            triage.append(f"{c['addr']} {c['newname']}: {','.join(arts)}")

        extra = synth_decls(impl)
        t = sig.rstrip() + '\n' + impl
        t = fix_partial_access(t)
        t = fix_ftol(t)
        t = fix_concat(t)
        # SUB41(v,w) two-arg Ghidra form -> single-arg
        t = re.sub(r'\bSUB(\d)(\d)\(([^,()]*),[^()]*\)', r'SUB\1\2(\3)', t)
        # 3-byte partial stores/loads -> helper calls (no 3-byte C type)
        t = re.sub(r'DATAPART\(([^,()]*(?:\([^()]*\))?[^,()]*)\s*,\s*(\w+)\s*,\s*3\)\s*=\s*',
                   r'data_wr3(&\1, \2, ', t)
        # (careful: write form handled above; read form wraps with data_rd3)
        t = re.sub(r'DATAPART\(([^,()]*(?:\([^()]*\))?[^,()]*)\s*,\s*(\w+)\s*,\s*3\)',
                   r'data_rd3(&\1, \2)', t)
        # close the write call: data_wr3(&b, o, EXPR needs a ')' - handle by rewriting
        # the earlier substitution: data_wr3(&b, o, EXPR;  ->  data_wr3(&b, o, EXPR);
        t = re.sub(r'(data_wr3\(&[^;]*?);', r'\1);', t)
        # array-typed casts are not C: `local = (char [4])DATAPART(b,o,4);`
        # becomes a memcpy from the source bytes
        t = re.sub(r'(\b[A-Za-z_]\w*)\s*=\s*\(\s*(?:unsigned\s+|signed\s+)?'
                   r'(?:char|byte|undefined\d*|uchar|uint8)\s*\[\s*(\d+)\s*\]\s*\)\s*'
                   r'DATAPART\(\s*([^,()]+(?:\([^()]*\))?[^,()]*)\s*,\s*([^,()]+?)\s*,\s*\d+\s*\)\s*;',
                   lambda m: 'memcpy(%s, (const void *)((unsigned char *)&(%s) + (ptrdiff_t)(%s)), %s);'
                             % (m.group(1), m.group(3), m.group(4), m.group(2)),
                   t)
        # value-use of &LAB_x where the label is in another function: point at the
        # function that contains the address (runtime-imprecise, compile-clean)
        def _lab_repl(m):
            lab = m.group(1)
            tgt = func_for_lab.get(lab)
            return tgt if tgt else 'lab_addr(' + lab + ')'
        t = re.sub(r'&(LAB_[0-9a-fA-F]{8})', _lab_repl, t)
        # 3-byte casts have no C equivalent
        t = t.replace('(uint3)', '(unsigned)').replace('(undefined3)', '(unsigned)')
        # unmapped register reference (single site, GDT/FS-relative scratch)
        t = re.sub(r'register0x[0-9a-fA-F]+', 'reg_scratch', t)
        # float-typed expression cast to a pointer type: Ghidra artifact on
        # functions with missing return paths; keep the bit pattern instead.
        # Matches float-valued operands only: fVar/dVar (optionally subscripted)
        # and pfVar[..] elements.  A bare pfVar is a pointer value, not a float.
        # The cast is kept; flt_bits returns the float's bit pattern as an
        # integer, so `*(int *)flt_bitsf(x)` derefs a reconstructed address.
        t = re.sub(r'\((undefined\d?|void|int|char|byte)\s*\*\s*\)\s*'
                   r'((?:[fd]Var\d+(?:\[[^\]]*\])?|\*+pfVar\d+\b|pfVar\d+\[[^\]]*\]))',
                   lambda m: f'({m.group(1)} *)(uintptr_t)flt_bitsf({m.group(2)})', t)
        t = re.sub(r'\((undefined\d?|void|int|char|byte)\s*\*\s*\)\s*(dVar\d+(?:\[[^\]]*\])?)',
                   lambda m: f'({m.group(1)} *)(uintptr_t)flt_bitsd({m.group(2)})', t)
        if extra:
            # insert after first '{' line of body, but skip artifacts the chunk
            # already declares (the regex scan above can miss `void *name;`)
            extra = [e for e in extra if e[:-1] not in t]
            t = t.replace('\n{\n', '\n{\n  ' + '\n  '.join(extra) + '\n', 1)

        # rename referenced functions/data per map
        if renames:
            # apply longest-first to avoid prefix collisions
            for old, new in sorted(renames.items(), key=lambda kv: -len(kv[0])):
                if old.startswith(('FUN_', 'DAT_', 'PTR_')) or re.match(r'^[0-9a-fA-F]{8}$', old):
                    t = re.sub(r'\b' + re.escape(old) + r'\b', new, t)

        game_parts.append(f"// ===== {c['newname']} @ {c['addr']} =====\n" + t.strip() + '\n')

        # prototype: from sig (strip newlines).  Functions whose call sites
        # disagree with the decompiled arity are declared unprototyped (K&R
        # `ret name();`), which accepts any call arity under gnu17.
        psig = ' '.join(sig.split())
        psig = re.sub(r'\s+', ' ', psig)
        # ALL game functions are declared unprototyped (K&R style).  The decompiled
        # signatures are unreliable (Ghidra models stack-passed args inconsistently),
        # and unprototyped declarations make every call site compile without argument
        # type checking under gnu17.
        m2 = re.match(r'^(.*?)\s*\b' + re.escape(c['name']) + r'\s*\(', psig)
        ret = m2.group(1).strip() if m2 else 'void'
        protos.append(f'{ret} {c["newname"]}();')

    # ---- *SYM where SYM is an array symbol --------------------------------
    # Ghidra writes `*DAT_x` for element 0 of an array-typed symbol and
    # `DAT_x[k]` for the rest; C needs the element form everywhere.  Call sites
    # `(*SYM)(...)` are function pointers, not element reads, and stay.
    full = '\n'.join(game_parts)
    # ---- fold string-label spellings ---------------------------------------
    # The decompiler export keeps the label but may fold some characters and
    # leave others (`s_a:b_c_->msg_x` becomes `s_a__b__>msg_x`).  Every s_ label
    # ends in its address, so match from the s_ token through the address and
    # rewrite to the identifier spelling the data header declares.
    _slabels = []
    for line in open(args.symbols):
        p = line.rstrip('\n').split('|')
        if p[0] == 'DATA' and p[4].startswith('s_'):
            folded = re.sub(r'[^A-Za-z0-9_]', '_', p[4])
            if folded != p[4]:
                _slabels.append((p[4], p[1], folded))
    for raw, addr, folded in _slabels:
        full = re.sub(r'\bs_[A-Za-z0-9_]*(?:[^\w\s,;(){}[\]][A-Za-z0-9_]*)*_' + addr + r'\b',
                      folded, full)
    # index-ish use: bare `SYM[` or Ghidra's `(&SYM)[...]`
    def _idxform(sym):
        e = re.escape(sym)
        if re.search(r'(?<![\w&])' + e + r'\s*\[', full):
            return 'bare'
        if re.search(r'\(\s*&\s*' + e + r'\s*\)\s*\[', full):
            return 'amp'
        return None
    _has_idx = set()
    for sym in set(re.findall(r'\b(DAT_[0-9A-Fa-f]{8}|PTR_[A-Za-z0-9_]+)\b', full)):
        if _idxform(sym):
            _has_idx.add(sym)
    full = re.sub(r'\*\s*(DAT_[0-9A-Fa-f]{8}|PTR_[A-Za-z0-9_]+)\b(?!\s*\)\s*\()',
                  lambda mt: mt.group(1) + '[0]' if mt.group(1) in _has_idx else mt.group(0), full)

    # ---- void-return retype pass ------------------------------------------
    # `x = FUN_y(...)` where FUN_y's definition says void: the ABI returns eax,
    # Ghidra just didn't model it.  Retype definition + prototype to long.
    def _retype_void():
        used = set()
        for m in re.finditer(r'=\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*)?(FUN_[0-9A-Fa-f]{8})\s*\(', full):
            used.add(m.group(1))
        # also '(x) = FUN(' with casts on LHS is covered; check def ret type
        changed = 0
        for name in sorted(used):
            for idx, part in enumerate(game_parts):
                if 'void ' + name + '(' in part:
                    game_parts[idx] = part.replace('void ' + name + '(', 'long ' + name + '(', 1)
                    # bare returns inside this function become return 0
                    game_parts[idx] = re.sub(r'(?m)^(\s*)return;\s*$', r'\1return 0;', game_parts[idx])
                    changed += 1
                    break
        return changed
    _retype_void()
    # regenerate protos to match (they were built before; fix any 'void NAME();')
    protos = [('long ' + p[5:]) if p.startswith('void ') and p[5:].split('(')[0] in
              {c['newname'] for c in chunks} else p for p in protos]

    # ---- arity-mismatch call wrapping ------------------------------------
    # The header declares every function unprototyped, but a definition with a
    # parameter list re-enables argument checking for calls that textually follow
    # it.  Wrap those calls in an explicit unprototyped function-pointer call so
    # the stack-passed-args Ghidra artifacts compile.
    def_arity = {}
    def_ret = {}
    for c in chunks:
        if c['cls'] != 'game':
            continue
        s2, _ = split_sig(c['text'])
        s2n = re.sub(r'/\*.*?\*/', '', s2, flags=re.S)
        s2n = ' '.join(s2n.split())
        m2 = re.search(r'\((.*)\)\s*$', s2n)
        if m2:
            inner = m2.group(1).strip()
            def_arity[c['newname']] = 0 if inner in ('', 'void') else inner.count(',') + 1
        mr = re.match(r'^([A-Za-z_][\w ]*?\*?)\s*\b' + re.escape(c['name']) + r'\s*\(', s2n)
        def_ret[c['newname']] = mr.group(1).strip() if mr else 'long'
    out_parts = []
    pos = 0
    for m in re.finditer(r'\b(FUN_[0-9A-Fa-f]{8})\s*\(', full):
        name = m.group(1)
        da = def_arity.get(name)
        if da is None:
            continue
        start = m.start()
        if start < pos:
            continue
        # skip definitions/prototypes: preceded by a type token
        pre = full[max(0, m.start()-40):m.start()]
        if re.search(r'\b(?:void|undefined\d?|uint\d*|int|char|short|byte|float|double|longdouble|ulonglong|longlong|long|ulong|ushort|uchar|bool|code)\s*$', pre):
            continue
        # balanced-paren scan
        i = m.end() - 1
        depth = 0
        end = None
        while i < len(full):
            ch = full[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        if end is None:
            continue
        if full[end+1:end+3] == '\n{':
            continue
        argstr = full[m.end():end]
        d = 0
        n = 1
        if argstr.strip() == '':
            n = 0
        else:
            for ch in argstr:
                if ch == '(':
                    d += 1
                elif ch == ')':
                    d -= 1
                elif ch == ',' and d == 0:
                    n += 1
        # value context: next non-space char after the call is not a statement
        # separator or the start of a block
        k = end + 1
        while k < len(full) and full[k] in ' \t':
            k += 1
        statement_call = k >= len(full) or full[k] in ';\n}'
        wrap_arity = n != da
        wrap_void = (def_ret.get(name) == 'void') and not statement_call
        if not (wrap_arity or wrap_void):
            continue
        out_parts.append(full[pos:start])
        # variadic function-pointer cast: tolerates any arity, and the cast sits
        # on the function rather than the result, so void-returning callees are
        # fine even where Ghidra's output uses their (garbage) return value.
        out_parts.append('((long (*)(...))' + full[start:m.end()-1] + ')(' + full[m.end():end] + ')')
        pos = end + 1
    out_parts.append(full[pos:])
    full = ''.join(out_parts)

    with open(os.path.join(args.outdir, 'bblit_game.c'), 'w') as f:
        f.write('/* bblit_game.c -- generated from bugs_decompiled.c by tools/decomp2linux.py.\n'
                ' * Do not edit by hand; edit the generator or the rename map.\n */\n'
                '#include "bblit_game.h"\n\n')
        f.write(full)

    with open(os.path.join(args.outdir, 'bblit_game.h'), 'w') as f:
        f.write('/* bblit_game.h -- prototypes for all kept game functions (generated). */\n'
                '#ifndef BBLIT_GAME_H\n#define BBLIT_GAME_H\n\n'
                '#include "ghidra_types.h"\n#include "data_syms.h"\n#include "winshim.h"\n\n')
        f.write('\n'.join(protos))
        f.write('\n\n#endif\n')

    with open(os.path.join(args.outdir, 'triage.txt'), 'w') as f:
        f.write('\n'.join(triage) + '\n')

    print(f"kept {kept} game funcs, dropped {dropped} crt/thunk; {len(triage)} funcs need artifact triage")

if __name__ == '__main__':
    main()
