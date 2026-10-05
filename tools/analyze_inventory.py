#!/usr/bin/env python3
"""Inventory bugs_decompiled.c: functions, undefined identifiers, Ghidra artifacts."""
import re, sys, json, collections

SRC = sys.argv[1] if len(sys.argv) > 1 else '/workspace/bblit/bugs_decompiled.c'
text = open(SRC, encoding='utf-8', errors='replace').read()

# Split into function chunks: "// ===== FUN_00401000 @ 00401000 ====="
chunks = re.split(r'(?=^// ===== (FUN_[0-9a-f]{8}) @ )', text, flags=re.M)
funcs = []
i = 1
while i < len(chunks):
    name = chunks[i]
    body = chunks[i+1]
    funcs.append((name, body))
    i += 2

print(f"functions: {len(funcs)}")

# Ghidra builtin type names
G = set('undefined undefined2 undefined4 undefined8 char short int long longlong float double bool code'.split())
G |= set('uint ushort uchar uint8 uint16 uint32 int8 int16 int32 float2 double2 dword word byte'.split())
G |= set('pointer undefined *'.split())
G |= {'void'}

CRT = set('''memcpy memset memmove memcmp strlen strcpy strncpy strcat strcmp strncmp strchr strrchr
strstr strdup snprintf sprintf printf fprintf vfprintf puts putchar getchar scanf sscanf
malloc calloc realloc free exit abort atexit qsort bsearch abs labs fabs sin cos tan asin acos
atan atan2 sqrt pow floor ceil fmod exp log log10 modf
fopen fclose fread fwrite fseek ftell fgetc fputc fgets fputs feof ferror ungetc fflush setvbuf
open read write close lseek creat unlink rename remove
tolower toupper isdigit isspace isalpha isalnum isupper islower
atoi atol strtol strtoul strtod srand rand time clock
__ftol __ftol2 _ftol __chkstk _chkstk __alloca_probe
cosf sinf sqrtf fabsf floorf ceilf powf atan2f fmodf atanf acosf asinf tanf logf expf
_wtoi _stricmp _strnicmp stricmp strnicmp _snprintf _vsnprintf _itoa _ltoa _ultoa
'''.split())

# identifiers used
ident_re = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')
defined = set()   # functions defined in file + their locals won't matter
used = collections.Counter()
artifacts = collections.Counter()
func_set = set(n for n, _ in funcs)

ART_PAT = re.compile(r'\b(unaff_[A-Za-z0-9_]+|in_[A-Za-z0-9_]+|LAB_[0-9a-f]{8}|__ftol|__ftol2|stack0x[0-9a-f]+|s__[^" ]*|DAT_[0-9A-Fa-f]{8}|PTR_[A-Za-z0-9_]+|SUB_[0-9a-f]{8}|FUN_[0-9a-f]{8}|uStack[0-9a-fx]+|extraout_[A-Za-z0-9_]+|in_stack_[0-9a-fx]+)\b')

per_func_art = {}
for name, body in funcs:
    a = set(m.group(1) for m in ART_PAT.finditer(body))
    for m in ident_re.finditer(body):
        used[m.group(1)] += 1
    per_func_art[name] = a
    for k in a:
        artifacts[k] += 1

# Win32-ish & other externals: identifiers used but not defined locally, not CRT, not ghidra types, not locals
# locals heuristic: lowercase d/b/u/i + Var or local_
LOCAL = re.compile(r'^(local_|uStack|auStack|extraout|in_|unaff_|in_stack|apuStack|aiStack|afStack|acStack|aucStack|asStack|puStack|iStack|pcStack|ppuStack|puVar|ppbVar)')
ext = collections.Counter()
ext_uses = collections.defaultdict(set)
kw = set('if else while for do switch case return goto sizeof typedef struct union enum static const unsigned signed volatile extern register inline'.split())
for name, body in funcs:
    for m in ident_re.finditer(body):
        w = m.group(1)
        if w in G or w in kw or w in CRT or w in func_set: continue
        if LOCAL.match(w): continue
        if re.match(r'^(undefined|uint|uchar|ushort|uint|int8|int16|int32|longlong|float|double|code|char|short|long|bool|byte|word|dword|pointer|void)$', w): continue
        if re.match(r'^(b|c|d|f|i|l|pc|pd|pf|pi|pl|ppb|ppd|ppf|ppi|ppl|ppu|ps|pu|pv|pw|u|auc|au|ai|af|ac|as|a|ppc|ppu|in_)[a-zA-Z]*Var[0-9]+$', w): continue
        if re.match(r'^local_[0-9a-fA-F]+$', w): continue
        if w.startswith(('FUN_','DAT_','PTR_','SUB_','s_','LAB_')): continue
        ext[w] += 1
        ext_uses[w].add(name)

print("\n== artifact summary ==")
for k, v in artifacts.most_common(60):
    print(f"{v:5d}  {k}")

print(f"\n== external identifiers (used, not defined in file): {len(ext)} ==")
for k, v in sorted(ext.items(), key=lambda x: -x[1]):
    print(f"{v:5d}  {k}   used_in={len(ext_uses[k])}")

json.dump({'funcs':[n for n,_ in funcs],
           'artifacts':dict(artifacts),
           'externals':{k:v for k,v in ext.items()},
           'ext_uses':{k:sorted(v) for k,v in ext_uses.items()}},
          open('/workspace/bblit/tools/inventory.json','w'), indent=0)
print("\nwrote tools/inventory.json")
