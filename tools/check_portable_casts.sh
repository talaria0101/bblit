#!/bin/sh
# check_portable_casts.sh -- fail if any generated source has reintroduced the
# bare-`...` function-pointer cast.
#
# Why this is a guard and not a note: `(T (*)(...))` is a gcc extension.  ISO C
# requires a named parameter in front of `...`, so clang rejects every such cast
# outright ("ISO C requires a named parameter before '...'"), and the ported
# tree has ~400 of them.  The failure only shows up on a toolchain that is not
# the one the tree was developed on, which is exactly the kind of regression
# nobody notices until a fresh clone on a different distro won't build.
#
# The portable spelling is the unprototyped `(T (*)())`, which both compilers
# accept.  The generator in tools/decomp2linux.py emits that form, and the
# normalization pass in tools/fix_loop.py rewrites older output, so this check
# guards both the generated file and any hand-edited regression.
#
# Exits 0 when clean, 1 when a bare-`...` cast is present.
set -e
cd "$(dirname "$0")/.."

FILES="linux/bblit_game.c linux/data_syms.c linux/port_main.c linux/shim/winapi_table.c linux/shim/winapi_stubs.c linux/shim/shim_crt.c linux/shim/port_helpers.c"

rc=0
for f in $FILES; do
    if [ ! -f "$f" ]; then
        echo "check_portable_casts: missing source $f" >&2
        rc=1
        continue
    fi
    # `(*)` immediately followed by a parenthesised `...` is the bad spelling.
    # Both the generator output and the fix_loop normalization target this.
    if grep -nE '\(\*\)\s*\(\s*\.\.\.\s*\)' "$f" >/dev/null 2>&1; then
        echo "check_portable_casts: FAIL $f uses the bare-\`...\` cast (gcc-only):" >&2
        grep -nE '\(\*\)\s*\(\s*\.\.\.\s*\)' "$f" | head -5 >&2
        rc=1
    fi
done

if [ "$rc" -eq 0 ]; then
    echo "check_portable_casts: OK (no bare-\`...\` casts)"
fi
exit $rc