#!/usr/bin/env bash
# audit_bundle_deps.sh
#
# Self-containment auditor for a Apk on Mac .app bundle. Walks every Mach-O
# file inside Contents/ (executables and dylibs), runs `otool -L` on each,
# and flags any linked dependency that is NOT one of:
#   - a macOS system path (/usr/lib/..., /System/...)
#   - @rpath/..., @loader_path/..., @executable_path/...
#   - the file's own id (for a dylib, otool -L's first line)
#
# A non-empty flagged list means the bundle depends on something outside
# itself -- Homebrew, a system JDK, MacPorts, etc -- and will fail on a
# clean Mac with none of that installed. See CLAUDE.md's "runtime freshness"
# / self-containment work (added 2026-08-14) for why this matters: a Dock
# launch does not inherit a login shell's PATH, so a bare tool-name shellout
# (the then-bundled `apktool` was the 2026-08-14 case) silently no-ops on a
# real user's machine even though it works fine from a developer's terminal.
#
# Usage:
#   scripts/audit_bundle_deps.sh [path/to/Apk on Mac.app]
#
# Exit code: 0 if fully self-contained, 1 if any external dependency found.
# Always prints the full otool -L output for every Mach-O, so this doubles
# as the "before" / "after" evidence dump for a bundling change.

set -uo pipefail

APP="${1:-build/Apk on Mac.app}"
if [ ! -d "$APP" ]; then
    echo "ERROR: $APP not found." >&2
    exit 2
fi

echo "=== Bundle self-containment audit: $APP ==="
echo "    (generated $(date '+%Y-%m-%d %H:%M %Z'))"
echo

any_external=0
file_count=0

# Find every regular file under Contents/ and let `file` decide if it's
# Mach-O (covers binaries with no +x bit, e.g. some dylibs, and skips
# non-Mach-O resources like jars/pngs/plists without hardcoding names).
while IFS= read -r -d '' f; do
    magic="$(file -b "$f" 2>/dev/null)"
    case "$magic" in
        Mach-O*) ;;
        *) continue ;;
    esac
    file_count=$((file_count + 1))
    rel="${f#"$APP"/}"

    echo "--- $rel ---"
    otool -L "$f" 2>&1 | sed 's/^/    /'

    # otool -L prints one un-indented "<path>[ (architecture X)]:" header
    # line PER SLICE (a universal/fat binary has more than one -- e.g.
    # libMoltenVK.dylib ships x86_64 AND arm64), followed by indented
    # dependency lines. A naive `tail -n +2` only strips the FIRST header,
    # so a second slice's header gets misread as a dependency on a fat
    # binary. Dependency lines are the only ones that start with a literal
    # tab, so filter on that instead of position -- this is what actually
    # caught libMoltenVK.dylib's absolute self-reference (its LC_ID_DYLIB
    # is the same absolute path in BOTH slices' headers, which are not
    # dependency lines at all and must not be double-counted as one).
    external_for_file=""
    while IFS= read -r line; do
        path="$(echo "$line" | sed -E 's/^[[:space:]]*//; s/ \(.*\)$//')"
        [ -z "$path" ] && continue
        case "$path" in
            @rpath/*|@loader_path/*|@executable_path/*) ;;
            /usr/lib/*|/System/*) ;;
            *)
                external_for_file="${external_for_file}      EXTERNAL: ${path}\n"
                any_external=1
                ;;
        esac
    done < <(otool -L "$f" 2>/dev/null | grep -E $'^\t')

    if [ -n "$external_for_file" ]; then
        printf "%b" "$external_for_file"
    fi
done < <(find "$APP/Contents" -type f -print0)

echo
echo "=== Summary: $file_count Mach-O file(s) inspected ==="
if [ "$any_external" -eq 0 ]; then
    echo "PASS: zero non-system, non-@rpath/@loader_path/@executable_path paths found."
    exit 0
else
    echo "FAIL: external dependencies found (see EXTERNAL lines above)."
    exit 1
fi
