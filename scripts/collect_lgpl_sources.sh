#!/usr/bin/env bash
# collect_lgpl_sources.sh <out-dir> [--upload <tag>]
#
# Gather the COMPLETE CORRESPONDING SOURCE of every LGPL library Mac.apk ships,
# for the exact versions in the build, so each GitHub release can carry it as
# release assets (owner, 2026-10-02: "Lets fully comply").
#
# WHY: Contents/Resources/jre/lib ships two LGPL-2.1-or-later libraries that the
# Homebrew-built JDK links -- GLib (libglib-2.0.0.dylib) and GNU gettext's libintl
# (libintl.8.dylib); scripts/stage_jre.sh copies them from the LINKED Homebrew
# kegs. LGPL-2.1 section 6(d) is satisfied when the source is offered from the
# SAME place as the binary, so the release that carries macapk.dmg must also
# carry these files. A pointer to the upstream project alone is the weaker form.
#
# WHAT IT COLLECTS, per library, from the keg's own build recipe
# (<keg>/.brew/<formula>.rb, the exact recipe Homebrew built that keg from):
#   - the upstream source tarball (the recipe's top-level `url`), verified
#     against the recipe's `sha256` -- a mismatch is FATAL, never a warning;
#   - every `patch do ... url/sha256 ... end` the recipe applies, verified the
#     same way, plus any inline `patch :DATA` text after `__END__`;
#   - the recipe itself (homebrew-<formula>.rb), which holds the build commands
#     and any `inreplace` edits;
#   - LGPL-SOURCE-README.txt: checksums, what Mac.apk changed (load-path
#     metadata only), and how to use a modified build.
#
#   scripts/collect_lgpl_sources.sh ../scratch/lgpl_src
#   scripts/collect_lgpl_sources.sh ../scratch/lgpl_src --upload v1.0.1667
#
# --upload runs `gh release upload <tag> <files> --clobber` on
# kksimp/Mac.apk-Releases. Run it as a release step, after the DMG is built
# from the same kegs (scripts/gen_third_party_notices.sh names these versions).
set -euo pipefail

OUT="${1:?usage: collect_lgpl_sources.sh <out-dir> [--upload <tag>]}"
TAG=""
[ "${2:-}" = "--upload" ] && TAG="${3:?--upload needs a release tag}"
REPO_SLUG="${MACAPK_RELEASES_SLUG:-kksimp/Mac.apk-Releases}"

# formula : the dylib Mac.apk ships from it
LIBS="glib:libglib-2.0.0.dylib gettext:libintl.8.dylib"

mkdir -p "$OUT"
files=()
readme="$OUT/LGPL-SOURCE-README.txt"

fetch_verified() {   # <url> <sha256> <dest>
    local url="$1" sum="$2" dest="$3" got
    if [ ! -f "$dest" ] || [ "$(shasum -a 256 "$dest" | cut -d' ' -f1)" != "$sum" ]; then
        curl -fsSL -o "$dest.part" "$url"
        mv -f "$dest.part" "$dest"
    fi
    got="$(shasum -a 256 "$dest" | cut -d' ' -f1)"
    if [ "$got" != "$sum" ]; then
        echo "FATAL: $dest sha256 $got != recipe $sum ($url)" >&2
        exit 1
    fi
}

{
cat <<'HDR'
Mac.apk -- LGPL source for the libraries it ships
================================================

Mac.apk's bundle contains two libraries licensed under the GNU Lesser General
Public License, version 2.1 or (at your option) any later version:

  Contents/Resources/jre/lib/libglib-2.0.0.dylib   GLib
  Contents/Resources/jre/lib/libintl.8.dylib       GNU gettext runtime (libintl)

They are used by the Java runtime's font stack (HarfBuzz uses GLib, GLib uses
libintl). The files attached to this release are the complete corresponding
source for the exact versions shipped: the upstream source tarball, every patch
applied to it, and the build recipe (Homebrew formula) the binaries were built
from. The full LGPL-2.1 text is in THIRD_PARTY_NOTICES.txt.

What Mac.apk changed: nothing in the code. scripts/stage_jre.sh copies each
library unmodified and only rewrites Mach-O load-path metadata (the install
name becomes @rpath/<name>, an @loader_path rpath is added, and references to
sibling libraries become @rpath/<name>), then the bundle is code-signed.

Using a modified version: build an interface-compatible library from this
source, put it in Contents/Resources/jre/lib/ under the same file name, and
re-sign the app (replacing a file invalidates Mac.apk's Developer ID
signature). Mac.apk's runtime is signed with library validation disabled, so
it loads a substituted library. Mac.apk copies its runtime, including these
files, to ~/Library/Application Support/Mac.apk/runtime/ when an app next
starts after Mac.apk changes.

HDR
} > "$readme"

for pair in $LIBS; do
    f="${pair%%:*}"; dylib="${pair#*:}"
    keg="$(cd "/opt/homebrew/opt/$f" 2>/dev/null && pwd -P)" || { echo "FATAL: no keg for $f" >&2; exit 1; }
    ver="$(basename "$keg")"; ver="${ver%_*}"
    rb="$keg/.brew/$f.rb"
    [ -f "$rb" ] || { echo "FATAL: $rb missing (cannot prove the recipe)" >&2; exit 1; }

    # Top-level source: the first 2-space-indented url/sha256 pair.
    url="$(awk '/^  url "/{gsub(/^  url "|"$/,""); print; exit}' "$rb")"
    sum="$(awk '/^  sha256 "/{gsub(/^  sha256 "|"$/,""); print; exit}' "$rb")"
    src="$OUT/$(basename "$url")"
    fetch_verified "$url" "$sum" "$src"
    files+=("$src")
    printf '%s %s (%s)\n  source  %s\n          sha256 %s\n          from %s\n' \
        "$f" "$ver" "$dylib" "$(basename "$src")" "$sum" "$url" >> "$readme"

    # Patches: every `patch do ... end` block's url + sha256.
    n=0
    while IFS='|' read -r purl psum; do
        [ -z "$purl" ] && continue
        n=$((n + 1))
        pdest="$OUT/$f-$(basename "$purl")"
        fetch_verified "$purl" "$psum" "$pdest"
        files+=("$pdest")
        printf '  patch   %s\n          sha256 %s\n          from %s\n' "$(basename "$pdest")" "$psum" "$purl" >> "$readme"
    done < <(awk '/^  patch do/{p=1; u=""; s=""; next}
                  p && /^    url "/{u=$0; gsub(/^    url "|"$/,"",u)}
                  p && /^    sha256 "/{s=$0; gsub(/^    sha256 "|"$/,"",s)}
                  p && /^  end/{print u "|" s; p=0}' "$rb")
    if grep -q '^__END__' "$rb"; then
        sed -n '/^__END__/,$p' "$rb" | tail -n +2 > "$OUT/$f-inline.patch"
        files+=("$OUT/$f-inline.patch")
        printf '  patch   %s (inline in the recipe)\n' "$f-inline.patch" >> "$readme"
        n=$((n + 1))
    fi
    [ "$n" -eq 0 ] && printf '  patches none\n' >> "$readme"

    cp -f "$rb" "$OUT/homebrew-$f.rb"
    files+=("$OUT/homebrew-$f.rb")
    printf '  recipe  homebrew-%s.rb (build commands, including any in-place source edits)\n\n' "$f" >> "$readme"
done
files+=("$readme")

echo "collected into $OUT:"
for x in "${files[@]}"; do printf '  %-40s %s\n' "$(basename "$x")" "$(du -h "$x" | cut -f1)"; done

if [ -n "$TAG" ]; then
    gh release upload "$TAG" "${files[@]}" --clobber -R "$REPO_SLUG"
    echo "uploaded ${#files[@]} file(s) to $REPO_SLUG $TAG"
fi
