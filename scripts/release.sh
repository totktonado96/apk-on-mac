#!/usr/bin/env bash
# release.sh [--no-notarize]
#
# The ONE command that produces a shippable, notarized, stapled Mac.apk DMG.
# Wraps scripts/build_dist.sh with this machine's signing + notary settings so
# nobody has to remember them (and so they are not pasted into a shell history
# or a commit message).
#
# Settings live in an UNTRACKED scripts/.release.env, because the signing
# identity and issuer id are account identifiers -- not secrets, but they do not
# belong in a repo that may be public. Copy .release.env.example and fill it in
# on a new machine. The App Store Connect .p8 itself is never read by this
# script or by us: notarytool takes it BY PATH.
#
# Verified end to end 2026-08-21 (v1.0.1020): app + dmg both "status: Accepted",
# all six entitlements SURVIVED notarization (incl. custom-x18-abi-toggle), and
# `spctl -a -vvv -t install` reports "accepted / source=Notarized Developer ID".
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ENVF="$HERE/.release.env"
if [ -f "$ENVF" ]; then
    # shellcheck disable=SC1090
    . "$ENVF"
else
    echo "ERROR: $ENVF not found." >&2
    echo "       Copy scripts/.release.env.example and fill in the three values." >&2
    exit 1
fi

: "${MACAPK_SIGN_IDENTITY:?set MACAPK_SIGN_IDENTITY in scripts/.release.env}"
: "${MACAPK_NOTARY_ISSUER:?set MACAPK_NOTARY_ISSUER in scripts/.release.env}"
export MACAPK_SIGN_IDENTITY MACAPK_NOTARY_ISSUER
[ -n "${MACAPK_NOTARY_KEY:-}" ] && export MACAPK_NOTARY_KEY
[ -n "${MACAPK_NOTARY_KEY_ID:-}" ] && export MACAPK_NOTARY_KEY_ID

ARGS=(--dmg --notarize)
for a in "$@"; do
    case "$a" in
        --no-notarize) ARGS=(--dmg) ;;
        *) ARGS+=("$a") ;;
    esac
done

# Bake the release number into the launcher (BuildInfo.releaseVersion, read by
# launcher/UpdateCheck.swift). This build is the one uploaded to GitHub
# Releases, so it is the only one that should compare itself against the
# latest release there; every other build bakes nil. Tag the release
# "v<this number>" so the comparison lines up.
MACAPK_RELEASE_VERSION="$(tr -d '[:space:]' < "$HERE/../VERSION")"
export MACAPK_RELEASE_VERSION
echo "Baking release version $MACAPK_RELEASE_VERSION (tag the GitHub release v$MACAPK_RELEASE_VERSION)"

echo "Releasing with identity: $MACAPK_SIGN_IDENTITY"
exec "$HERE/build_dist.sh" "${ARGS[@]}"
