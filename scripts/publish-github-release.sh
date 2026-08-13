#!/usr/bin/env bash
#
# Publish a built release to GitHub Releases.
#
#   scripts/publish-github-release.sh [version]
#
# The installer's `auto` source tries the release host first and GitHub second.
# That fallback is only worth having if GitHub actually carries the current
# release: with the newest tag months behind the sources, an install on a path
# where the host is unreachable falls all the way through to a source build,
# which then needs a Go toolchain from a third host that may be unreachable too.
# One published release turns three chances of failure into one.
#
# Needs a token with `contents: write` on the repo, in GH_TOKEN or GITHUB_TOKEN.
# Create one at https://github.com/settings/tokens — nothing else here reads it,
# and it is never written to disk.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-$(tr -d '[:space:]' < "${ROOT}/VERSION")}"
VERSION="${VERSION#v}"
SLUG="${ET_REPO_SLUG:-AMirHossein-donyavii/tunnel}"
RELDIR="${ROOT}/release/releases/v${VERSION}"
TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

die() { printf '  \033[38;5;203m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ok()  { printf '  \033[38;5;114m✓\033[0m %s\n' "$*"; }

[ -n "$TOKEN" ] || die "set GH_TOKEN (or GITHUB_TOKEN) to a token with contents:write on ${SLUG}"
[ -d "$RELDIR" ] || die "no build at ${RELDIR} — run scripts/build-release.sh ${VERSION} first"
[ -f "${RELDIR}/SHA256SUMS" ] || die "${RELDIR} has no SHA256SUMS — that build is incomplete"

api() { # api <method> <url> [data]
    curl -sS -X "$1" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        ${3:+-H "Content-Type: application/json" -d "$3"} \
        "$2"
}

# The changelog section for this version, as the release notes. A release whose
# notes say nothing is a release nobody can tell apart from the last one.
notes="$(awk -v v="## [${VERSION}]" '
    index($0, v) == 1 { on = 1; next }
    on && /^## \[/     { exit }
    on                 { print }
' "${ROOT}/CHANGELOG.md")"
[ -n "${notes//[[:space:]]/}" ] || notes="See CHANGELOG.md."

echo "==> Creating v${VERSION} on ${SLUG}"
body="$(python3 - "$VERSION" "$notes" <<'PY'
import json, sys
v, notes = sys.argv[1], sys.argv[2]
print(json.dumps({"tag_name": f"v{v}", "name": f"v{v}", "body": notes.strip(),
                  "draft": False, "prerelease": False}))
PY
)"
resp="$(api POST "https://api.github.com/repos/${SLUG}/releases" "$body")"
upload="$(printf '%s' "$resp" | sed -n 's/.*"upload_url":[[:space:]]*"\([^"{]*\).*/\1/p')"

if [ -z "$upload" ]; then
    # Most likely the tag already exists; reuse that release rather than failing.
    resp="$(api GET "https://api.github.com/repos/${SLUG}/releases/tags/v${VERSION}")"
    upload="$(printf '%s' "$resp" | sed -n 's/.*"upload_url":[[:space:]]*"\([^"{]*\).*/\1/p')"
    [ -n "$upload" ] || die "could not create or find release v${VERSION}: $(printf '%s' "$resp" | head -c 300)"
    echo "    release already exists — replacing its assets"
    relid="$(printf '%s' "$resp" | sed -n 's/.*"id":[[:space:]]*\([0-9]*\).*/\1/p' | head -n1)"
    for id in $(api GET "https://api.github.com/repos/${SLUG}/releases/${relid}/assets" \
                | sed -n 's/.*"id":[[:space:]]*\([0-9]*\).*/\1/p'); do
        api DELETE "https://api.github.com/repos/${SLUG}/releases/assets/${id}" >/dev/null || true
    done
fi

# The installer downloads exactly these four plus SHA256SUMS, so exactly these
# are uploaded — an asset list that does not match what the installer asks for
# produces a release that resolves and then fails halfway through.
echo "==> Uploading assets"
for f in et-core-linux-amd64 et-core-linux-arm64 et-core-linux-armv7 \
         et-panel.sh uninstall.sh emergency-tunnel@.service SHA256SUMS; do
    [ -f "${RELDIR}/${f}" ] || die "missing ${f} in ${RELDIR}"
    curl -sS -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@${RELDIR}/${f}" \
        "${upload}?name=${f}" >/dev/null || die "upload failed: ${f}"
    ok "$f"
done
[ -f "${RELDIR}/SHA256SUMS.minisig" ] && curl -sS -X POST \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/octet-stream" \
    --data-binary "@${RELDIR}/SHA256SUMS.minisig" \
    "${upload}?name=SHA256SUMS.minisig" >/dev/null && ok "SHA256SUMS.minisig"

echo
ok "https://github.com/${SLUG}/releases/tag/v${VERSION}"
echo
echo "  Installs that cannot reach the release host will now use this:"
echo "    curl -fsSL https://raw.githubusercontent.com/${SLUG}/main/scripts/install.sh | bash -s -- --source github"
