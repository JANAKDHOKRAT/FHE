#!/usr/bin/env bash
# Checks the OpenFHE pin against upstream, so that "advisories are tracked by
# hand" becomes a CI job. Exits non-zero (with one line per finding) when:
#   1. the pinned tag no longer resolves to the pinned commit (retagged);
#   2. upstream has published a security advisory after the pinned release;
#   3. upstream's latest release is newer than the pin.
# Findings 1 and 2 are always failures. Finding 3 is a failure too: the pin
# is deliberate (AUDIT.md §8), and moving it means re-running the shim's
# rebuild self-test and the ceremony measurements, but a newer upstream is
# something the deployer must know about, not discover.
#
# Usage: openfhe-pin-check.sh <tag> <commit>      (needs curl and jq)
# GITHUB_TOKEN, if set, raises the API rate limit; unauthenticated works.
set -euo pipefail

tag="${1:?pinned tag, e.g. v1.3.1}"
commit="${2:?pinned commit sha}"
repo="openfheorg/openfhe-development"
# GitHub Actions sets GITHUB_API_URL; a local run may point it at a mock.
api="${GITHUB_API_URL:-https://api.github.com}"

auth=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi
get() {
  curl -sS --fail-with-body "${auth[@]}" -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" "$api/$1"
}

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# 1. The tag must still point at the pinned commit. A lightweight tag's
#    ref object is the commit; an annotated tag's is a tag object to
#    dereference.
ref="$(get "repos/$repo/git/ref/tags/$tag")"
obj_type="$(jq -r .object.type <<<"$ref")"
obj_sha="$(jq -r .object.sha <<<"$ref")"
if [[ "$obj_type" == "tag" ]]; then
  obj_sha="$(get "repos/$repo/git/tags/$obj_sha" | jq -r .object.sha)"
fi
if [[ "$obj_sha" != "$commit" ]]; then
  fail "tag $tag resolves to $obj_sha, the pin is $commit (the tag moved)"
else
  echo "ok: $tag -> $commit"
fi

# 2. No security advisory published after the pinned release.
release="$(get "repos/$repo/releases/tags/$tag")"
pinned_at="$(jq -r .published_at <<<"$release")"
advisories="$(get "repos/$repo/security-advisories?state=published&per_page=100")"
count="$(jq 'length' <<<"$advisories")"
newer="$(jq -r --arg t "$pinned_at" '[.[] | select(.published_at > $t)] | .[] | "\(.ghsa_id) \(.severity) \(.summary)"' <<<"$advisories")"
if [[ -n "$newer" ]]; then
  while IFS= read -r line; do fail "advisory after $tag ($pinned_at): $line"; done <<<"$newer"
else
  echo "ok: $count published advisories, none after $tag ($pinned_at)"
fi

# 3. The latest upstream release is the pin.
latest="$(get "repos/$repo/releases/latest" | jq -r .tag_name)"
if [[ "$latest" != "$tag" ]]; then
  fail "upstream latest release is $latest, the pin is $tag: read its notes and re-validate the shim before moving the pin"
else
  echo "ok: $tag is upstream's latest release"
fi

if (( failures > 0 )); then
  echo "$failures finding(s)"
  exit 1
fi
