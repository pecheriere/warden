#!/usr/bin/env bash
# Fail if any of reqwest's response-decompression features is enabled for the
# broker anywhere in the resolved dependency graph.
#
# The API proxy redacts secrets from response bodies and relies on receiving
# them uncompressed (it sends `Accept-Encoding: identity` and refuses
# compressed responses). With `gzip`, `brotli`, `zstd` or `deflate` enabled,
# reqwest would decompress transparently and that assumption would silently
# change. The features may be switched on by another crate through feature
# unification, so this inspects the resolved graph rather than Cargo.toml.
set -euo pipefail

cd "$(dirname "$0")/.."

# `--target all` covers every platform, `--all-features` every broker feature;
# normal, build and dev edges are all included by default.
tree="$(cargo tree -e features -p warden-broker --all-features --target all --locked --prefix none)"

# Guard against a vacuous pass: the output format or package name changing
# must not make the check silently match nothing.
if ! grep -q '^reqwest v' <<<"$tree"; then
  echo "error: reqwest not found in the warden-broker dependency graph" >&2
  exit 1
fi

if offending="$(grep -E '^reqwest feature "(gzip|brotli|zstd|deflate)"$' <<<"$tree" | sort -u)"; then
  echo "error: reqwest decompression feature(s) enabled for warden-broker:" >&2
  echo "$offending" >&2
  echo "Secret redaction requires uncompressed responses; see docs/threat-model.md." >&2
  exit 1
fi

echo "ok: no reqwest decompression features enabled"
