#!/usr/bin/env bash
# Fail unless the Claude Code plugin's version equals the workspace version.
#
# plugins/warden/.claude-plugin/plugin.json is bumped by the release pull
# request with the rest, and `warden setup claude` pins the marketplace to the
# tag of the CLI's version, so a plugin that names another version would be
# installed from a tag that does not hold it.
#
# Usage: scripts/check-plugin-version.sh
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "error: $*" >&2
  exit 1
}

manifest=plugins/warden/.claude-plugin/plugin.json
[ -f "$manifest" ] || fail "$manifest not found"

# The first `version` key of the [workspace.package] table.
workspace="$(awk '
  /^\[/ { in_table = ($0 == "[workspace.package]"); next }
  in_table && /^version[[:space:]]*=/ {
    split($0, parts, "\"")
    print parts[2]
    exit
  }' Cargo.toml)"
[ -n "$workspace" ] || fail "no version in [workspace.package] of Cargo.toml"

plugin="$(python3 -I -c '
import json, sys
print(json.load(open(sys.argv[1])).get("version", ""))' "$manifest")"
[ -n "$plugin" ] || fail "$manifest has no version"

[ "$plugin" = "$workspace" ] \
  || fail "$manifest says $plugin but the workspace version is $workspace"

echo "ok: the plugin's version is $workspace, the workspace version"
