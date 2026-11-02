#!/usr/bin/env bash
# Run fuzz targets for a fixed time each, on the toolchain fuzz/rust-toolchain.toml
# pins. Needs cargo-fuzz (see "Fuzzing" in AGENTS.md).
#
# Each target reads its committed inputs in fuzz/seeds/<target>, so every earlier
# crash is replayed first, and keeps what it discovers in the ignored
# fuzz/corpus/<target>. A crash leaves the input in fuzz/artifacts/<target>.
#
# With --quiet the fuzzer's output is discarded: it holds the crashing input and a
# stack trace, which must not reach the public CI log before a fix (see
# SECURITY.md). Only the target, the result and the random seed are printed; rerun
# with --seed and that seed to look for the crash.
#
# Usage: scripts/fuzz.sh [--quiet] [--seed N] [--jobs N] <seconds> [target ...]
#        (with no target, all of them)
set -euo pipefail

cd "$(dirname "$0")/../fuzz"

quiet=false
seed="${RANDOM}${RANDOM}"
jobs=1
while (($#)); do
  case "$1" in
    --quiet) quiet=true ;;
    --seed) seed="$2"; shift ;;
    --jobs) jobs="$2"; shift ;;
    *) break ;;
  esac
  shift
done
if (($# < 1)) || ! [[ "$1" =~ ^[1-9][0-9]*$ ]] || ! [[ "$seed" =~ ^[0-9]+$ ]] || ! [[ "$jobs" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: scripts/fuzz.sh [--quiet] [--seed N] [--jobs N] <seconds> [target ...]" >&2
  exit 2
fi
seconds="$1"
shift

# The targets, or an error rather than a run of nothing.
if (($# > 0)); then
  targets=("$@")
else
  targets=()
  while IFS= read -r target; do
    targets+=("$target")
  done < <(cargo fuzz list)
  if ((${#targets[@]} == 0)); then
    echo "error: no fuzz targets found" >&2
    exit 1
  fi
fi

failed=0
for target in "${targets[@]}"; do
  mkdir -p "corpus/$target"
  # A slow input counts as a crash: it would be a denial of service.
  command=(cargo fuzz run --jobs "$jobs" "$target" "corpus/$target" "seeds/$target" --
    "-max_total_time=$seconds" "-seed=$seed" -timeout=20 -rss_limit_mb=2048)
  if "$quiet"; then
    if "${command[@]}" >/dev/null 2>&1; then
      echo "$target: no crash in ${seconds}s (seed $seed)"
    else
      echo "$target: FAILED (seed $seed); the output is withheld, rerun it locally"
      failed=1
    fi
  elif ! "${command[@]}"; then
    echo "$target: FAILED (seed $seed)"
    failed=1
  fi
done
exit "$failed"
