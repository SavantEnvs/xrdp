#!/usr/bin/env bash
#
# mayhem/test.sh — RUNS xrdp's own check-based unit suites for libcommon, libipm and libxrdp (built by
# mayhem/build.sh with the normal flags). Each suite prints TAP; every `ok` line is a known-input ->
# known-output assertion made by the project's tests (parsers, dechunker, IPM encode/decode, MCS
# monitor data). The counts below are floors: a suite that dies early or is stubbed out falls short.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TST="$SRC/mayhem/build-test"
passed=0
failed=0
skipped=0
status=0

# run_suite <dir> <binary> <minimum number of passing assertions>
run_suite() {
  local dir="$1" bin="$2" min="$3" out rc ok nok sk
  if [ ! -x "$TST/tests/$dir/$bin" ]; then
    echo "missing test runner $TST/tests/$dir/$bin (mayhem/build.sh should have built it)" >&2
    failed=$(( failed + 1 )); status=1; return
  fi
  out=$(cd "$TST/tests/$dir" && ./"$bin" 2>/dev/null); rc=$?
  ok=$(printf '%s\n' "$out" | grep -c '^ok ')
  nok=$(printf '%s\n' "$out" | grep -c '^not ok ')
  sk=$(printf '%s\n' "$out" | grep -c '^ok .*# SKIP')
  echo "suite $dir: ok=$ok not_ok=$nok skipped=$sk exit=$rc (need >= $min ok)"
  passed=$(( passed + ok - sk )); failed=$(( failed + nok )); skipped=$(( skipped + sk ))
  if [ "$rc" -ne 0 ]; then failed=$(( failed + 1 )); status=1; fi
  if [ "$ok" -lt "$min" ]; then
    echo "suite $dir ran only $ok passing assertions, expected at least $min" >&2
    failed=$(( failed + 1 )); status=1
  fi
}

run_suite common test_common 150
run_suite libipm test_libipm 30
run_suite libxrdp test_libxrdp 10

emit_ctrf "check" "$passed" "$failed" "$skipped" || status=1
exit $status
