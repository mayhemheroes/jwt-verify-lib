#!/usr/bin/env bash
#
# jwt-verify-lib/mayhem/test.sh — RUN google/jwt_verify_lib's own gtest suite (built by
# mayhem/build.sh with normal flags) and emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: these are the project's real known-answer tests — they parse fixed JWTs and
# JWKS and assert the exact parsed claims, statuses, and signature-verification verdicts (e.g.
# JwtParseTest asserts iss/sub/aud/exp; verify_jwk_*_test assert Status::Ok vs the precise failure
# status for tampered tokens). A no-op / exit(0) patch, or any change that alters parsing or
# verification behavior, fails these assertions. This script only RUNS the pre-built binaries; it
# never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

TBUILD="$SRC/mayhem-tests"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

if [ ! -d "$TBUILD" ] || ! ls "$TBUILD"/*_test >/dev/null 2>&1; then
  echo "missing gtest binaries in $TBUILD — run mayhem/build.sh first" >&2
  emit_ctrf "googletest" 0 1 0; exit 2
fi

PASS=0; FAIL=0
for t in "$TBUILD"/*_test; do
  echo "=== running $(basename "$t") ==="
  out="$("$t" 2>&1)"; rc=$?
  echo "$out" | tail -3
  # gtest summary lines: "[  PASSED  ] N tests." / "[  FAILED  ] N tests, ..."
  p="$(printf '%s\n' "$out" | sed -n 's/.*\[  PASSED  \] \([0-9][0-9]*\) test.*/\1/p' | tail -1)"
  f="$(printf '%s\n' "$out" | sed -n 's/.*\[  FAILED  \] \([0-9][0-9]*\) test.*/\1/p' | tail -1)"
  : "${p:=0}" "${f:=0}"
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then f=1; fi   # crash/abort with no parseable FAILED line
  PASS=$(( PASS + p )); FAIL=$(( FAIL + f ))
done

emit_ctrf "googletest" "$PASS" "$FAIL" 0
