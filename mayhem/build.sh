#!/usr/bin/env bash
#
# jwt-verify-lib/mayhem/build.sh — build google/jwt_verify_lib's OSS-Fuzz harness as a sanitized
# libFuzzer target (+ a standalone reproducer), re-encode the upstream seed corpus, AND build the
# project's own gtest suite (normal flags) so mayhem/test.sh can RUN it.
#
# WHY NOT BAZEL: upstream + OSS-Fuzz drive this with Bazel (`bazel_build_fuzz_tests`) and
# libprotobuf-mutator. Bazel is not available in the org base image and is intractable to bootstrap,
# so we build directly with clang. The library is small (6 .cc) and its deps are:
#   - abseil          -> system libabsl-dev
#   - protobuf        -> system libprotobuf-dev + protoc (Struct/Value + JSON, message_differencer)
#   - BoringSSL       -> built from source here. REQUIRED: the lib uses BoringSSL-only APIs
#                        (openssl/curve25519.h, ED25519_verify, EVP_PKEY_ED25519). Stock OpenSSL
#                        has no curve25519.h, so system libssl-dev will NOT do.
#   - libprotobuf-mutator (harness only) -> avoided; the harness consumes the FuzzInput protobuf in
#                        wire format instead (see mayhem/harnesses/jwt_verify_lib_fuzzer.cc).
#
# Sanitizer note: building abseil's header-only swisstables under -fsanitize=address turns on
# abseil's generation-checking (ABSL_SWISSTABLE_ENABLE_GENERATIONS), whose generation_ pointer is
# only initialized by an ASan-built libabsl. We link the system (non-ASan) libabsl, so that pointer
# is null -> SEGV on the first hash insert. Defining -DNDEBUG_SANITIZER makes our TUs take the
# generations-OFF path that MATCHES the prebuilt libabsl (abseil's documented "performance is
# important" opt-out). This is NOT a sanitizer relax: ASan + full UBSan stay on and halting.

set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS= builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
PROTO_DIR="$SRC/test/fuzz"
PROTO="jwt_verify_lib_fuzz_input.proto"
BUILD="$SRC/mayhem-build"
GEN="$BUILD/gen"
mkdir -p "$BUILD" "$GEN"

ABSL_DIR="$(dirname "$(find /usr/lib /usr/local/lib -name 'libabsl_strings.so*' 2>/dev/null | head -1)")"
PB_CFLAGS="$(pkg-config --cflags protobuf 2>/dev/null || true)"
PB_LIBS="$(pkg-config --libs protobuf 2>/dev/null || echo -lprotobuf)"

# ── 1) BoringSSL crypto (the only crypto backend the lib compiles against) ─────────────────────────
BSSL_SRC="$SRC/mayhem-boringssl"
if [ ! -f "$BSSL_SRC/build/libcrypto.a" ]; then
  rm -rf "$BSSL_SRC"
  git clone --quiet --depth 1 https://github.com/google/boringssl.git "$BSSL_SRC"
  cmake -GNinja -S "$BSSL_SRC" -B "$BSSL_SRC/build" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
  ninja -C "$BSSL_SRC/build" crypto
fi
BSSL_INC="$BSSL_SRC/include"
BSSL_LIB="$BSSL_SRC/build/libcrypto.a"

# ── 2) Generate the fuzz-input protobuf C++ (used by the lib? no — only the harness) ───────────────
protoc --cpp_out="$GEN" -I "$PROTO_DIR" "$PROTO"

# Compile flags for the sanitized fuzz build. -DNDEBUG_SANITIZER: see header note above.
SAN_BUILD="$SANITIZER_FLAGS $DEBUG_FLAGS -DNDEBUG_SANITIZER"
INC="-Ijwt_verify_lib -I. -I$BSSL_INC -I$GEN $PB_CFLAGS"

# ── 3) Build jwt_verify_lib itself WITH sanitizers (the fuzzed code is instrumented) ───────────────
LIB_SRCS="src/check_audience.cc src/jwks.cc src/jwt.cc src/status.cc src/struct_utils.cc src/verify.cc"
OBJS=()
for s in $LIB_SRCS; do
  obj="$BUILD/$(basename "${s%.cc}").o"
  $CXX -std=c++17 $SAN_BUILD $INC -c "$s" -o "$obj"
  OBJS+=("$obj")
done
# The generated FuzzInput message (compiled with the same flags).
$CXX -std=c++17 $SAN_BUILD -I"$GEN" $PB_CFLAGS -c "$GEN/jwt_verify_lib_fuzz_input.pb.cc" \
     -o "$BUILD/fuzz_input.pb.o"
OBJS+=("$BUILD/fuzz_input.pb.o")

LIBJWT="$BUILD/libjwtverify.a"
rm -f "$LIBJWT"; ar rcs "$LIBJWT" "${OBJS[@]}"

# Standalone driver object (no libFuzzer runtime; replays one input file). C source -> .o.
$CC $SAN_BUILD -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

# Link helper: group resolves the abseil/protobuf/crypto interdependencies.
link_target() {  # <engine-flags> <out>
  $CXX -std=c++17 $SAN_BUILD $INC "$HARNESS_DIR/jwt_verify_lib_fuzzer.cc" $1 \
    -Wl,--start-group "$LIBJWT" "$BSSL_LIB" $PB_LIBS -L"$ABSL_DIR" "$ABSL_DIR"/libabsl_*.so -Wl,--end-group \
    -lz -lpthread -o "$2"
}

# ── 4) libFuzzer target + standalone reproducer ────────────────────────────────────────────────────
link_target "$LIB_FUZZING_ENGINE" "/mayhem/jwt_verify_lib_fuzzer"
link_target "$BUILD/standalone_main.o" "/mayhem/jwt_verify_lib_fuzzer-standalone"
echo "built jwt_verify_lib_fuzzer (+ standalone)"

# ── 5) Re-encode the upstream text-format seed corpus to protobuf WIRE FORMAT for the testsuite ────
#       (the harness ParseFromArray()s wire format; upstream ships text-format corpus files).
SEED_OUT="$SRC/mayhem/jwt_verify_lib_fuzzer/testsuite"
mkdir -p "$SEED_OUT"
for txt in "$SRC"/test/fuzz/corpus/jwt_verify_lib_fuzz_test/*; do
  [ -f "$txt" ] || continue
  name="$(basename "${txt%.txt}")"
  if protoc --encode=google.jwt_verify.FuzzInput -I "$PROTO_DIR" "$PROTO" < "$txt" > "$SEED_OUT/$name.bin" 2>/dev/null; then
    :
  else
    rm -f "$SEED_OUT/$name.bin"
  fi
done
echo "seed corpus (wire format): $(ls "$SEED_OUT" | wc -l) files"

# ── 6) Build the project's own gtest suite with NORMAL flags so mayhem/test.sh only RUNS it ────────
#       (separate object tree; no sanitizers; honest PATCH oracle of golden JWT/JWKS verification).
if command -v clang++ >/dev/null 2>&1 && ls /usr/lib/*/libgtest.* >/dev/null 2>&1; then
  TBUILD="$SRC/mayhem-tests"; mkdir -p "$TBUILD"
  TINC="-Ijwt_verify_lib -I. -I$BSSL_INC -Itest $PB_CFLAGS"
  TOBJS=()
  for s in $LIB_SRCS; do
    o="$TBUILD/$(basename "${s%.cc}").o"
    $CXX -std=c++17 -O1 $TINC -c "$s" -o "$o"
    TOBJS+=("$o")
  done
  ar rcs "$TBUILD/libjwtverify.a" "${TOBJS[@]}"
  for t in check_audience_test jwt_test jwks_test jwt_time_test verify_audiences_test verify_x509_test \
           verify_jwk_rsa_test verify_jwk_rsa_pss_test verify_jwk_ec_test verify_jwk_hmac_test \
           verify_jwk_okp_test verify_pem_rsa_test verify_pem_ec_test verify_pem_okp_test; do
    $CXX -std=c++17 -O1 $TINC "test/$t.cc" \
      -Wl,--start-group "$TBUILD/libjwtverify.a" "$BSSL_LIB" $PB_LIBS -L"$ABSL_DIR" "$ABSL_DIR"/libabsl_*.so \
      -lgtest -lgtest_main -lgmock -Wl,--end-group -lz -lpthread -o "$TBUILD/$t"
  done
  echo "built $(ls "$TBUILD"/*_test | wc -l) gtest binaries in mayhem-tests/"
else
  echo "WARNING: gtest not found — test suite not built (mayhem/test.sh will fail loudly)" >&2
fi

echo "build.sh complete:"
ls -la /mayhem/jwt_verify_lib_fuzzer /mayhem/jwt_verify_lib_fuzzer-standalone 2>&1 || true
