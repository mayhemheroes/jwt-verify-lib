// jwt_verify_lib_fuzzer.cc — Mayhem libFuzzer harness for google/jwt_verify_lib.
//
// Faithful port of upstream test/fuzz/jwt_verify_lib_fuzz_test.cc. Upstream uses
// libprotobuf-mutator's DEFINE_PROTO_FUZZER(const FuzzInput&) macro, which mutates a
// google.jwt_verify.FuzzInput protobuf and hands it to the target. libprotobuf-mutator is a
// Bazel-only dependency that is intractable to wire up in the base image, so this harness keeps
// the EXACT SAME fuzzed surface but consumes the protobuf from its serialized WIRE FORMAT instead:
// libFuzzer mutates raw bytes, we ParseFromArray() them into the same FuzzInput, then drive the
// identical jwt.parseFromString / Jwks::createFrom / verifyJwt sequence. The seed corpus is the
// upstream text-format corpus re-encoded to wire format by mayhem/build.sh (protoc --encode), so
// the seeds remain the genuine upstream JWT/JWKS pairs.
//
// The fuzzed code is google/jwt_verify_lib's JWT parser (jwt.cc), JWKS parser (jwks.cc, JWKS+PEM
// formats), and signature verifier (verify.cc — HS/RS/ES/PS/EdDSA via BoringSSL).

#include <cstddef>
#include <cstdint>

#include "jwt_verify_lib/jwks.h"
#include "jwt_verify_lib/jwt.h"
#include "jwt_verify_lib/verify.h"
#include "jwt_verify_lib_fuzz_input.pb.h"

namespace google {
namespace jwt_verify {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzInput input;
  // Wire-format parse of the libprotobuf-mutator message. Reject non-protobuf inputs cheaply.
  if (!input.ParseFromArray(data, static_cast<int>(size))) {
    return 0;
  }

  Jwt jwt;
  auto jwt_status = jwt.parseFromString(input.jwt());

  auto jwks1 = Jwks::createFrom(input.jwks(), Jwks::JWKS);
  auto jwks2 = Jwks::createFrom(input.jwks(), Jwks::PEM);

  if (jwt_status == Status::Ok) {
    if (jwks1->getStatus() == Status::Ok) {
      verifyJwt(jwt, *jwks1);
    }
    if (jwks2->getStatus() == Status::Ok) {
      verifyJwt(jwt, *jwks2);
    }
  }
  return 0;
}

}  // namespace jwt_verify
}  // namespace google
