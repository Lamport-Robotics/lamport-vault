# Test vectors

Known-answer vectors for the LMS verifier live in `kat/`. Each file is read by
both the Rust crate (`cargo test -p lamport-lms --features sign`, tests in
`programs/lms/tests/`) and the TypeScript package (`cd sdk && npm test`, tests
in `sdk/packages/lms/test/`). Four sources are independent of this repository.

| File | Source | Covers | Count |
|------|--------|--------|-------|
| `kat/lms_sha256_w4.json` | [hsslms 0.1.3](https://pypi.org/project/hsslms/) (Python RFC 8554 implementation), SEED/I pinned by patching its RNG | W4 at H5 (q = 0, 1, 7, 31) and H10 (q = 0, 1023); public keys reproduce from SEED/I via Appendix A | 2 keys, 6 signatures |
| `kat/sdk_signatures.json` | this repository's TypeScript signer, fixed `C` | cross-implementation check: TS signatures under the Rust verifier | 2 keys, 3 signatures |
| `kat/rfc8554_appendix_f.json` | [RFC 8554 Appendix F](https://www.rfc-editor.org/rfc/rfc8554.txt), test cases 1 and 2, parsed verbatim by `kat/tools/parse_rfc_f.py` | HSS L=2 envelopes; LMS layers H5/W8 + H5/W8 (case 1) and H10/W4 + H5/W8 (case 2). Case 2 publishes SEED and I of both trees | 2 HSS signatures = 4 LMS layer verifications, 2 keys reproduced from SEED/I |
| `kat/hashsigs_w4.json` | [cisco/hash-sigs](https://github.com/cisco/hash-sigs) commit `cea4dda4f937e56ab42e1a74665f6397473a2838` (2026-10-09), `demo genkey <h>/4`, `demo sign`, `demo advance` | W4 at H5 (q = 0, 1, 2, 29, 30, 31), H10 (0, 1, 1022, 1023), H15 (0, 32767); messages 0 to 4096 bytes | 3 keys, 12 signatures |
| `kat/hashsigs_w1w2w8.json` | same hash-sigs build | W1 H5, W2 H5, W8 H5 (q = 0, 1, 31 each), W8 H10 (q = 0, 1023) | 4 keys, 11 signatures |
| `kat/acvp_lms.json` | [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server) commit `975de31eb83d87039ec88934fdc47d8c312b892d`, `gen-val/json-files/LMS-{keyGen-1.0,sigGen-1.0,sigGen-SP800-208,sigVer-1.0,sigVer-SP800-208}/internalProjection.json` | **SHA-256/192 only** (see below): sigVer 16 cases (4 valid, 12 invalid with reasons), sigGen 62, keyGen 9 with SEED/I | 87 cases |
| `kat/vault_encoding.json` | this repository | vault account and instruction byte layouts (not LMS) | — |

## What each source pins down

* **hsslms** (original vectors): the Appendix A key derivation and the W4 code
  path end to end, since public keys are reproduced from SEED/I in both
  implementations and signatures are verified.
* **RFC 8554 Appendix F**: the normative vectors. They exercise W8 (chain
  length 255, `ls = 0`) and the H10/W4 set the vault uses; the HSS envelope is
  parsed in the tests only (the crate and the program know LMS, not HSS).
  With test case 2's SEED and I, both implementations reproduce the public
  keys and, given the RFC's randomizer `C`, both LMS signatures byte for
  byte. The Rust crate's deterministic `C` (`H(I || q || 0xfffd || 0xff ||
  SEED)`) turns out to be the convention hash-sigs used to make the RFC's
  vectors, so `LmsPrivateKey::sign_with_tree` reproduces them without being
  given `C`.
* **hash-sigs**: an independent C implementation across every Winternitz
  width and the three tree heights the vault accepts, including the first and
  last leaf of each tree. hash-sigs stores private keys in its own
  side-channel-hardened format (not Appendix A), so only public keys and
  signatures are recorded; no SEED, so no key reproduction.
* **ACVP**: every LMS test group NIST publishes at that commit uses the
  SP 800-208 SHA-256/192 parameter sets (`LMS_SHA256_M24_H5/H10`,
  `LMOTS_SHA256_N24_W1/W2`, typecodes `0x0A/0x0B` and `0x05/0x06`, n = m =
  24). There are **no** RFC 8554 `SHA256_M32` cases, in any of the five
  directories or in the prompt/expectedResults projections. This repository
  implements n = m = 32 only (the on-chain account is laid out for 56-byte
  keys), so the ACVP file is used two ways:
  1. the shipped parsers must reject every ACVP key cleanly (48-byte key,
     foreign typecodes), and the verifier must not panic on their signatures;
  2. a **test-only** n = 24 instantiation of Algorithms 4b and 6a, written
     in the test files on top of the crate's `coef` and `H`, checks that the
     algorithm as implemented here agrees with NIST: the 4 valid sigVer cases
     and all 62 sigGen signatures verify, the 12 invalid sigVer cases fail
     with the documented reason (`modify message` / `modify signature` fail
     at the root comparison, `modify signature header` at the typecode or
     root check), and the 9 keyGen public keys are reproduced from SEED/I
     with the Appendix A derivation (which confirms SP 800-208 keys use it).
  This exercises the shared arithmetic and the reading of the specification,
  not the production verifier. If NIST adds M32 groups, re-run
  `kat/tools/convert_acvp.py` and the tests will pick up the
  new sets through `parameter_sets`.

## Acceptance policy

RFC 8554 Table 1 has four SHA-256 LM-OTS rows. Both implementations sign and
verify all four; the arithmetic is written once for any `w`. Which rows a
*parser* admits is a policy:

| | Rust | TypeScript |
|---|---|---|
| program policy, W4 only | `LmsPublicKey::parse`, `LmotsType::from_typecode` (`LmotsType::ACCEPTED`) | the vault client only creates W4 keys |
| every row | `LmsPublicKey::parse_any`, `LmotsType::from_typecode_in(code, LmotsType::ALL)` | `lmsVerify`, `parseLmsPublicKey` (any Table 1/2 typecode) |

The on-chain program calls `LmsPublicKey::parse`, so it accepts W4 only and
nothing in the new vector sources changes that; the tests assert that every
W1/W2/W8 key is refused by `parse` and verified by `parse_any`.

## Regenerating

The scripts are in `kat/tools/` (see its README).

* RFC: `python3 -I kat/tools/parse_rfc_f.py rfc8554.txt kat/rfc8554_appendix_f.json`
  over the RFC text from rfc-editor.org; the JSON records every label of
  Appendix F, so a diff against a fresh parse is the check.
* hash-sigs: clone the pinned commit into `<dir>/src`, `make demo` against
  OpenSSL, `kat/tools/gen_hashsigs.sh <dir>` (uses `demo genkey`, `sign`,
  `advance`), then `kat/tools/convert_hashsigs.py`, which strips the 4-byte
  HSS `levels`/`Nspk` prefixes. hash-sigs draws I and its seed at random, so
  a regeneration yields different keys; the tests only need the signatures to
  verify under their public keys.
* ACVP: fetch the five `internalProjection.json` files at the pinned commit
  and run `kat/tools/convert_acvp.py`.

## Fuzzing

`fuzz/` holds cargo-fuzz targets seeded from these vectors (`fuzz/gen_seeds.py`):
`lms_parse`, `lms_verify`, `action_decode`, `key_history`, `leaf_bitmap`.
`.github/workflows/fuzz.yml` runs each for 5 minutes on push and for 2 hours
weekly.
