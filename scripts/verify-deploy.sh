#!/usr/bin/env bash
# Checks that a deployed program is the one this tree builds. No Docker, no
# solana-verify: `anchor build` (platform-tools pinned in the program's
# Cargo.toml), then sha256 of the local .so against sha256 of the on-chain
# program bytes.
#
# Usage:
#   scripts/verify-deploy.sh <program-name> <program-id> [--url <rpc|moniker>] [--no-build]
#
#   scripts/verify-deploy.sh lamport-vault B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH --url devnet
#   scripts/verify-deploy.sh pq-registry   48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad --url devnet
#
# On-chain bytes: the ProgramData account is `u32 type || u64 slot ||
# Option<Pubkey> authority (1 + 32)` = 45 bytes of header, then the ELF, then
# zero padding up to the allocation (`--max-len` is usually larger than the
# binary). The header is stripped, the ELF magic is checked, trailing zeros
# are trimmed from both sides before hashing. That is the same hash
# `solana-verify get-program-hash` / `get-executable-hash` print, so the
# numbers here can be compared with the CI output in .github/workflows/verify.yml.
#
# Exit code: 0 on MATCH, 1 on MISMATCH or error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

if [ $# -lt 2 ]; then
  echo "usage: $0 <program-name> <program-id> [--url <rpc|moniker>] [--no-build]" >&2
  exit 2
fi

NAME="$1"
PROGRAM_ID="$2"
shift 2
URL_ARGS=()
BUILD=1
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL_ARGS=(--url "$2"); shift 2 ;;
    --no-build) BUILD=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$NAME" in
  lamport-vault|lamport_vault) CRATE=lamport-vault; LIB=lamport_vault ;;
  pq-registry|pq_registry)     CRATE=pq-registry;   LIB=pq_registry ;;
  *) echo "unknown program '$NAME' (expected: lamport-vault, pq-registry)" >&2; exit 2 ;;
esac

for tool in anchor solana python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found on PATH" >&2
    exit 1
  fi
done

SO="target/deploy/${LIB}.so"
if [ "$BUILD" -eq 1 ]; then
  echo "== building $CRATE"
  # macOS: keep resource forks out of the build.
  COPYFILE_DISABLE=1 anchor build -p "$CRATE" >/dev/null
fi
if [ ! -f "$SO" ]; then
  echo "missing $SO (build first, or drop --no-build)" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== fetching $PROGRAM_ID"
SHOW="$TMP/show.json"
solana program show "$PROGRAM_ID" ${URL_ARGS[@]+"${URL_ARGS[@]}"} --output json > "$SHOW"
PROGRAMDATA="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["programdataAddress"])' "$SHOW")"
AUTHORITY="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("authority") or "none (immutable)")' "$SHOW")"
SLOT="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["lastDeploySlot"])' "$SHOW")"

RAW="$TMP/programdata.bin"
solana account "$PROGRAMDATA" ${URL_ARGS[@]+"${URL_ARGS[@]}"} --output-file "$RAW" >/dev/null

# Strip the 45-byte ProgramData header, check the ELF magic, trim the zero
# padding, hash. The local .so gets the same trim so both sides are hashed
# the same way.
read -r LOCAL_HASH LOCAL_LEN CHAIN_HASH CHAIN_LEN < <(python3 -I - "$SO" "$RAW" <<'PY'
import hashlib, sys

HEADER = 4 + 8 + 1 + 32  # u32 type, u64 slot, Option<Pubkey>

def trimmed(b: bytes) -> bytes:
    return b.rstrip(b"\0")

local = trimmed(open(sys.argv[1], "rb").read())
raw = open(sys.argv[2], "rb").read()
if len(raw) < HEADER + 4:
    sys.exit("programdata account too small: %d bytes" % len(raw))
kind = int.from_bytes(raw[:4], "little")
if kind != 3:
    sys.exit("account is not ProgramData (type %d); pass the program id, not the data account" % kind)
elf = raw[HEADER:]
if elf[:4] != b"\x7fELF":
    sys.exit("no ELF magic after the 45-byte header")
chain = trimmed(elf)
print(hashlib.sha256(local).hexdigest(), len(local), hashlib.sha256(chain).hexdigest(), len(chain))
PY
)

echo
echo "== $LIB"
echo "   local    $LOCAL_HASH  ($LOCAL_LEN bytes, $SO)"
echo "   on-chain $CHAIN_HASH  ($CHAIN_LEN bytes, programdata $PROGRAMDATA)"
echo "   upgrade authority   $AUTHORITY"
echo "   last deployed slot  $SLOT"
echo
if [ "$LOCAL_HASH" = "$CHAIN_HASH" ]; then
  echo "MATCH"
  exit 0
fi
echo "MISMATCH"
exit 1
