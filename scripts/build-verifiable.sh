#!/usr/bin/env bash
# Reproducible build of the on-chain programs with solana-verify, printing the
# hash of each resulting .so so anyone can compare it with the deployed program.
#
# Install solana-verify once (needs Docker running):
#   cargo install solana-verify
#
# Usage:
#   scripts/build-verifiable.sh                 # build both programs
#   scripts/build-verifiable.sh lamport-vault   # build one
#
# To check a deployed program against the source instead:
#   solana-verify verify-from-repo --url <rpc> --program-id <id> \
#       --library-name lamport_vault https://github.com/Lamport-Robotics/lamport-vault
#
# The build runs inside the pinned solanafoundation/solana-verifiable-build
# image (same one as .github/workflows/verify.yml; override with BASE_IMAGE),
# so the output does not depend on the host toolchain. cargo-build-sbf in the
# image reads tools-version from the program's Cargo.toml and fetches
# platform-tools v1.56. The on-chain hash is
# `solana-verify get-program-hash --url <rpc> <program-id>`; the local one is
# printed below. They must be identical. Without Docker use
# scripts/verify-deploy.sh instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

BASE_IMAGE="${BASE_IMAGE:-solanafoundation/solana-verifiable-build:2.3.13}"

if ! command -v solana-verify >/dev/null 2>&1; then
  echo "solana-verify not found. Install it with: cargo install solana-verify" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running; solana-verify builds inside a container." >&2
  exit 1
fi

# Program crate directory -> library name (the .so basename).
lib_for() {
  case "$1" in
    lamport-vault) echo lamport_vault ;;
    pq-registry) echo pq_registry ;;
    *) return 1 ;;
  esac
}

if [ $# -gt 0 ]; then
  SELECTED=("$@")
else
  SELECTED=(lamport-vault pq-registry)
fi

for crate in "${SELECTED[@]}"; do
  if ! lib="$(lib_for "$crate")"; then
    echo "unknown program '$crate' (expected: lamport-vault, pq-registry)" >&2
    exit 1
  fi
  echo "== building $crate ($lib) reproducibly"
  # --library-name selects the crate; the workspace root is the build context.
  solana-verify build --library-name "$lib" --base-image "$BASE_IMAGE"
  so="target/deploy/${lib}.so"
  echo "== $lib"
  echo "   size:  $(wc -c < "$so") bytes"
  echo "   hash:  $(solana-verify get-executable-hash "$so")"
done

echo
echo "Compare with the on-chain hash:"
echo "  solana-verify get-program-hash --url <rpc> <program-id>"
