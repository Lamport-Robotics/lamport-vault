#!/usr/bin/env bash
# Makes a deployed program immutable by removing its upgrade authority.
# This cannot be undone: after it runs, nobody (including the deployer) can
# ever change the program's code again.
#
# Usage:
#   scripts/burn-upgrade-authority.sh <program-id> [--url <rpc>] [--keypair <authority.json>]
#   scripts/burn-upgrade-authority.sh <program-id> --yes [--url <rpc>] [--keypair <authority.json>]
#
# Without --yes the script only prints the command it would run and the
# program's current authority. Verify the reproducible build hash
# (scripts/build-verifiable.sh) against the deployed program before burning.
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <program-id> [--yes] [--url <rpc>] [--keypair <authority.json>]" >&2
  exit 2
fi

PROGRAM_ID="$1"
shift
YES=0
URL_ARGS=()
KEYPAIR_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1; shift ;;
    --url) URL_ARGS=(--url "$2"); shift 2 ;;
    --keypair) KEYPAIR_ARGS=(--keypair "$2"); shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! command -v solana >/dev/null 2>&1; then
  echo "solana CLI not found on PATH" >&2
  exit 1
fi

echo "== program $PROGRAM_ID"
solana program show "$PROGRAM_ID" ${URL_ARGS[@]+"${URL_ARGS[@]}"} || {
  echo "could not read the program account; check the program id and --url" >&2
  exit 1
}

CMD=(solana program set-upgrade-authority "$PROGRAM_ID" --final ${URL_ARGS[@]+"${URL_ARGS[@]}"} ${KEYPAIR_ARGS[@]+"${KEYPAIR_ARGS[@]}"})
echo
echo "This command removes the upgrade authority permanently:"
echo "  ${CMD[*]}"

if [ "$YES" -ne 1 ]; then
  echo
  echo "Dry run. Re-run with --yes to execute."
  exit 0
fi

echo
echo "Burning the upgrade authority now."
"${CMD[@]}"
echo
echo "== after"
solana program show "$PROGRAM_ID" ${URL_ARGS[@]+"${URL_ARGS[@]}"}
