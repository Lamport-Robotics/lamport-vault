#!/usr/bin/env bash
# Runs an anchor command against the Heir-enabled build (docs/SUCCESSION.md).
#
#   scripts/anchor-succession.sh                            anchor test -- --features succession
#   scripts/anchor-succession.sh succession,small-history   the same, with the small key history
#   scripts/anchor-succession.sh succession build           another anchor command
#
# A build with the `succession` feature declares a program id of its own, and Anchor.toml names
# the address the local validator loads the program at. This points that entry at the feature
# build's id for the length of the command and puts the file back afterwards, whatever happens.
set -euo pipefail
cd "$(dirname "$0")/.."

features="${1:-succession}"
command="${2:-test}"
lib=programs/lamport-vault/src/lib.rs
case ",$features," in
  *,short-clocks,*) id=$(sed -n 's/.*#\[cfg(feature = "short-clocks")\] declare_id!("\([^"]*\)").*/\1/p' "$lib") ;;
  *,succession,*)   id=$(sed -n 's/.*not(feature = "short-clocks")))\] declare_id!("\([^"]*\)").*/\1/p' "$lib") ;;
  *) echo "the feature list must include succession (got: $features)" >&2; exit 2 ;;
esac
[ -n "$id" ] || { echo "could not read the feature build's program id from $lib" >&2; exit 1; }

cp Anchor.toml Anchor.toml.orig
trap 'mv Anchor.toml.orig Anchor.toml' EXIT
sed -i.bak "s/^lamport_vault = \".*\"/lamport_vault = \"$id\"/" Anchor.toml && rm -f Anchor.toml.bak
grep -q "^lamport_vault = \"$id\"" Anchor.toml || { echo "Anchor.toml has no lamport_vault entry to point at $id" >&2; exit 1; }
echo "lamport_vault -> $id (features: $features)"
anchor "$command" -- --features "$features"
