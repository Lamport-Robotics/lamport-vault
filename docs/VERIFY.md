# Verifying a deployment

One number decides it: sha256 of the ELF the source builds, against sha256 of the bytes in the
program's ProgramData account (the 45-byte loader header stripped, trailing zero padding trimmed on
both sides). `solana-verify` prints that same number, so a hash from the local script, from CI and
from `solana-verify get-program-hash` can be compared directly.

## Locally, no Docker

```sh
git checkout <commit>
scripts/verify-deploy.sh lamport-vault B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH --url devnet
scripts/verify-deploy.sh pq-registry   48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad --url devnet
```

The script runs `anchor build` (platform-tools v1.56, pinned in `programs/*/Cargo.toml`, downloaded by
`cargo-build-sbf` on first use), fetches the ProgramData account, prints both hashes, `MATCH` or
`MISMATCH`, the upgrade authority and the slot of the last deployment. Needs anchor 0.32.1, agave 2.3.x
and python3. Another platform-tools version produces another ELF, so if the hashes differ check that
first. `--no-build` reuses `target/deploy/*.so`.

## In CI, with Docker

`.github/workflows/verify.yml` builds both programs with `solana-verify build` (0.5.2) in
`solanafoundation/solana-verifiable-build:2.3.13` on every push to `main`, prints each hash in the job
summary and uploads the `.so` files as artifacts. On a tag named `devnet-<x>` or `mainnet-<x>` it also
runs `solana-verify get-program-hash` against that cluster and fails on a mismatch.

Deployments that are meant to be tagged are made from the CI artifact, not from a laptop build:
download the `.so` from the run for the release commit, `solana program deploy` it, push the tag.
Anyone can redo the check without trusting our CI:

```sh
cargo install solana-verify --version 0.5.2       # Docker must be running
solana-verify verify-from-repo --url <rpc> --program-id <id> --library-name lamport_vault \
    --commit-hash <sha> --base-image solanafoundation/solana-verifiable-build:2.3.13 \
    https://github.com/Lamport-Robotics/lamport-vault
```

`scripts/build-verifiable.sh` is the same build for a machine that has Docker.

## Upgrade authority

`solana program show <id> --url <cluster>` prints it; `scripts/verify-deploy.sh` prints it too. On
devnet both programs are upgradeable by the devnet deployer key, and they get redeployed. On mainnet
there will be none: see below.

## Mainnet

Not deployed. The plan, in order:

1. Tag the release commit; let `verify.yml` build it and keep the artifact.
2. `solana program deploy` each `.so` from that artifact with the deployer key as upgrade authority,
   same program ids as devnet (the ids are in the source).
3. `scripts/verify-deploy.sh <program> <id> --url mainnet-beta` from the tagged commit: `MATCH`.
4. `scripts/burn-upgrade-authority.sh <id> --url mainnet-beta --yes` for both programs, right away.
   After this nobody can change the code; a bug means a new program id and vaults moving over by
   `Close` and recreate.
5. Push `mainnet-<version>`; CI compares with the cluster.
6. Write the slot, hash and commit into the record below.

## Record

devnet, from commit `c596d0a` (`anchor build`, platform-tools v1.56):

```
lamport_vault  B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH
  hash       4d492d9e99d61cabac01a2e4a5ca93e8eeb61cb24b0f9175ef9332df67a7d8c1
  slot       510255069
  authority  5QrJ7MW6Ez7P6cYCwbYbiy8aeHn1NoYEFBXqGtKdyNNR

pq_registry    48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad
  hash       ad3beeabf96a0140d0b00781c3c22286b15b9f984aac7b8432e21d751db3de81
  slot       510250792
  authority  5QrJ7MW6Ez7P6cYCwbYbiy8aeHn1NoYEFBXqGtKdyNNR
```

Devnet is redeployed as the code changes; this block is updated with each deployment and the script
is the source of truth in between.

mainnet: nothing yet.
