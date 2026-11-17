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

There is one row per deployment, not per crate. The Heir-enabled vault (docs/SUCCESSION.md) is
this crate built with the `succession` feature, which compiles in an id of its own: on devnet
`3mJU9ozZByXsHavMGfzdwDLFs9YuFaMA3jabaLwczxAV`, the row `lamport_vault-heir`.

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

## The web build

The `web` job of `.github/workflows/test.yml` builds the vault page and the single-file cold signer
with `npm ci` and prints `sha256(dist/signer.html)` in the job summary; the signer's footer shows the
commit it was built from. A downloaded `lamport-vault-signer.html` is checked by hashing it and
comparing with the summary of that commit's run.

## Upgrade authority

`solana program show <id> --url <cluster>` prints it; `scripts/verify-deploy.sh` prints it too. On
devnet both programs are upgradeable by the devnet deployer key, and they get redeployed. On mainnet
there will be none: see below.

## Mainnet

Not deployed. The mainnet programs are this same source built with the `mainnet` cargo feature,
which compiles in program ids of their own and changes nothing else:

| program | features | mainnet id |
|---|---|---|
| lamport-vault | `mainnet` | `7EiE5pRP5byrY7mzvUBfXS2UD8GwGtPhbGne6D1BTR5H` |
| lamport-vault, Heir-enabled (docs/SUCCESSION.md) | `mainnet,succession` | `3XsnTrQJ5XmFyEyVauMmMseHph4wXkn6QWUZCRPjuEEX` |
| pq-registry | `mainnet` | `9MYg9uqYBrTPXA6MNRZ6cbpwHSissY3496Y84iofTaNF` |

The signed message binds the program id and nothing else about the cluster: with the devnet ids a
devnet signature by a raw or hardware key would replay on mainnet. So mainnet has ids of its own,
each with a deployment keypair kept by the project owner. `mainnet` cannot be combined with a test
build (`short-clocks`, `small-history`): the source refuses to compile. The test that says which
id a build carries (`programs/*/tests/program_id.rs`) runs on both sides in CI, and `verify.yml`
builds one row per deployment.

The plan, in order:

1. Merge the release commit to main. `verify.yml` builds every row there and keeps the artifacts
   (`lamport_vault-mainnet-<sha>`, `lamport_vault-mainnet-heir-<sha>`, `pq_registry-mainnet-<sha>`).
2. `solana program deploy` each `.so` from those artifacts with the deployer key as upgrade
   authority, under its mainnet id.
3. `scripts/verify-deploy.sh <program> <id> --url mainnet-beta --features <features>` from that
   commit: `MATCH`.
4. `scripts/burn-upgrade-authority.sh <id> --url mainnet-beta --yes` for every program, right away.
   After this nobody can change the code; a bug means a new program id and vaults moving over by
   `Close` and recreate.
5. Push `mainnet-<version>`; CI compares the mainnet rows with the cluster (a devnet tag compares
   the devnet rows, and says nothing about mainnet).
6. Write the slot, hash and commit into the record below.

## Record

devnet, 2026-11-17, commit `989f8db`: the Heir-enabled vault (`succession`, docs/SUCCESSION.md) deployed
for the first time, from the `verify.yml` artifact `lamport_vault-heir` of that commit. It is a program
of its own beside the vault below, which it does not replace or change. No tag: a `devnet-<x>` tag
compares every devnet row, and the plain vault's row is ahead of what is on chain (see below).
[lamport-heir's `docs/program-ids.md`](https://github.com/Lamport-Robotics/lamport-heir/blob/main/docs/program-ids.md)
keeps this program's record.

```
lamport_vault-heir  3mJU9ozZByXsHavMGfzdwDLFs9YuFaMA3jabaLwczxAV
  hash       848bc48ae379c081a5103a814b0170261d75ea40ebe06104eb6a5187ceb85ec8
  size       386 504 bytes (allocation 386 504)
  slot       523426265
  authority  4ARvLemSynLjt82WaBvcyS93E7PB5ZdSwR2HwQgiRBcg
```

devnet, tag `devnet-2`, commit `8558973`, vault redeployed from the `verify.yml` artifact of that commit
(solana-verify 0.5.2 in `solanafoundation/solana-verifiable-build@sha256:0cf72459…`, platform-tools v1.56);
the registry is unchanged since `devnet-1`. `scripts/verify-deploy.sh … --no-build` on the artifacts prints
`MATCH` for both. What changed on chain: the `TransferTokenFrom` action (variant 4) and error 6037
`WrongSource`; every earlier action encodes and executes as before.

```
lamport_vault  B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH
  hash       b9c055c3ba267849970076a5689e068a19f05dd4045f8f49f16f05cf2e2a563b
  size       341 968 bytes (341 953 hashed; allocation 350 000)
  slot       515785357
  authority  5QrJ7MW6Ez7P6cYCwbYbiy8aeHn1NoYEFBXqGtKdyNNR

pq_registry    48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad
  hash       95af8d50f1167c4ae55d7cf68ce85870682486bc9110862e5040d4c3dd22a118
  size       262 000 bytes (261 985 hashed; allocation 272 000)
  slot       514636087
  authority  5QrJ7MW6Ez7P6cYCwbYbiy8aeHn1NoYEFBXqGtKdyNNR
```

Earlier: tag `devnet-1`, commit `63176dc`, vault hash `3f9a9bc3…` at slot 514635841 (same registry).

`main` is ahead of this record. The transfer-hook fix (`docs/DESIGN.md`, "Transfer hooks") changed
`lamport_vault` on purpose, so `main` no longer builds to `b9c055c3…`; the registry is unchanged. The
vault on devnet is still the `devnet-2` program above, in which a token whose mint has a Token-2022
transfer hook cannot leave a vault. The fix is on chain once a build of `main` from `verify.yml` is
deployed, tagged and written down here. A local `anchor build` of it is 1 008 bytes smaller than the
one before (340 808 against 341 816), so it fits the 350 000 bytes already allocated.

A laptop `anchor build` of the same source gives another ELF than the Docker build (the registry's
earlier `3480ae2d…` hash was one); from this tag on, what is on chain is always the CI artifact, so
`solana-verify verify-from-repo` at the tagged commit is the check that counts.

earlier: commit `16b7fe8`, vault `4dd77696…2f98` at slot 510317125 (anchor build); commit `17c7880`,
registry `3480ae2d…bd9f` at slot 510277271; commit `e8b3446`, vault `71e4dde1…4348` at slot 510305889;
commit `17c7880`, vault `d7481e24…8f85` at slot 510277112; commit `c596d0a`, vault `4d492d9e…d8c1` at slot
510255069, registry `ad3beeab…de81` at slot 510250792.

mainnet: nothing yet.
