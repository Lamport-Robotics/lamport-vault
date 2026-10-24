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

Not deployed. The plan, in order:

1. Tag the release commit; let `verify.yml` build it and keep the artifact.
2. `solana program deploy` each `.so` from that artifact with the deployer key as upgrade authority,
   under **new program ids** (fresh keypairs; the ids are compiled in, so this is a commit of its own).
   The signed message binds the program id and nothing else about the cluster: with the devnet ids a
   devnet signature by a raw or hardware key would replay on mainnet.
3. `scripts/verify-deploy.sh <program> <id> --url mainnet-beta` from the tagged commit: `MATCH`.
4. `scripts/burn-upgrade-authority.sh <id> --url mainnet-beta --yes` for both programs, right away.
   After this nobody can change the code; a bug means a new program id and vaults moving over by
   `Close` and recreate.
5. Push `mainnet-<version>`; CI compares with the cluster.
6. Write the slot, hash and commit into the record below.

## Record

devnet, tag `devnet-1`, commit `63176dc`, both programs deployed from the `verify.yml` artifacts of that
commit (solana-verify 0.5.2 in `solanafoundation/solana-verifiable-build@sha256:0cf72459…`, platform-tools
v1.56). The tag's CI job and `scripts/verify-deploy.sh … --no-build` on the same artifacts print `MATCH`.

```
lamport_vault  B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH
  hash       3f9a9bc3e385026fb9ac4ee3f29601712537f96cb36914683fab9402354b6698
  size       339 896 bytes (339 881 hashed; allocation 350 000)
  slot       514635841
  authority  5QrJ7MW6Ez7P6cYCwbYbiy8aeHn1NoYEFBXqGtKdyNNR

pq_registry    48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad
  hash       95af8d50f1167c4ae55d7cf68ce85870682486bc9110862e5040d4c3dd22a118
  size       262 000 bytes (261 985 hashed; allocation 272 000)
  slot       514636087
  authority  5QrJ7MW6Ez7P6cYCwbYbiy8aeHn1NoYEFBXqGtKdyNNR
```

A laptop `anchor build` of the same source gives another ELF than the Docker build (the registry's
earlier `3480ae2d…` hash was one); from this tag on, what is on chain is always the CI artifact, so
`solana-verify verify-from-repo` at the tagged commit is the check that counts.

earlier: commit `16b7fe8`, vault `4dd77696…2f98` at slot 510317125 (anchor build); commit `17c7880`,
registry `3480ae2d…bd9f` at slot 510277271; commit `e8b3446`, vault `71e4dde1…4348` at slot 510305889;
commit `17c7880`, vault `d7481e24…8f85` at slot 510277112; commit `c596d0a`, vault `4d492d9e…d8c1` at slot
510255069, registry `ad3beeab…de81` at slot 510250792.

mainnet: nothing yet.
