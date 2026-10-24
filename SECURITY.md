# Security

## Reporting

Email security@lamportrobotics.com. Don't open a public issue for anything that could move
funds or forge a signature. Include the commit, the program or package, and steps to
reproduce; a failing test is ideal. You'll hear back within a few days.

We ask for 90 days from the report before public disclosure. If a fix ships earlier you can
publish earlier; if we need more time we'll say so before the 90 days are up. Credit in the
release notes if you want it.

## Scope

- `programs/`: `lamport-vault`, `pq-registry`, the `lms` crate they verify with
- `sdk/`: `@lamport-robotics/lms`, `@lamport-robotics/vault`
- `kat/`: the test vectors, if one is wrong in a way that hides a bug

`web/` (the vault page and the cold signer) is a second phase. Reports about it are welcome and
will be read, but it is not in scope for disclosure terms or bounties yet.

What matters most: signature forgery or leaf reuse, spending without a valid LMS signature over
the generation-bound message, rotating to a key the vault had before, anything that strands funds
(the exhaustion rule and the key-history cap exist so that can't happen), and SDK encoding that
disagrees with the program.

## Out of scope

- Anything that needs the 24 words, the derived key material, or the signer machine
- Devnet: the devnet programs are upgradeable and get redeployed; devnet SOL has no value
- Bugs in Solana itself, the loaders, the token programs, or third-party dependencies
  (report those upstream; tell us too if they affect the vault)
- Denial of service by paying rent or fees, RPC outages, phishing, social engineering
- Findings from automated scanners with no working exploit

## Mainnet

There is no mainnet deployment yet. The devnet program ids are in the README. When mainnet is
deployed the upgrade authority is burned right after deployment and the slot, hash and commit are
recorded in `docs/VERIFY.md`, so a mainnet report can only be fixed by a new program and a
vault migration. That is deliberate.

## Audits

None yet. Reports will be linked here when they exist.

## Bounty

Terms will be published here before the mainnet deployment.

One LMS key serves one vault. The message domains stop a signature from being replayed between the vault,
the registry or another vault, but two signatures by one leaf over two messages are a forgery oracle the chain
cannot see; the SDK and the cold signer refuse to point a key at a second vault for that reason.
