# The `succession` feature

`succession` is a cargo feature of the `lamport-vault` crate. It holds the on-chain inactivity
clock of Lamport Heir: if a vault's owner signs nothing and checks in nowhere for longer than the
window they chose, anyone may open a public waiting period, and when it runs out anyone may release
the vault to an address the owner named. The design, and the decisions behind it, are in the Heir
repository:
[lamport-heir, `docs/design-note.md`](https://github.com/Lamport-Robotics/lamport-heir/blob/main/docs/design-note.md).

A build with the feature is a **different program**. It has its own program id and its own
deployment and is never an upgrade of the vault. Without the feature, nothing below exists.

Two rules hold for everything behind the feature (sections 1 and 2). Sections 3 to 8 describe what
it adds.

## 1. The default build does not change

Without the feature, `lamport_vault.so` must be byte-for-byte the program it is without this code.

This is stricter than it sounds, because the program contains its own line numbers. Anchor's
`require!` and `error!` compile `file!()` and `line!()` into the error they return, and every
overflow check and `unwrap` carries its source location. Measured with `solana-verify` 0.5.2 in the
image `verify.yml` pins, at commit `c4a4ccd`:

| change to the source | default build |
|---|---|
| none | `b9c055c3…2a563b`, 341 968 bytes (the hash in `docs/VERIFY.md`) |
| one blank line added near the top of `lib.rs` | `4d309fc1…de3547`: a different program |
| one blank line added after the `#[program]` module, above the `#[derive(Accounts)]` structs | `223d12bc…080fa3`: a different program |
| feature-gated code added at the **end of existing lines** and at the **end of files**, plus a new file | `b9c055c3…2a563b`: identical |

So the rule for `programs/lamport-vault/src/*.rs` is: **no existing line moves.**

- New code goes in `succession.rs`, or in another new file.
- A whole new item (a module declaration, an `impl` block) is appended at the end of the file.
- Where an existing item needs a member that only exists with the feature (an enum variant, a struct
  field, a match arm, an instruction inside `#[program]`), it goes at the end of an existing line,
  behind `#[cfg(feature = "succession")]`. For example, after the last variant of `Action`:

  ```rust
      }, #[cfg(feature = "succession")] SetSuccession(crate::succession::SetSuccession),
  ```

  Those lines get long. That is the price of not moving the ones below them.
- Nothing is added to the default build's dependencies.
- No second `#[error_code]` enum. Anchor's IDL has room for one error list per program, and a
  second enum replaces the vault's own list there. Succession's errors are written out by hand
  (section 5).

The places where existing files carry such a hook: the `declare_id!` line, the end of the `Close`
arm and the final `Ok(())` of `verify_and_act`, the `sweep_closed_sol` line (four instructions),
two `Vault` struct literals and the end of `lib.rs`; the last variant of `Action` and its validity
window arm in `action.rs`; one field, the version constant and `space()` in `state.rs`.

`.github/workflows/succession.yml` enforces the rule: on a pull request from a branch named
`succession*` it builds the default features of both programs at the pull request and at its base,
from nothing each time, and fails unless the files are identical. A pull request that means to
change a program itself comes from a branch with another name, and updates `docs/VERIFY.md` as
before.

`pq-registry` declares a feature called `succession` too, and it gates nothing there. `anchor build
-- --features succession` hands the flag to every program in the workspace, as it does with
`small-history`, so the registry has to know the name.

## 2. The vault's own tests pass both ways

Every existing suite also runs with the feature on:

| suite | workflow | default | with `succession` |
|---|---|---|---|
| `cargo test --workspace` | `test.yml`, job `rust` | yes | yes, and once more with `short-clocks` |
| `anchor test` on a local validator | `anchor.yml` | yes, and with `small-history` | yes, and with `small-history` |
| `execute_direct` in LiteSVM | `anchor.yml` | yes | yes, plus the succession tests (section 6) |
| SDK (`cd sdk && npm test`) | `test.yml`, job `sdk` | yes | the same run: the SDK knows both programs |
| fuzzing | `fuzz.yml` | the five existing targets | two more targets |
| reproducible build | `succession.yml` | compared with the base | hash and size printed, `.so` uploaded |

Three things in the existing suites know about the feature, because a build with it is a different
program with a larger vault account:

- `programs/lamport-vault/tests/encoding.rs` (the vault's byte-layout vectors) is compiled only
  without the feature; `tests/succession_encoding.rs` checks the feature build's layout against
  `kat/succession_encoding.json` instead.
- The unit tests that assert account sizes add `Vault::EXT`, which is 0 without the feature.
- The localnet suite (`tests/lamport-vault.ts`) reads the program id from the IDL and expects
  account version 3 and 200 more bytes when the IDL has a `checkin` instruction.
  `tests/succession.ts` registers its tests only for such a build, so a run against the vault as
  it is reports the tests it always had.

Locally:

```sh
cargo test --workspace --features lamport-lms/sign                               # as always
cargo test --workspace --features lamport-lms/sign,lamport-vault/succession      # with the feature
anchor test                                                                      # as always
scripts/anchor-succession.sh                                                     # anchor test, feature build
scripts/anchor-succession.sh succession,small-history
(cd tests/svm && cargo test --features succession)                               # after a feature build
```

`scripts/anchor-succession.sh` exists because `Anchor.toml` names the address the local validator
loads the program at, and the feature build declares another one. The script points that entry at
the feature build's id for one command and puts the file back.

## 3. Program ids

| build | features | program id |
|---|---|---|
| the vault | none | `B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH` |
| Heir-enabled vault | `succession` | `3mJU9ozZByXsHavMGfzdwDLFs9YuFaMA3jabaLwczxAV` |
| test build, one-second days | `short-clocks` | `3pwH161r4SZRH6nCHY4RUm7gk2NZqypyFJaUgv9a2duG` |

The two Heir ids have deployment keypairs, made on 2026-11-13 for devnet and kept by the project
owner outside every repository. An id says where a build would be deployed, not that it is:
[lamport-heir's `docs/program-ids.md`](https://github.com/Lamport-Robotics/lamport-heir/blob/main/docs/program-ids.md)
records what is deployed, on which cluster, with which hash. Because a vault's key derivation binds
the program id, a vault of one program can never be operated under another.

`short-clocks` implies `succession` and makes a "day" of the clock last one second, so a whole
cycle (90 days of inactivity, 30 days of waiting) fits in a devnet test. It has its own id so that
a short-clocks build can never stand in for the real program.

## 4. What it adds

### State

Every vault of the Heir-enabled program carries a 200-byte succession block from creation, all
zero until a plan is set. It sits at byte 114 of the account data, after `created_slot` and before
the two vectors, so it is at the same offset in every vault and `Rotate` does not touch it. The
account `version` is 3 (the vault's is 2).

| offset | field | type | meaning |
|---|---|---|---|
| 114 | `claim` | Pubkey | where the vault releases to; all zero = no plan |
| 146 | `window_secs` | u64 | inactivity before a waiting period can open |
| 154 | `wait_secs` | u64 | length of the waiting period |
| 162 | `last_signed_ts` | i64 | when the last signed action executed |
| 170 | `last_checkin_ts` | i64 | when the last valid check-in executed |
| 178 | `checkin_key` | Pubkey | a key that may only check in; all zero = none |
| 210 | `contact_key` | Pubkey | a trusted contact's key; all zero = none |
| 242 | `contact_used` | bool | the contact has used their one extension |
| 243 | `extended_until_ts` | i64 | the contact's extension; 0 = none |
| 251 | `wait_open` | bool | a waiting period is open |
| 252 | `wait_started_ts` | i64 | when it opened |
| 260 | `reserved` | 54 bytes | zero |

Times are `Clock.unix_timestamp`, in seconds.

### The clock

```text
activity   = max(last_signed_ts, min(last_checkin_ts, last_signed_ts + 730 days))
deadline   = max(activity + window_secs, extended_until_ts)
release_at = wait_started_ts + wait_secs
```

| limit | value |
|---|---|
| shortest window | 90 days |
| shortest waiting period | 30 days |
| longest window or waiting period | 100 years |
| a check-in counts until | 730 days after the last signed action |
| the contact's extension | 90 days, once per plan |

### `Action::SetSuccession` (variant 5)

```text
5 SetSuccession { claim: Pubkey, window_secs: u64, wait_secs: u64, checkin_key: Pubkey,
                  contact_key: Pubkey, issued_slot: u64, expiry_slot: u64 }               129 bytes
```

A signed action like the other five: it costs a one-time leaf and goes through the same
`upload_sig` / `execute` (or `execute_direct`) path. Its one remaining account is the claim account,
which the program refuses if it is the vault itself, a program, a token account or mint, a sysvar,
the id of a loader or of the sysvar owner, or one of this program's own accounts other than an
open vault. An open vault whose own plan names this vault is refused too: two vaults that name each
other would hand a release back and forth between their tombstones for ever. (The program sees one
step. A longer ring of vaults is not caught on chain.) An all-zero `claim` clears the
plan and must carry zeros in every other plan field.

The program accepts an address with nothing at it, because a wallet that has never been used looks
like that. It cannot tell such a wallet from a program-derived address that no program has set up
yet, for which no key exists: what is released there may never be reachable. The SDK's signer
refuses that case (an address off the curve with no account) unless told otherwise, and a client
that names a program's account should check that the account exists and is the one it means.

It takes effect at once. There is no queue: every signed action restarts the window, this one
included, so nothing can be released sooner than `window_secs + wait_secs` (at least 120 days)
after any change to the plan. Setting a plan again, even an identical one, gives the contact their
one extension back.

**Every signed action that executes** (`Withdraw`, `WithdrawToken`, `Rotate`, `SetSpendLimit`,
`SetSuccession`) sets `last_signed_ts`, cancels an open waiting period and ends the contact's
extension. `Close` leaves a tombstone, as before.

### Four instructions

| instruction | signer | accounts | what it does |
|---|---|---|---|
| `checkin` | the check-in key | vault (w), check-in key (s) | counts as activity while within 730 days of the last signed action; cancels an open waiting period. It can only move the deadline later: the contact's extension stays until the owner signs |
| `contact_extend` | the contact key | vault (w), contact key (s) | once per plan: `extended_until_ts = max(deadline, now) + 90 days`; cancels an open waiting period |
| `start_succession` | none | vault (w) | opens the waiting period once `now > deadline` |
| `execute_succession` | none | vault (w), claim (w), then `[token account, token program]` pairs | once `now >= release_at`: releases the vault to `claim` |

`execute_succession` does what a signed `Close { to: claim }` does: it closes the empty token
accounts passed to it, sends every lamport above a tombstone's rent to the claim address and
leaves a `Tombstone` naming it as heir, so `sweep_closed` and `sweep_closed_sol` deliver whatever
else is there or arrives later. It spends no leaf and does not touch the key history. Its body
repeats the `Close` arm on purpose (sharing the code would move that arm, see section 1);
`tests/svm/tests/succession_close.rs` holds the two to the same result over random vault states.

Neither extra key can move funds, change the plan or shorten a clock. The check-in key can delay
a release by at most two years past the owner's last signature; the contact key by 90 days, once.

## 5. Errors

Succession has its own codes, numbered from 6100 so the vault's 6000 to 6037 stay where they are.
They are not in the IDL (section 1); the SDK lists them as `SUCCESSION_ERROR`, and
`kat/succession_encoding.json` pins the numbers for both sides.

| code | name | when |
|---|---|---|
| 6100 | `NotArmed` | no plan is set |
| 6101 | `WrongCheckinKey` | the signer is not the plan's check-in key, or the plan has none |
| 6102 | `CheckinPastCap` | more than 730 days since the last signed action: a signature is due |
| 6103 | `WrongContactKey` | the signer is not the plan's contact key, or the plan has none |
| 6104 | `ContactAlreadyUsed` | the one extension is spent |
| 6105 | `WaitAlreadyOpen` | `start_succession` while a waiting period is open |
| 6106 | `BeforeDeadline` | `start_succession` at or before the deadline |
| 6107 | `NoWaitOpen` | `execute_succession` with no waiting period open |
| 6108 | `WaitNotOver` | `execute_succession` before `release_at` |
| 6109 | `WindowOutOfRange` | window outside 90 days to 100 years |
| 6110 | `WaitOutOfRange` | waiting period outside 30 days to 100 years |
| 6111 | `ClearCarriesPlan` | a clear with a window, a wait or a key |
| 6112 | `ClaimAccountMissing` | the claim account is not the first remaining account |
| 6113 | `ClaimIsTheVault` | the claim address is the vault |
| 6114 | `ClaimNotUsable` | the claim address cannot receive a release |
| 6115 | `WrongClaim` | `execute_succession` given an account that is not the plan's claim address |
| 6116 | `Overflow` | arithmetic overflow |

The token-account checks in `execute_succession` return the vault's own errors, as `Close` does.

## 6. Tests

| what | where | count |
|---|---|---|
| the clock rules, with no chain | unit tests in `src/succession.rs` | 16 |
| byte layouts against the shared vectors | `programs/lamport-vault/tests/succession_encoding.rs` | 5 |
| every instruction on chain, each with its refusals | `tests/svm/tests/succession.rs` | 25 |
| `execute_succession` equals a signed `Close` | `tests/svm/tests/succession_close.rs` | 2 (120 random vault states) |
| random sequences of signatures, check-ins, extensions and clock jumps against a model | `tests/svm/tests/succession_random.rs` | 400 sequences |
| Token-2022 extensions through a release and the sweeps | `tests/svm/tests/succession_tokens.rs` | 13 |
| the SDK: encodings, the clock, the signer's refusals | `sdk/packages/vault/test/succession.test.ts` | 30 |
| the SDK's signer and builders against a real validator | `tests/succession.ts` (localnet, feature build only) | 8 |
| fuzzing | `fuzz/fuzz_targets/succession_action.rs`, `succession_clock.rs` | in `fuzz.yml` |
| mutation check | `tests/mutants/succession.py` | 40 mutants |

The on-chain tests run the real `.so` in LiteSVM, which can set the clock; the test validator
cannot jump 90 days. The random test keeps counters and fails if a run never reached a release, a
cancelled waiting period, a capped check-in and the other states it is meant to cover.

The mutation check breaks the code one rule at a time (a comparison off by one, a missing check, a
clock that is not reset), rebuilds, and runs the unit tests and the LiteSVM suite. Every mutant
must be caught; one that survives is a rule no test defends. It rebuilds the program 40 times, so
it has its own job in the `succession` workflow, split four ways:

```sh
python3 tests/mutants/succession.py                # all of them
python3 tests/mutants/succession.py --shard 1/4    # a quarter, as CI runs it
```

`kat/succession_encoding.json` is written by the SDK (`cd sdk && npm run kat`) and read by the Rust
crate: program ids, discriminators, limits, error codes, the action and account bytes, and fifteen
clock cases that both implementations must compute alike.

## 7. Tokens a release cannot move

`execute_succession` and the sweeps move what a signed `Close` can move. Confirmed on chain in
`tests/svm/tests/succession_tokens.rs`, for whoever finishes a release:

- A Token-2022 account with **withheld transfer fees** cannot be closed, even at balance zero, and
  passing it to `execute_succession` fails the release. Leave it out; `sweep_closed` empties it
  afterwards, and closing it needs the fees harvested to the mint first (anyone may do that).
- **Non-transferable** tokens stay where they are: no instruction of this program can move them.
- A **frozen** account (including a mint whose accounts start frozen) moves only after the issuer
  thaws it.
- A **paused** mint, a destination that requires **memos**, and a **transfer hook** whose program
  is missing all fail the sweep of that one token cleanly. The SOL and every other token still go.

None of this blocks the release itself, provided such accounts are not passed to it.

## 8. In the SDK

`@lamport-robotics/vault` reads and writes both programs. `decodeVault` returns a `succession`
field for a version 3 account; `successionStatus(state, now)` gives the phase (`unarmed`, `quiet`,
`overdue`, `waiting`, `releasable`) and the times; `checkSuccessionPlan` applies the program's
rules before a leaf is spent; `VaultSigner` signs a `SetSuccession` for a version 3 vault and
refuses one for any other, and refuses a claim address that the program would refuse or that has
neither an account nor a key (`allowUnkeyedClaim` overrides the last); `checkinInstruction`, `contactExtendInstruction`,
`startSuccessionInstruction` and `executeSuccessionInstruction` build the four instructions.
`encodeAction` and `decodeAction` are unchanged and still refuse variant 5; `encodeHeirAction` and
`decodeHeirAction` accept it.

The cold signer (`web/signer.html`, the one file that sees the 24 words) does not change: built
from this code it is the file `main` builds, byte for byte, apart from the commit it prints. Two
things keep it so. Succession's extra Borsh field types are functions in `borshExtra.ts`, not
methods of the reader and writer classes that the signer bundles whole; and the Heir program ids
live in `succession.ts`, not in `programIds.ts`. The vault page and the cold signer cannot show or
sign a `SetSuccession` yet. They learn it together with the Heir app, in a change that is reviewed
as a change to the signer.
