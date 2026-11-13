# The `succession` feature

`succession` is a cargo feature of the `lamport-vault` crate. It will hold the on-chain inactivity
clock of Lamport Heir: if a vault's owner signs nothing and checks in nowhere for a long time, anyone
may open a public waiting period, and when it runs out the vault releases to an address the owner
named. The design is in the Heir repository:
[lamport-heir, `docs/design-note.md`](https://github.com/Lamport-Robotics/lamport-heir/blob/main/docs/design-note.md).

**Today it is a scaffold.** The feature exists and CI builds and tests with it, but
`programs/lamport-vault/src/succession.rs` adds no state, no instruction and no behaviour yet.

Two things hold for everything that lands behind it.

## 1. The default build does not change

Without the feature, `lamport_vault.so` must be byte-for-byte the program it is without this code.
A build *with* the feature is a different program: it gets its own program id and its own
deployment, and is never an upgrade of the vault.

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

`.github/workflows/succession.yml` enforces it: on a pull request from a branch named
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
| `cargo test --workspace` | `test.yml`, job `rust` | yes | yes |
| `anchor test` on a local validator | `anchor.yml` | yes, and with `small-history` | yes, and with `small-history` |
| `execute_direct` in LiteSVM | `anchor.yml` | yes | yes |
| reproducible build | `succession.yml` | compared with the base | hash and size printed, `.so` uploaded |

Locally:

```sh
cargo test --workspace --features lamport-lms/sign                               # as always
cargo test --workspace --features lamport-lms/sign,lamport-vault/succession      # with the feature
anchor test -- --features succession
```
