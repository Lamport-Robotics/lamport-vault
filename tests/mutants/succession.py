#!/usr/bin/env python3
"""Mutation check for the succession feature.

Breaks the succession code one way at a time, rebuilds the program with the feature, and runs the
crate's unit tests and the LiteSVM suite. Every mutant has to be caught by at least one test; a
mutant that survives is a rule no test defends. Each mutation is a text replacement in
programs/lamport-vault/src, undone before the next one.

    python3 tests/mutants/succession.py                # all of them
    python3 tests/mutants/succession.py cap            # only mutants whose name contains "cap"
    python3 tests/mutants/succession.py --shard 2/4    # every fourth mutant, starting with the second (CI)

Needs `cargo build-sbf` on the PATH. Exits non-zero if a mutant survives, or if a pattern no longer
matches the source (then the list below needs the same edit the source got).
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "programs", "lamport-vault", "src")
BUILD = "cargo build-sbf --manifest-path programs/lamport-vault/Cargo.toml --features succession"

# (what the mutant does, file, text to find exactly once, replacement)
MUTANTS = [
    ("a waiting period may open before the deadline", "succession.rs",
     "        require!(now > self.deadline()?, SuccessionError::BeforeDeadline);\n", ""),
    ("a waiting period may open exactly at the deadline", "succession.rs",
     "        require!(now > self.deadline()?, SuccessionError::BeforeDeadline);\n",
     "        require!(now >= self.deadline()?, SuccessionError::BeforeDeadline);\n"),
    ("a second waiting period may open over the first", "succession.rs",
     "        require!(!self.wait_open, SuccessionError::WaitAlreadyOpen);\n", ""),
    ("a waiting period may open with no plan", "succession.rs",
     "        require!(self.is_armed(), SuccessionError::NotArmed);\n        require!(!self.wait_open, SuccessionError::WaitAlreadyOpen);\n",
     "        require!(!self.wait_open, SuccessionError::WaitAlreadyOpen);\n"),
    ("the release does not wait out the waiting period", "succession.rs",
     "        require!(now >= self.release_at()?, SuccessionError::WaitNotOver);\n", ""),
    ("the release may come one second early", "succession.rs",
     "        require!(now >= self.release_at()?, SuccessionError::WaitNotOver);\n",
     "        require!(now + 1 >= self.release_at()?, SuccessionError::WaitNotOver);\n"),
    ("the release needs no open waiting period", "succession.rs",
     "        require!(self.wait_open, SuccessionError::NoWaitOpen);\n", ""),
    ("the release goes to whatever account is passed", "succession.rs",
     "    require_keys_eq!(to_ai.key(), to, SuccessionError::WrongClaim);\n", ""),
    ("a signed action does not cancel the waiting period", "succession.rs",
     "        self.last_signed_ts = now;\n        self.extended_until_ts = 0;\n        self.cancel_wait();\n",
     "        self.last_signed_ts = now;\n        self.extended_until_ts = 0;\n"),
    ("a signed action does not restart the window", "succession.rs",
     "        self.last_signed_ts = now;\n        self.extended_until_ts = 0;\n        self.cancel_wait();\n",
     "        self.extended_until_ts = 0;\n        self.cancel_wait();\n"),
    ("a signed action does not end the contact's extension", "succession.rs",
     "        self.last_signed_ts = now;\n        self.extended_until_ts = 0;\n        self.cancel_wait();\n",
     "        self.last_signed_ts = now;\n        self.cancel_wait();\n"),
    ("signed actions are not seen by the clock at all", "lib.rs",
     '    #[cfg(feature = "succession")] crate::succession::after_signed_action(vault)?; Ok(())\n', "    Ok(())\n"),
    ("check-ins count for ever", "succession.rs",
     "        require!(now <= add(self.last_signed_ts, CHECKIN_CAP_SECS)?, SuccessionError::CheckinPastCap);\n", ""),
    ("a check-in counts one second past the cap", "succession.rs",
     "        require!(now <= add(self.last_signed_ts, CHECKIN_CAP_SECS)?, SuccessionError::CheckinPastCap);\n",
     "        require!(now <= add(self.last_signed_ts, CHECKIN_CAP_SECS)? + 1, SuccessionError::CheckinPastCap);\n"),
    ("anyone may check in", "succession.rs",
     "        require!(self.checkin_key != Pubkey::default() && *signer == self.checkin_key, SuccessionError::WrongCheckinKey);\n", ""),
    ("a check-in does not cancel the waiting period", "succession.rs",
     "        self.last_checkin_ts = now;\n        self.extended_until_ts = 0;\n        self.cancel_wait();\n",
     "        self.last_checkin_ts = now;\n        self.extended_until_ts = 0;\n"),
    ("a check-in does not count as activity", "succession.rs",
     "        self.last_checkin_ts = now;\n        self.extended_until_ts = 0;\n        self.cancel_wait();\n",
     "        self.extended_until_ts = 0;\n        self.cancel_wait();\n"),
    ("a check-in does not end the contact's extension", "succession.rs",
     "        self.last_checkin_ts = now;\n        self.extended_until_ts = 0;\n        self.cancel_wait();\n",
     "        self.last_checkin_ts = now;\n        self.cancel_wait();\n"),
    ("activity ignores the cap", "succession.rs",
     "        Ok(self.last_signed_ts.max(self.last_checkin_ts.min(cap)))\n",
     "        let _ = cap;\n        Ok(self.last_signed_ts.max(self.last_checkin_ts))\n"),
    ("the contact may extend again and again", "succession.rs",
     "        require!(!self.contact_used, SuccessionError::ContactAlreadyUsed);\n", ""),
    ("anyone may extend", "succession.rs",
     "        require!(self.contact_key != Pubkey::default() && *signer == self.contact_key, SuccessionError::WrongContactKey);\n", ""),
    ("an extension counts from the old deadline even when it is long past", "succession.rs",
     "        self.extended_until_ts = add(self.deadline()?.max(now), CONTACT_EXTENSION_SECS)?;\n",
     "        self.extended_until_ts = add(self.deadline()?, CONTACT_EXTENSION_SECS)?;\n"),
    ("an extension does not cancel the waiting period", "succession.rs",
     "        self.contact_used = true;\n        self.cancel_wait();\n", "        self.contact_used = true;\n"),
    ("the deadline ignores the extension", "succession.rs",
     "        Ok(add(self.activity()?, self.window_secs)?.max(self.extended_until_ts))\n",
     "        add(self.activity()?, self.window_secs)\n"),
    ("a restated plan does not give the contact another extension", "succession.rs",
     "        self.contact_key = plan.contact_key;\n        self.contact_used = false;\n", "        self.contact_key = plan.contact_key;\n"),
    ("no floor under the window", "succession.rs",
     "            require!((MIN_WINDOW_SECS..=MAX_DURATION_SECS).contains(&plan.window_secs), SuccessionError::WindowOutOfRange);\n",
     "            require!(plan.window_secs <= MAX_DURATION_SECS, SuccessionError::WindowOutOfRange);\n"),
    ("no ceiling over the window", "succession.rs",
     "            require!((MIN_WINDOW_SECS..=MAX_DURATION_SECS).contains(&plan.window_secs), SuccessionError::WindowOutOfRange);\n",
     "            require!(plan.window_secs >= MIN_WINDOW_SECS, SuccessionError::WindowOutOfRange);\n"),
    ("no floor under the waiting period", "succession.rs",
     "            require!((MIN_WAIT_SECS..=MAX_DURATION_SECS).contains(&plan.wait_secs), SuccessionError::WaitOutOfRange);\n",
     "            require!(plan.wait_secs <= MAX_DURATION_SECS, SuccessionError::WaitOutOfRange);\n"),
    ("a clear may carry a plan", "succession.rs",
     "            require!(\n                plan.window_secs == 0 && plan.wait_secs == 0 && plan.checkin_key == Pubkey::default() && plan.contact_key == Pubkey::default(),\n                SuccessionError::ClearCarriesPlan\n            );\n", ""),
    ("the claim account need not be shown", "succession.rs",
     "        require_keys_eq!(claim.key(), plan.claim, SuccessionError::ClaimAccountMissing);\n", ""),
    ("the vault may be its own claim address", "succession.rs",
     "    require_keys_neq!(claim.key(), *vault_key, SuccessionError::ClaimIsTheVault);\n", ""),
    ("a program may be the claim address", "succession.rs",
     "    require!(!claim.executable, SuccessionError::ClaimNotUsable);\n", ""),
    ("a token account or a sysvar may be the claim address", "succession.rs",
     "    require!(!is_token_program(claim.owner) && !UNUSABLE_OWNERS.contains(claim.owner), SuccessionError::ClaimNotUsable);\n", ""),
    ("a closed vault may be the claim address", "succession.rs",
     "        require!(data.len() >= 8 && data[..8] == *<Vault as Discriminator>::DISCRIMINATOR, SuccessionError::ClaimNotUsable);\n", ""),
    ("the release closes token accounts that still hold tokens", "succession.rs",
     "        require!(amount == 0, VaultError::TokenAccountNotEmpty);\n", ""),
    ("the release takes the tombstone's rent too", "succession.rs",
     "    let keep = Rent::get()?.minimum_balance(Tombstone::SPACE);\n    let payout = vault_ai.lamports().checked_sub(keep).ok_or(VaultError::InsufficientFunds)?;\n    vault_ai.sub_lamports(payout)?;\n    to_ai.add_lamports(payout)?;\n    vault_ai.resize(Tombstone::SPACE)?;\n    let tombstone = Tombstone { version: Tombstone::VERSION, vault_id, closed_slot: clock.slot, heir: to };",
     "    let keep = Rent::get()?.minimum_balance(Tombstone::SPACE) - 1;\n    let payout = vault_ai.lamports().checked_sub(keep).ok_or(VaultError::InsufficientFunds)?;\n    vault_ai.sub_lamports(payout)?;\n    to_ai.add_lamports(payout)?;\n    vault_ai.resize(Tombstone::SPACE)?;\n    let tombstone = Tombstone { version: Tombstone::VERSION, vault_id, closed_slot: clock.slot, heir: to };"),
    ("the tombstone names somebody else", "succession.rs",
     "    let tombstone = Tombstone { version: Tombstone::VERSION, vault_id, closed_slot: clock.slot, heir: to };",
     "    let tombstone = Tombstone { version: Tombstone::VERSION, vault_id, closed_slot: clock.slot, heir: vault_key };"),
    ("the tombstone records the wrong slot", "succession.rs",
     "    let tombstone = Tombstone { version: Tombstone::VERSION, vault_id, closed_slot: clock.slot, heir: to };",
     "    let tombstone = Tombstone { version: Tombstone::VERSION, vault_id, closed_slot: 0, heir: to };"),
]


def sh(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True)


def failed_tests(output):
    return [l.split()[1] for l in output.splitlines() if l.startswith("test ") and l.rstrip().endswith("FAILED")]


def main():
    only = sys.argv[1:]
    shard, shards = 1, 1
    if "--shard" in only:
        at = only.index("--shard")
        shard, shards = (int(x) for x in only[at + 1].split("/"))
        if not 1 <= shard <= shards:
            print(f"--shard {shard}/{shards}: the first number runs from 1 to the second")
            return 2
        del only[at:at + 2]
    bad = []
    ran = 0
    for index, (name, file, old, new) in enumerate(MUTANTS):
        if index % shards != shard - 1:
            continue
        if only and not any(o in name for o in only):
            continue
        ran += 1
        path = os.path.join(SRC, file)
        with open(path) as f:
            original = f.read()
        if original.count(old) != 1:
            print(f"SETUP     {name}: pattern found {original.count(old)} times in {file}", flush=True)
            bad.append(name)
            continue
        try:
            with open(path, "w") as f:
                f.write(original.replace(old, new))
            build = sh(BUILD, ROOT)
            if build.returncode != 0:
                # a mutant that does not compile cannot ship; it tells us nothing about the tests
                print(f"NO BUILD  {name}", flush=True)
                bad.append(name)
                continue
            unit = sh("cargo test -p lamport-vault --features succession 2>&1", ROOT)
            svm = sh("cargo test --features succession 2>&1", os.path.join(ROOT, "tests", "svm"))
            caught_unit, caught_svm = failed_tests(unit.stdout), failed_tests(svm.stdout)
            if caught_unit or caught_svm:
                where = f"{len(caught_unit)} unit, {len(caught_svm)} on chain"
                print(f"caught    {name}: {where}, e.g. {(caught_svm or caught_unit)[0]}", flush=True)
            else:
                print(f"SURVIVED  {name}", flush=True)
                bad.append(name)
        finally:
            with open(path, "w") as f:
                f.write(original)
    if ran == 0:
        print("no mutant was selected")
        return 1
    restored = sh(BUILD, ROOT)
    if restored.returncode != 0:
        print("the restored source does not build:", restored.stderr[-400:])
        return 1
    if bad:
        print(f"{len(bad)} mutant(s) not caught: {bad}")
        return 1
    print(f"every mutant was caught ({ran} of {len(MUTANTS)} run)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
