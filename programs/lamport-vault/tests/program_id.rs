//! The program id each build compiles in.
//!
//! The message a vault key signs binds the program id and nothing else about the cluster, so the
//! id is what keeps a devnet signature from being a mainnet one, and a signature for the vault
//! from being one for the Heir-enabled vault. Every deployment therefore has an id of its own,
//! chosen by cargo features (docs/VERIFY.md). This test is run once per feature set in CI.

use lamport_vault::ID;

const DEVNET: &str = "B7dNdVV8shrKgqx7A5JvBQBp7vsTyQTLrdAdeiLKwXqH";
const DEVNET_HEIR: &str = "3mJU9ozZByXsHavMGfzdwDLFs9YuFaMA3jabaLwczxAV";
const SHORT_CLOCKS: &str = "3pwH161r4SZRH6nCHY4RUm7gk2NZqypyFJaUgv9a2duG";
const MAINNET: &str = "7EiE5pRP5byrY7mzvUBfXS2UD8GwGtPhbGne6D1BTR5H";
const MAINNET_HEIR: &str = "3XsnTrQJ5XmFyEyVauMmMseHph4wXkn6QWUZCRPjuEEX";

#[test]
fn the_id_is_the_one_these_features_name() {
    let expected = if cfg!(feature = "short-clocks") {
        SHORT_CLOCKS
    } else if cfg!(all(feature = "mainnet", feature = "succession")) {
        MAINNET_HEIR
    } else if cfg!(feature = "mainnet") {
        MAINNET
    } else if cfg!(feature = "succession") {
        DEVNET_HEIR
    } else {
        DEVNET
    };
    assert_eq!(ID.to_string(), expected);
}

#[test]
fn no_two_builds_share_an_id() {
    let all = [DEVNET, DEVNET_HEIR, SHORT_CLOCKS, MAINNET, MAINNET_HEIR];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}
