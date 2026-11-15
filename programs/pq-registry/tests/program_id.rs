//! The program id each build compiles in: devnet's by default, mainnet's with the `mainnet`
//! feature (docs/VERIFY.md). The message a committed key signs binds the program id and nothing
//! else about the cluster, so the two clusters never share one.

use pq_registry::ID;

const DEVNET: &str = "48J2BtWFjEUbGPYf1yMPBkHxpy4dLo69gK2znQR2q2ad";
const MAINNET: &str = "9MYg9uqYBrTPXA6MNRZ6cbpwHSissY3496Y84iofTaNF";

#[test]
fn the_id_is_the_one_these_features_name() {
    let expected = if cfg!(feature = "mainnet") { MAINNET } else { DEVNET };
    assert_eq!(ID.to_string(), expected);
    assert_ne!(DEVNET, MAINNET);
}
