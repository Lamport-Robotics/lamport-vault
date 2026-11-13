//! Succession: an inactivity clock for a vault (Lamport Heir). Compiled only with the `succession`
//! cargo feature; a build that carries it is a separate program with its own id, never an upgrade
//! of the vault. `docs/SUCCESSION.md` has the rules this module is written under.
//!
//! Scaffold: no state, no instruction and no behaviour yet. The feature is wired through CI first
//! (the vault's suites with it on and off, and the check that the default build keeps its bytes),
//! so that everything added here later lands under those checks.

#[cfg(test)]
mod tests {
    /// Runs only in the legs of CI that pass `--features succession`: proof that those legs
    /// compile this module.
    #[test]
    fn compiled_only_with_the_feature() {
        assert!(cfg!(feature = "succession"));
    }
}
