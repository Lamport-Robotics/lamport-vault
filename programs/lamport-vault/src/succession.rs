//! Succession: an inactivity clock for a vault (Lamport Heir). Compiled only with the `succession`
//! cargo feature; a build that carries it is a separate program with its own id, never an upgrade
//! of the vault. `docs/SUCCESSION.md` has the rules this module is written under.
//!
//! If a vault's owner signs nothing and checks in nowhere for longer than the window they chose,
//! anyone may open a public waiting period. Any signed action or check-in cancels it. If none
//! comes before the waiting period ends, anyone may release the vault to the address the owner
//! named, by the same path a signed `Close` takes.
//!
//! Nothing here adds a key to the funds path. The plan is set by a signed action
//! ([`SetSuccession`]), and the release is authorised by time passing. The two extra keys can only
//! *delay* a release: the check-in key by at most [`CHECKIN_CAP_SECS`] past the last signed action,
//! the contact key once, by [`CONTACT_EXTENSION_SECS`].
//!
//! The rules are methods on [`Succession`] that take the time as an argument, so tests and fuzzing
//! drive them without a chain. The instruction handlers below them only fetch the clock and the
//! accounts.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, CloseAccount};

use crate::{is_token_program, token_account_fields, write_account, Tombstone, Vault, VaultError, VAULT_SEED};

/// Seconds in one day of this clock: 86 400. A `short-clocks` test build makes a day last one
/// second, so a whole cycle fits in a devnet test; that build has its own program id and can never
/// be deployed as the real program.
#[cfg(not(feature = "short-clocks"))]
pub const DAY_SECS: u64 = 86_400;
/// Seconds in one day of this clock, in a `short-clocks` test build: one.
#[cfg(feature = "short-clocks")]
pub const DAY_SECS: u64 = 1;

/// Shortest inactivity window a plan may set: 90 days.
pub const MIN_WINDOW_SECS: u64 = 90 * DAY_SECS;
/// Shortest waiting period a plan may set: 30 days.
pub const MIN_WAIT_SECS: u64 = 30 * DAY_SECS;
/// Longest window or waiting period: 100 years. It also keeps the clock arithmetic far from overflow.
pub const MAX_DURATION_SECS: u64 = 36_500 * DAY_SECS;
/// A check-in counts only up to this long after the last signed action: two years. It bounds what
/// a stolen check-in key can do.
pub const CHECKIN_CAP_SECS: u64 = 730 * DAY_SECS;
/// How far the trusted contact moves the deadline, once: 90 days.
pub const CONTACT_EXTENSION_SECS: u64 = 90 * DAY_SECS;

/// The succession block of a vault: the plan, and the clock.
///
/// Present in every vault of the Heir-enabled program from creation, all zero until a
/// [`SetSuccession`] arms it. Fixed size, and placed before the vault's two vectors, so it sits at
/// one offset in every vault (114, after `created_slot`) and survives `Rotate` untouched.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Succession {
    /// Where the vault releases to. The default address means no plan is armed.
    pub claim: Pubkey,
    /// How long the owner may be inactive before a waiting period can be opened.
    pub window_secs: u64,
    /// How long an open waiting period lasts before the vault can be released.
    pub wait_secs: u64,
    /// When the last signed action executed.
    pub last_signed_ts: i64,
    /// When the last valid check-in executed.
    pub last_checkin_ts: i64,
    /// A key that may only check in. The default address means none.
    pub checkin_key: Pubkey,
    /// A trusted contact's key that may move the deadline once. The default address means none.
    pub contact_key: Pubkey,
    /// Whether the contact has used their one extension under the plan as last set.
    pub contact_used: bool,
    /// The contact's extension: the deadline is not before this. 0 when none is in force. It ends
    /// the next time the owner is active.
    pub extended_until_ts: i64,
    /// Whether a waiting period is open.
    pub wait_open: bool,
    /// When the open waiting period started. Meaningless unless `wait_open`.
    pub wait_started_ts: i64,
    /// Zero. Room for later fields without moving the vectors that follow.
    pub reserved: [u8; 54],
}

impl Default for Succession {
    /// No plan, no clock: every byte zero.
    fn default() -> Self {
        Self {
            claim: Pubkey::default(),
            window_secs: 0,
            wait_secs: 0,
            last_signed_ts: 0,
            last_checkin_ts: 0,
            checkin_key: Pubkey::default(),
            contact_key: Pubkey::default(),
            contact_used: false,
            extended_until_ts: 0,
            wait_open: false,
            wait_started_ts: 0,
            reserved: [0; 54],
        }
    }
}

impl Succession {
    /// Borsh size of the block: 200 bytes.
    pub const SPACE: usize = 32 + 8 + 8 + 8 + 8 + 32 + 32 + 1 + 8 + 1 + 8 + 54;

    /// Whether a plan is armed.
    pub fn is_armed(&self) -> bool {
        self.claim != Pubkey::default()
    }

    /// The owner's last sign of life: the last signed action, or a later check-in, but a check-in
    /// counts only up to [`CHECKIN_CAP_SECS`] past the last signed action.
    pub fn activity(&self) -> Result<i64> {
        let cap = add(self.last_signed_ts, CHECKIN_CAP_SECS)?;
        Ok(self.last_signed_ts.max(self.last_checkin_ts.min(cap)))
    }

    /// The moment after which a waiting period may be opened.
    pub fn deadline(&self) -> Result<i64> {
        Ok(add(self.activity()?, self.window_secs)?.max(self.extended_until_ts))
    }

    /// The moment from which an open waiting period may be finished.
    pub fn release_at(&self) -> Result<i64> {
        add(self.wait_started_ts, self.wait_secs)
    }

    fn cancel_wait(&mut self) {
        self.wait_open = false;
        self.wait_started_ts = 0;
    }

    /// A signed action executed at `now`: the owner is alive. Restarts the window, cancels an open
    /// waiting period and ends the contact's extension.
    pub fn on_signed_action(&mut self, now: i64) {
        self.last_signed_ts = now;
        self.extended_until_ts = 0;
        self.cancel_wait();
    }

    /// Arms, changes or clears the plan. Takes effect at once: the protection against a hasty or
    /// forced change is the clock itself, since nothing is released sooner than `window + wait`
    /// after any signed action, this one included.
    ///
    /// A clear is `claim` = the default address with every other field zero (one encoding).
    /// Naming a contact key, even the same one, gives that contact one extension again.
    pub fn set(&mut self, plan: &SetSuccession) -> Result<()> {
        if plan.claim == Pubkey::default() {
            require!(
                plan.window_secs == 0 && plan.wait_secs == 0 && plan.checkin_key == Pubkey::default() && plan.contact_key == Pubkey::default(),
                SuccessionError::ClearCarriesPlan
            );
        } else {
            require!((MIN_WINDOW_SECS..=MAX_DURATION_SECS).contains(&plan.window_secs), SuccessionError::WindowOutOfRange);
            require!((MIN_WAIT_SECS..=MAX_DURATION_SECS).contains(&plan.wait_secs), SuccessionError::WaitOutOfRange);
        }
        self.claim = plan.claim;
        self.window_secs = plan.window_secs;
        self.wait_secs = plan.wait_secs;
        self.checkin_key = plan.checkin_key;
        self.contact_key = plan.contact_key;
        self.contact_used = false;
        Ok(())
    }

    /// A check-in signed by `signer` at `now`. Counts as activity, cancels an open waiting period
    /// and ends the contact's extension, but only while it is within the cap; past the cap it
    /// fails with [`SuccessionError::CheckinPastCap`] and a signed action is due.
    pub fn checkin(&mut self, signer: &Pubkey, now: i64) -> Result<()> {
        require!(self.is_armed(), SuccessionError::NotArmed);
        require!(self.checkin_key != Pubkey::default() && *signer == self.checkin_key, SuccessionError::WrongCheckinKey);
        require!(now <= add(self.last_signed_ts, CHECKIN_CAP_SECS)?, SuccessionError::CheckinPastCap);
        self.last_checkin_ts = now;
        self.extended_until_ts = 0;
        self.cancel_wait();
        Ok(())
    }

    /// The trusted contact's one extension, signed by `signer` at `now`: the deadline moves to
    /// [`CONTACT_EXTENSION_SECS`] past the later of the old deadline and now, and an open waiting
    /// period is cancelled.
    pub fn contact_extend(&mut self, signer: &Pubkey, now: i64) -> Result<()> {
        require!(self.is_armed(), SuccessionError::NotArmed);
        require!(self.contact_key != Pubkey::default() && *signer == self.contact_key, SuccessionError::WrongContactKey);
        require!(!self.contact_used, SuccessionError::ContactAlreadyUsed);
        self.extended_until_ts = add(self.deadline()?.max(now), CONTACT_EXTENSION_SECS)?;
        self.contact_used = true;
        self.cancel_wait();
        Ok(())
    }

    /// Opens the waiting period at `now`. Anyone may; it needs a plan, no waiting period already
    /// open, and the deadline to have passed.
    pub fn start(&mut self, now: i64) -> Result<()> {
        require!(self.is_armed(), SuccessionError::NotArmed);
        require!(!self.wait_open, SuccessionError::WaitAlreadyOpen);
        require!(now > self.deadline()?, SuccessionError::BeforeDeadline);
        self.wait_open = true;
        self.wait_started_ts = now;
        Ok(())
    }

    /// Whether the vault may be released at `now`: a plan, an open waiting period, and its end reached.
    pub fn release_due(&self, now: i64) -> Result<()> {
        require!(self.is_armed(), SuccessionError::NotArmed);
        require!(self.wait_open, SuccessionError::NoWaitOpen);
        require!(now >= self.release_at()?, SuccessionError::WaitNotOver);
        Ok(())
    }
}

/// `ts + secs`, refusing overflow.
fn add(ts: i64, secs: u64) -> Result<i64> {
    i64::try_from(secs).ok().and_then(|s| ts.checked_add(s)).ok_or_else(|| error!(SuccessionError::Overflow))
}

impl Vault {
    /// Bytes the succession block adds to a vault account.
    pub const EXT: usize = Succession::SPACE;
}

/// The plan a signature sets: the payload of `Action::SetSuccession`, variant 5.
///
/// ```text
/// 5 SetSuccession { claim: Pubkey, window_secs: u64, wait_secs: u64, checkin_key: Pubkey,
///                   contact_key: Pubkey, issued_slot: u64, expiry_slot: u64 }               129 bytes
/// ```
///
/// Executed like every other action. Its one remaining account is the claim account (none when
/// clearing), which the program needs to see in order to refuse an unusable one.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SetSuccession {
    /// Where the vault releases to. The default address clears the plan.
    pub claim: Pubkey,
    /// Inactivity window, [`MIN_WINDOW_SECS`] to [`MAX_DURATION_SECS`].
    pub window_secs: u64,
    /// Waiting period, [`MIN_WAIT_SECS`] to [`MAX_DURATION_SECS`].
    pub wait_secs: u64,
    /// The check-in key, or the default address for none.
    pub checkin_key: Pubkey,
    /// The trusted contact's key, or the default address for none.
    pub contact_key: Pubkey,
    /// Slot the action was signed at; must not be in the future.
    pub issued_slot: u64,
    /// Last slot at which the action may execute; at most `issued_slot + MAX_VALIDITY_SLOTS`.
    pub expiry_slot: u64,
}

/// Succession's own errors, numbered from 6100 so the vault's codes stay where they are.
#[error_code(offset = 6100)]
pub enum SuccessionError {
    #[msg("no succession plan is armed")]
    NotArmed,
    #[msg("the signer is not the plan's check-in key")]
    WrongCheckinKey,
    #[msg("a check-in no longer counts: two years have passed since the last signed action, and one is due")]
    CheckinPastCap,
    #[msg("the signer is not the plan's contact key")]
    WrongContactKey,
    #[msg("the contact has already used their one extension")]
    ContactAlreadyUsed,
    #[msg("a waiting period is already open")]
    WaitAlreadyOpen,
    #[msg("the deadline has not passed: the owner was active within the window")]
    BeforeDeadline,
    #[msg("no waiting period is open")]
    NoWaitOpen,
    #[msg("the waiting period is not over")]
    WaitNotOver,
    #[msg("the window must be between 90 days and 100 years")]
    WindowOutOfRange,
    #[msg("the waiting period must be between 30 days and 100 years")]
    WaitOutOfRange,
    #[msg("clearing the plan takes no window, wait or keys")]
    ClearCarriesPlan,
    #[msg("the claim account must be passed as the first remaining account")]
    ClaimAccountMissing,
    #[msg("the claim address is the vault itself")]
    ClaimIsTheVault,
    #[msg("the claim address cannot receive a release: a program, a token account or mint, a sysvar, or an account of this program that is not an open vault")]
    ClaimNotUsable,
    #[msg("this is not the plan's claim address")]
    WrongClaim,
    #[msg("arithmetic overflow")]
    Overflow,
}

/// Owners whose accounts cannot usefully receive a release: programs' own data, and sysvars.
const UNUSABLE_OWNERS: [Pubkey; 6] = [
    pubkey!("Sysvar1111111111111111111111111111111111111"),
    pubkey!("NativeLoader1111111111111111111111111111111"),
    pubkey!("BPFLoader1111111111111111111111111111111111"),
    pubkey!("BPFLoader2111111111111111111111111111111111"),
    pubkey!("BPFLoaderUpgradeab1e11111111111111111111111"),
    pubkey!("LoaderV411111111111111111111111111111111111"),
];

/// Refuses a claim address that could never receive the vault: the vault itself, a program, a
/// token account or mint (SOL sent there is stuck), a sysvar, or one of this program's own accounts
/// other than an open vault. A plain address, another vault and any other program's account pass:
/// what the owner names beyond that is theirs to choose.
///
/// This runs when the plan is set. An address that turns unusable later would block the release,
/// which is one reason to name an account that cannot change, such as a claim-program plan.
pub fn check_claim(claim: &AccountInfo, vault_key: &Pubkey) -> Result<()> {
    require_keys_neq!(claim.key(), *vault_key, SuccessionError::ClaimIsTheVault);
    require!(!claim.executable, SuccessionError::ClaimNotUsable);
    require!(!is_token_program(claim.owner) && !UNUSABLE_OWNERS.contains(claim.owner), SuccessionError::ClaimNotUsable);
    if *claim.owner == crate::ID {
        let data = claim.try_borrow_data()?;
        require!(data.len() >= 8 && data[..8] == *<Vault as Discriminator>::DISCRIMINATOR, SuccessionError::ClaimNotUsable);
    }
    Ok(())
}

/// `Action::SetSuccession`, called from `verify_and_act` once the signature has been verified and
/// its leaf spent. The first remaining account is the claim account, unless the plan is cleared.
pub fn set_succession(vault: &mut Vault, vault_key: &Pubkey, plan: &SetSuccession, remaining: &[AccountInfo]) -> Result<()> {
    if plan.claim != Pubkey::default() {
        let claim = remaining.first().ok_or(SuccessionError::ClaimAccountMissing)?;
        require_keys_eq!(claim.key(), plan.claim, SuccessionError::ClaimAccountMissing);
        check_claim(claim, vault_key)?;
    }
    vault.succession.set(plan)
}

/// Called at the end of `verify_and_act`: every signed action that executed is a sign of life.
/// After a `Close` there is no vault left to record it in.
pub fn after_signed_action(vault: &mut Vault) -> Result<()> {
    if vault.version == Tombstone::VERSION {
        return Ok(());
    }
    vault.succession.on_signed_action(Clock::get()?.unix_timestamp);
    Ok(())
}

/// `checkin`: the check-in key signs; anyone may pay the fee.
pub fn handle_checkin(ctx: Context<Checkin>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    ctx.accounts.vault.succession.checkin(ctx.accounts.checkin_key.key, now)
}

/// `contact_extend`: the contact key signs; anyone may pay the fee.
pub fn handle_contact_extend(ctx: Context<ContactExtend>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    ctx.accounts.vault.succession.contact_extend(ctx.accounts.contact_key.key, now)
}

/// `start_succession`: anyone, once the deadline has passed.
pub fn handle_start_succession(ctx: Context<StartSuccession>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    ctx.accounts.vault.succession.start(now)
}

/// `execute_succession`: anyone, once the waiting period is over. Releases the vault to the plan's
/// claim address exactly as a signed `Close { to: claim }` would: empty token accounts passed as
/// `[token account, token program]` pairs are closed to the claim address, every lamport above a
/// tombstone's rent goes there, and the account becomes a `Tombstone` naming it as heir, so
/// `sweep_closed` and `sweep_closed_sol` deliver the rest. It needs no leaf and does not touch the
/// key history.
///
/// The body below the clock check repeats the `Action::Close` arm of `verify_and_act` on purpose.
/// Sharing the code would mean moving that arm, and a moved line changes the default build
/// (docs/SUCCESSION.md). A test holds the two to the same result.
pub fn handle_execute_succession<'info>(ctx: Context<'_, '_, 'info, 'info, ExecuteSuccession<'info>>) -> Result<()> {
    let clock = Clock::get()?;
    let vault = &mut ctx.accounts.vault;
    vault.succession.release_due(clock.unix_timestamp)?;

    let to = vault.succession.claim;
    let to_ai = ctx.accounts.claim.to_account_info();
    let vault_key = vault.key();
    require_keys_eq!(to_ai.key(), to, SuccessionError::WrongClaim);
    require_keys_neq!(to, vault_key, VaultError::SelfTransfer);

    let vault_id = vault.vault_id;
    let bump = vault.bump;
    let signer_seeds: &[&[u8]] = &[VAULT_SEED, &vault_id, &[bump]];
    let pairs = ctx.remaining_accounts;
    require!(pairs.chunks_exact(2).remainder().is_empty(), VaultError::MissingAccount);
    for pair in pairs.chunks_exact(2) {
        let acc_ai = &pair[0];
        let token_program = &pair[1];
        require!(is_token_program(token_program.key), VaultError::InvalidTokenProgram);
        require_keys_eq!(*acc_ai.owner, token_program.key(), VaultError::InvalidTokenProgram);
        let (_, owner, amount) = token_account_fields(acc_ai)?;
        require_keys_eq!(owner, vault_key, VaultError::NotVaultTokenAccount);
        require!(amount == 0, VaultError::TokenAccountNotEmpty);
        token_interface::close_account(CpiContext::new_with_signer(
            token_program.clone(),
            CloseAccount {
                account: acc_ai.clone(),
                destination: to_ai.clone(),
                authority: vault.to_account_info(),
            },
            &[signer_seeds],
        ))?;
    }
    let vault_ai = vault.to_account_info();
    let keep = Rent::get()?.minimum_balance(Tombstone::SPACE);
    let payout = vault_ai.lamports().checked_sub(keep).ok_or(VaultError::InsufficientFunds)?;
    vault_ai.sub_lamports(payout)?;
    to_ai.add_lamports(payout)?;
    vault_ai.resize(Tombstone::SPACE)?;
    let tombstone = Tombstone { version: Tombstone::VERSION, vault_id, closed_slot: clock.slot, heir: to };
    write_account(&vault_ai, &tombstone)?;
    // Anchor writes `vault` back at exit; with this version byte its serializer writes nothing.
    vault.version = Tombstone::VERSION;
    Ok(())
}

#[derive(Accounts)]
pub struct Checkin<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The plan's check-in key. It can do nothing else.
    pub checkin_key: Signer<'info>,
}

#[derive(Accounts)]
pub struct ContactExtend<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The plan's contact key. It can do nothing else.
    pub contact_key: Signer<'info>,
}

#[derive(Accounts)]
pub struct StartSuccession<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct ExecuteSuccession<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: must be the plan's claim address; receives the release.
    #[account(mut)]
    pub claim: UncheckedAccount<'info>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::error::ERROR_CODE_OFFSET;

    fn code<T: core::fmt::Debug>(r: Result<T>) -> u32 {
        match r.expect_err("expected an error") {
            anchor_lang::error::Error::AnchorError(a) => a.error_code_number,
            anchor_lang::error::Error::ProgramError(_) => u32::MAX,
        }
    }

    const fn e(err: SuccessionError) -> u32 {
        err as u32 + 6100
    }

    const D: i64 = DAY_SECS as i64;
    const T0: i64 = 1_800_000_000;

    fn key(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }

    fn plan(window_days: u64, wait_days: u64) -> SetSuccession {
        SetSuccession {
            claim: key(1),
            window_secs: window_days * DAY_SECS,
            wait_secs: wait_days * DAY_SECS,
            checkin_key: key(2),
            contact_key: key(3),
            issued_slot: 0,
            expiry_slot: 0,
        }
    }

    /// A plan armed by a signed action at `T0`.
    fn armed(window_days: u64, wait_days: u64) -> Succession {
        let mut s = Succession::default();
        s.set(&plan(window_days, wait_days)).unwrap();
        s.on_signed_action(T0);
        s
    }

    #[test]
    fn the_block_is_200_bytes_and_the_codes_start_at_6100() {
        assert_eq!(Succession::SPACE, 200);
        let mut bytes = Vec::new();
        Succession::default().serialize(&mut bytes).unwrap();
        assert_eq!(bytes.len(), Succession::SPACE);
        assert!(bytes.iter().all(|b| *b == 0), "an unarmed block is all zero");
        assert_eq!(Vault::EXT, 200);
        assert_eq!(code::<()>(err!(SuccessionError::NotArmed)), 6100);
        assert_eq!(code::<()>(err!(SuccessionError::Overflow)), 6116);
        assert!(6100 > ERROR_CODE_OFFSET + 37, "clear of the vault's own codes");
        let mut action = Vec::new();
        plan(365, 60).serialize(&mut action).unwrap();
        assert_eq!(1 + action.len(), 129, "variant byte + payload");
    }

    #[test]
    fn durations() {
        assert_eq!(MIN_WINDOW_SECS, 90 * DAY_SECS);
        assert_eq!(MIN_WAIT_SECS, 30 * DAY_SECS);
        assert_eq!(CHECKIN_CAP_SECS, 730 * DAY_SECS);
        assert_eq!(CONTACT_EXTENSION_SECS, 90 * DAY_SECS);
        #[cfg(not(feature = "short-clocks"))]
        assert_eq!((DAY_SECS, MIN_WINDOW_SECS, MIN_WAIT_SECS), (86_400, 7_776_000, 2_592_000));
        #[cfg(feature = "short-clocks")]
        assert_eq!((DAY_SECS, MIN_WINDOW_SECS, MIN_WAIT_SECS), (1, 90, 30));
    }

    #[test]
    fn nothing_happens_without_a_plan() {
        let mut s = Succession::default();
        assert!(!s.is_armed());
        s.on_signed_action(T0);
        assert_eq!(code(s.start(T0 + 10_000 * D)), e(SuccessionError::NotArmed));
        assert_eq!(code(s.release_due(i64::MAX)), e(SuccessionError::NotArmed));
        assert_eq!(code(s.checkin(&key(2), T0)), e(SuccessionError::NotArmed));
        assert_eq!(code(s.contact_extend(&key(3), T0)), e(SuccessionError::NotArmed));
        // the default address is never a key
        assert_eq!(code(s.checkin(&Pubkey::default(), T0)), e(SuccessionError::NotArmed));
    }

    #[test]
    fn plan_bounds() {
        let mut s = Succession::default();
        let max_days = MAX_DURATION_SECS / DAY_SECS;
        assert!(s.set(&plan(90, 30)).is_ok());
        assert!(s.set(&plan(max_days, max_days)).is_ok());
        let mut p = plan(90, 30);
        p.window_secs -= 1;
        assert_eq!(code(s.set(&p)), e(SuccessionError::WindowOutOfRange));
        let mut p = plan(90, 30);
        p.wait_secs -= 1;
        assert_eq!(code(s.set(&p)), e(SuccessionError::WaitOutOfRange));
        let mut p = plan(90, 30);
        p.window_secs = MAX_DURATION_SECS + 1;
        assert_eq!(code(s.set(&p)), e(SuccessionError::WindowOutOfRange));
        let mut p = plan(90, 30);
        p.wait_secs = u64::MAX;
        assert_eq!(code(s.set(&p)), e(SuccessionError::WaitOutOfRange));
        // a refused plan changes nothing
        assert_eq!(s.window_secs, max_days * DAY_SECS);
    }

    #[test]
    fn clearing_has_one_encoding_and_disarms() {
        let mut s = armed(365, 60);
        let clear = SetSuccession { claim: Pubkey::default(), window_secs: 0, wait_secs: 0, checkin_key: Pubkey::default(), contact_key: Pubkey::default(), issued_slot: 0, expiry_slot: 0 };
        for dirty in [
            SetSuccession { window_secs: 1, ..clear.clone() },
            SetSuccession { wait_secs: 1, ..clear.clone() },
            SetSuccession { checkin_key: key(2), ..clear.clone() },
            SetSuccession { contact_key: key(3), ..clear.clone() },
        ] {
            assert_eq!(code(s.set(&dirty)), e(SuccessionError::ClearCarriesPlan));
            assert!(s.is_armed());
        }
        s.set(&clear).unwrap();
        s.on_signed_action(T0 + D);
        assert!(!s.is_armed());
        assert_eq!((s.window_secs, s.wait_secs, s.checkin_key, s.contact_key), (0, 0, Pubkey::default(), Pubkey::default()));
        assert_eq!(code(s.start(i64::MAX / 2)), e(SuccessionError::NotArmed));
    }

    #[test]
    fn no_start_before_the_deadline_and_no_release_before_the_wait_ends() {
        let mut s = armed(365, 60);
        let deadline = T0 + 365 * D;
        assert_eq!(s.deadline().unwrap(), deadline);
        assert_eq!(code(s.start(T0)), e(SuccessionError::BeforeDeadline));
        assert_eq!(code(s.start(deadline)), e(SuccessionError::BeforeDeadline), "at the deadline is not past it");
        assert_eq!(code(s.release_due(i64::MAX / 2)), e(SuccessionError::NoWaitOpen));
        s.start(deadline + 1).unwrap();
        assert!(s.wait_open);
        assert_eq!(code(s.start(deadline + 2)), e(SuccessionError::WaitAlreadyOpen));
        let release = deadline + 1 + 60 * D;
        assert_eq!(s.release_at().unwrap(), release);
        assert_eq!(code(s.release_due(release - 1)), e(SuccessionError::WaitNotOver));
        s.release_due(release).unwrap();
        s.release_due(release + 1_000 * D).unwrap();
    }

    #[test]
    fn a_signed_action_restarts_the_window_and_cancels_the_wait() {
        let mut s = armed(90, 30);
        s.start(T0 + 90 * D + 1).unwrap();
        s.on_signed_action(T0 + 100 * D);
        assert!(!s.wait_open);
        assert_eq!(code(s.release_due(i64::MAX / 2)), e(SuccessionError::NoWaitOpen));
        assert_eq!(s.deadline().unwrap(), T0 + 190 * D);
        assert_eq!(code(s.start(T0 + 190 * D)), e(SuccessionError::BeforeDeadline));
        s.start(T0 + 190 * D + 1).unwrap();
    }

    #[test]
    fn a_checkin_counts_cancels_and_is_only_the_check_in_keys() {
        let mut s = armed(90, 30);
        assert_eq!(code(s.checkin(&key(9), T0 + D)), e(SuccessionError::WrongCheckinKey));
        assert_eq!(code(s.checkin(&key(3), T0 + D)), e(SuccessionError::WrongCheckinKey), "the contact key is not the check-in key");
        assert_eq!(code(s.checkin(&key(1), T0 + D)), e(SuccessionError::WrongCheckinKey), "nor is the claim address");
        s.checkin(&key(2), T0 + 50 * D).unwrap();
        assert_eq!(s.deadline().unwrap(), T0 + 140 * D);
        s.start(T0 + 140 * D + 1).unwrap();
        s.checkin(&key(2), T0 + 150 * D).unwrap();
        assert!(!s.wait_open, "a valid check-in cancels the waiting period");
        assert_eq!(s.deadline().unwrap(), T0 + 240 * D);

        // a plan with no check-in key accepts nobody, not even the default address
        let mut none = Succession::default();
        none.set(&SetSuccession { checkin_key: Pubkey::default(), ..plan(90, 30) }).unwrap();
        none.on_signed_action(T0);
        assert_eq!(code(none.checkin(&Pubkey::default(), T0 + D)), e(SuccessionError::WrongCheckinKey));
        assert_eq!(code(none.checkin(&key(2), T0 + D)), e(SuccessionError::WrongCheckinKey));
    }

    #[test]
    fn check_ins_stop_counting_two_years_after_the_last_signed_action() {
        let mut s = armed(90, 30);
        let cap = T0 + 730 * D;
        s.checkin(&key(2), cap).unwrap();
        assert_eq!(s.deadline().unwrap(), cap + 90 * D);
        // one second past the cap it fails and changes nothing
        let before = s.clone();
        assert_eq!(code(s.checkin(&key(2), cap + 1)), e(SuccessionError::CheckinPastCap));
        assert_eq!(s, before);
        // so a stolen check-in key delays the release to cap + window + wait at the most
        s.start(cap + 90 * D + 1).unwrap();
        assert_eq!(code(s.checkin(&key(2), cap + 100 * D)), e(SuccessionError::CheckinPastCap));
        assert!(s.wait_open, "a check-in past the cap does not cancel the waiting period");
        s.release_due(cap + 90 * D + 1 + 30 * D).unwrap();
        // a signed action opens two more years
        s.on_signed_action(cap + 100 * D);
        s.checkin(&key(2), cap + 100 * D + 730 * D).unwrap();
    }

    #[test]
    fn activity_never_runs_ahead_of_the_cap_even_with_a_stale_field() {
        // the field itself cannot pass the cap through `checkin`; if it ever did, `activity` still clamps it
        let mut s = armed(90, 30);
        s.last_checkin_ts = T0 + 5_000 * D;
        assert_eq!(s.activity().unwrap(), T0 + 730 * D);
        s.last_checkin_ts = T0 - 5;
        assert_eq!(s.activity().unwrap(), T0);
    }

    #[test]
    fn the_contact_extends_once_from_the_later_of_deadline_and_now() {
        // before the deadline: the deadline moves 90 days out
        let mut s = armed(90, 30);
        assert_eq!(code(s.contact_extend(&key(2), T0 + D)), e(SuccessionError::WrongContactKey), "the check-in key is not the contact");
        assert_eq!(code(s.contact_extend(&key(9), T0 + D)), e(SuccessionError::WrongContactKey));
        s.contact_extend(&key(3), T0 + 10 * D).unwrap();
        assert_eq!(s.deadline().unwrap(), T0 + 180 * D);
        assert_eq!(code(s.contact_extend(&key(3), T0 + 11 * D)), e(SuccessionError::ContactAlreadyUsed));

        // long after the deadline, with a waiting period open: 90 days from now, not from the old deadline
        let mut late = armed(90, 30);
        late.start(T0 + 300 * D).unwrap();
        late.contact_extend(&key(3), T0 + 310 * D).unwrap();
        assert!(!late.wait_open);
        assert_eq!(late.deadline().unwrap(), T0 + 400 * D);
        assert_eq!(code(late.start(T0 + 400 * D)), e(SuccessionError::BeforeDeadline));
        late.start(T0 + 400 * D + 1).unwrap();
    }

    #[test]
    fn the_extension_ends_when_the_owner_is_next_active_and_a_new_plan_grants_another() {
        let mut s = armed(90, 30);
        s.contact_extend(&key(3), T0 + 80 * D).unwrap();
        assert_eq!(s.deadline().unwrap(), T0 + 180 * D);
        s.checkin(&key(2), T0 + 100 * D).unwrap();
        assert_eq!(s.deadline().unwrap(), T0 + 190 * D, "back to activity + window");
        assert_eq!(code(s.contact_extend(&key(3), T0 + 101 * D)), e(SuccessionError::ContactAlreadyUsed), "still used");

        let mut s = armed(90, 30);
        s.contact_extend(&key(3), T0 + 80 * D).unwrap();
        s.on_signed_action(T0 + 100 * D);
        assert_eq!(s.deadline().unwrap(), T0 + 190 * D);
        // the owner restates the plan: the contact may extend once more
        s.set(&plan(90, 30)).unwrap();
        s.on_signed_action(T0 + 120 * D);
        s.contact_extend(&key(3), T0 + 121 * D).unwrap();

        // no contact key: nobody extends
        let mut none = Succession::default();
        none.set(&SetSuccession { contact_key: Pubkey::default(), ..plan(90, 30) }).unwrap();
        none.on_signed_action(T0);
        assert_eq!(code(none.contact_extend(&Pubkey::default(), T0 + D)), e(SuccessionError::WrongContactKey));
    }

    #[test]
    fn a_plan_change_takes_effect_at_once_and_still_nothing_releases_for_window_plus_wait() {
        let mut s = armed(365, 60);
        // day 100: a new claim address and the shortest clock
        let t = T0 + 100 * D;
        s.set(&SetSuccession { claim: key(7), ..plan(90, 30) }).unwrap();
        s.on_signed_action(t);
        assert_eq!(s.claim, key(7));
        assert_eq!(code(s.start(t + 90 * D)), e(SuccessionError::BeforeDeadline));
        s.start(t + 90 * D + 1).unwrap();
        assert_eq!(code(s.release_due(t + 120 * D)), e(SuccessionError::WaitNotOver));
        s.release_due(t + 120 * D + 1).unwrap();
    }

    /// `check_claim` on an account built by hand: `(owner, executable, data)`.
    fn claim_check(key: Pubkey, owner: Pubkey, executable: bool, data: &[u8], vault_key: &Pubkey) -> Result<()> {
        let mut lamports = 1_000_000u64;
        let mut data = data.to_vec();
        let ai = AccountInfo::new(&key, false, false, &mut lamports, &mut data, &owner, executable, 0);
        check_claim(&ai, vault_key)
    }

    #[test]
    fn which_accounts_may_be_a_claim_address() {
        let vault = key(50);
        let system = Pubkey::default(); // the System Program's id is the all-zero address
        let unusable = e(SuccessionError::ClaimNotUsable);
        // a plain wallet, an address with nothing at it, another program's data account
        assert!(claim_check(key(1), system, false, &[], &vault).is_ok());
        assert!(claim_check(key(1), key(77), false, &[1, 2, 3], &vault).is_ok());
        // the vault itself
        assert_eq!(code(claim_check(vault, crate::ID, false, &[], &vault)), e(SuccessionError::ClaimIsTheVault));
        // executable, whoever owns it: a loader this program has never heard of included
        assert_eq!(code(claim_check(key(1), key(77), true, &[], &vault)), unusable);
        assert_eq!(code(claim_check(key(1), system, true, &[], &vault)), unusable);
        // token accounts and mints, sysvars, and what the loaders own
        for owner in [anchor_spl::token::ID, anchor_spl::token_2022::ID].into_iter().chain(UNUSABLE_OWNERS) {
            assert_eq!(code(claim_check(key(1), owner, false, &[0u8; 165], &vault)), unusable, "owner {owner}");
        }
        // an account of this program: only an open vault
        let mut open = <Vault as Discriminator>::DISCRIMINATOR.to_vec();
        open.extend_from_slice(&[3u8; 40]);
        assert!(claim_check(key(1), crate::ID, false, &open, &vault).is_ok(), "another open vault");
        let mut tombstone = <Tombstone as Discriminator>::DISCRIMINATOR.to_vec();
        tombstone.extend_from_slice(&[0xFE; 73]);
        assert_eq!(code(claim_check(key(1), crate::ID, false, &tombstone, &vault)), unusable, "a closed vault");
        assert_eq!(code(claim_check(key(1), crate::ID, false, &[], &vault)), unusable, "an empty account of this program");
        assert_eq!(code(claim_check(key(1), crate::ID, false, &[1, 2, 3, 4, 5, 6, 7, 8, 9], &vault)), unusable, "a signature buffer or anything else");
    }

    #[test]
    fn the_clock_refuses_to_overflow() {
        let mut s = armed(90, 30);
        s.last_signed_ts = i64::MAX - 10;
        assert_eq!(code(s.activity()), e(SuccessionError::Overflow));
        assert_eq!(code(s.deadline()), e(SuccessionError::Overflow));
        assert_eq!(code(s.start(i64::MAX)), e(SuccessionError::Overflow));
        assert_eq!(code(s.checkin(&key(2), i64::MAX)), e(SuccessionError::Overflow));
        let mut w = armed(90, 30);
        w.wait_open = true;
        w.wait_started_ts = i64::MAX - 5;
        assert_eq!(code(w.release_due(i64::MAX)), e(SuccessionError::Overflow));
    }
}
