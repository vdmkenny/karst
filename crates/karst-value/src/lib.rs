//! KARST L14: capacity credentials that are earned and spent without linking the two.
//!
//! Issue #15. The whitepaper names this the most serious unresolved problem in the stack:
//! L14 needs settlement observable enough to be trusted, L4 needs it unlinkable, and a
//! payment system inside an anonymity network is a notorious correlation surface. If who
//! paid whom is observable, the anonymity above it is decorative.
//!
//! # The resolution: do not build money
//!
//! The conflict dissolves once you stop trying to make *payments* unlinkable and instead
//! separate two acts that have no reason to be joined:
//!
//! | | Acquisition | Spending |
//! |---|---|---|
//! | Frequency | rare | constant |
//! | Linkable | yes, and it does not matter | **never** |
//! | Reveals | that you obtained *n* units | that *someone* holds a valid unit |
//! | Anonymity set | irrelevant | everyone who ever acquired |
//!
//! A credential is acquired in the open and spent unlinkably. The spender's anonymity set is
//! not "everyone spending right now", it is **everyone who ever acquired a credential**,
//! which is far larger and grows monotonically.
//!
//! This is the design in *Coconut* (Sonnino, Al-Bassam, Bano, Meiklejohn, Danezis, NDSS
//! 2019), whose stated applications include anonymous payments and distributing proxies for
//! censorship resistance. The older single-issuer construction is Chaum's blind signature,
//! now standardised as RFC 9474.
//!
//! # And do not touch money at all
//!
//! The second move matters more for KARST. **Capacity is earned by providing capacity.** A
//! relay that carries traffic earns credentials; a client that consumes capacity spends them.
//! The loop closes with no bank, no processor, and nothing to de-bank, which is what L14
//! required in the first place. A financial on-ramp can exist, and it is optional rather than
//! structural.
//!
//! # Status
//!
//! Threshold issuance here is real Shamir sharing over a prime field. **The blind signature
//! is not implemented.** This crate models the protocol shape: issuers receive a blinded
//! commitment and never see the serial, so the issuance transcript and the spend transcript
//! share no field. That information-flow property is tested. The cryptographic binding needs
//! Coconut or RFC 9474.
//!
//! Verification here uses the threshold-issued secret, so a verifier could forge a credential
//! it never issued. Coconut gives public verifiability against an issuer public key and
//! removes that. Noted rather than hidden.

pub mod blind;
pub mod doublespend;
pub mod shamir;

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use shamir::{Share, P};

/// Every credential is worth exactly one unit.
///
/// Variable denominations are a fingerprint: an observer who sees a 4,096-unit credential
/// spent has narrowed the spender to whoever acquired one. Fixed denomination means every
/// credential on the wire is indistinguishable from every other, and larger amounts are
/// several credentials.
pub const UNIT: u64 = 1;

/// Bytes of a credential on the wire. Constant, for the same reason.
pub const CREDENTIAL_BYTES: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    /// Fewer partials than the issuer set's threshold.
    BelowThreshold { got: usize, need: usize },
    /// Two partials from the same issuer, which does not count twice.
    DuplicateIssuer(u64),
    /// The credential does not verify against the issuer set.
    Invalid,
    /// This serial has already been spent at this verifier.
    AlreadySpent,
    /// The earned-service warrant does not cover the requested amount.
    Unearned { requested: u64, earned: u64 },
}

impl core::fmt::Display for ValueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ValueError::BelowThreshold { got, need } => {
                write!(f, "{got} partial(s), need {need}")
            }
            ValueError::DuplicateIssuer(i) => write!(f, "issuer {i} contributed twice"),
            ValueError::Invalid => write!(f, "credential does not verify"),
            ValueError::AlreadySpent => write!(f, "credential already spent here"),
            ValueError::Unearned { requested, earned } => {
                write!(f, "requested {requested} units against {earned} earned")
            }
        }
    }
}

impl std::error::Error for ValueError {}

// ---------------------------------------------------------------- issuance

/// One issuer's share of the issuing key. No issuer holds the whole thing.
#[derive(Clone, Copy, Debug)]
pub struct Issuer {
    share: Share,
}

/// A threshold issuer set. `threshold` of `issuers.len()` must cooperate to issue, and fewer
/// than `threshold` colluding issuers learn nothing about the key.
///
/// This is what stops L14 becoming error 03. A single issuer sees every request and can link
/// every one to the party that made it.
pub struct IssuerSet {
    pub threshold: usize,
    issuers: Vec<Issuer>,
    /// Held here only so a verifier in this proof of concept can check a credential.
    /// Coconut publishes a verification key instead and no party needs the secret.
    secret: u128,
}

impl IssuerSet {
    pub fn new(threshold: usize, count: usize, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let secret: u128 = rng.gen_range(1..P);
        let shares = shamir::split(secret, threshold, count, seed);
        IssuerSet {
            threshold,
            issuers: shares.into_iter().map(|share| Issuer { share }).collect(),
            secret,
        }
    }

    pub fn count(&self) -> usize {
        self.issuers.len()
    }

    /// What an issuer sees, and everything it will ever see.
    pub fn partial(&self, issuer_index: usize, req: &IssuanceRequest) -> PartialCredential {
        let _ = req; // the blinded commitment binds the request; the share does the work
        PartialCredential {
            share: self.issuers[issuer_index].share,
        }
    }
}

/// What a holder sends to issuers.
///
/// Carries a **blinded** commitment and a warrant proving service was performed. It does not
/// carry the serial, and the serial is what a verifier later sees. That gap is the whole
/// design.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceRequest {
    pub blinded: [u8; 32],
    pub warrant: EarnedWarrant,
}

/// Proof that a relay carried traffic, which is how credentials enter circulation.
///
/// Signed by whoever received the service. This is the acquisition side, and it is
/// deliberately linkable: it says a relay did work, which is public anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarnedWarrant {
    pub relay: [u8; 32],
    pub units: u64,
    pub epoch: u64,
}

/// One issuer's contribution.
#[derive(Clone, Copy, Debug)]
pub struct PartialCredential {
    share: Share,
}

// ---------------------------------------------------------------- credential

/// A spendable unit of capacity.
///
/// Fixed size, fixed value, and carrying nothing that appears in the issuance transcript.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Credential {
    /// Chosen by the holder, never shown to an issuer, revealed only when spent so that
    /// double spending can be caught.
    pub serial: [u8; 32],
    witness: u128,
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately does not print the witness. Debug output ending up in a log is a
        // realistic way for a credential to leak.
        write!(f, "Credential(serial {})", hex_short(&self.serial))
    }
}

fn hex_short(b: &[u8]) -> String {
    b[..5].iter().map(|x| format!("{x:02x}")).collect()
}

fn witness_for(secret: u128, serial: &[u8; 32]) -> u128 {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.credential.v0");
    h.update(&secret.to_le_bytes());
    h.update(serial);
    let mut out = [0u8; 16];
    h.finalize_xof().fill(&mut out);
    u128::from_le_bytes(out) % P
}

/// A holder's wallet: serials it has chosen and the blinding it used.
pub struct Wallet {
    rng: StdRng,
    pending: Vec<([u8; 32], [u8; 32])>,
}

impl Wallet {
    pub fn new(seed: u64) -> Self {
        Wallet {
            rng: StdRng::seed_from_u64(seed),
            pending: Vec::new(),
        }
    }

    /// Choose a serial, blind it, and ask for issuance against earned service.
    ///
    /// The returned request contains `blake3(serial || blinding)`. Recovering the serial from
    /// it requires the blinding, which never leaves the wallet.
    pub fn request(&mut self, warrant: EarnedWarrant) -> IssuanceRequest {
        let serial: [u8; 32] = self.rng.gen();
        let blinding: [u8; 32] = self.rng.gen();

        let mut h = blake3::Hasher::new();
        h.update(b"karst.blind.v0");
        h.update(&serial);
        h.update(&blinding);
        let blinded = *h.finalize().as_bytes();

        self.pending.push((serial, blinding));
        IssuanceRequest { blinded, warrant }
    }

    /// Combine partials into a credential. Requires at least the issuer set's threshold.
    pub fn assemble(
        &mut self,
        set: &IssuerSet,
        partials: &[PartialCredential],
    ) -> Result<Credential, ValueError> {
        if partials.len() < set.threshold {
            return Err(ValueError::BelowThreshold {
                got: partials.len(),
                need: set.threshold,
            });
        }
        let mut seen = BTreeSet::new();
        for p in partials {
            if !seen.insert(p.share.index) {
                return Err(ValueError::DuplicateIssuer(p.share.index));
            }
        }

        let shares: Vec<Share> = partials.iter().map(|p| p.share).collect();
        let secret = shamir::combine(&shares).ok_or(ValueError::Invalid)?;

        let (serial, _blinding) = self.pending.pop().ok_or(ValueError::Invalid)?;
        Ok(Credential {
            serial,
            witness: witness_for(secret, &serial),
        })
    }
}

// ---------------------------------------------------------------- spending

/// What a verifier records when a credential is spent. Compare against [`IssuanceRequest`]:
/// no field is common to both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendRecord {
    pub serial: [u8; 32],
    pub units: u64,
}

/// Verifier-side double-spend state.
///
/// **The honest limit, which is the same one [`karst_cap::UseLedger`] has.** This catches a
/// serial spent twice *at this verifier*. Two disconnected verifiers both accept the same
/// credential, because neither can know about the other without talking to it, and requiring
/// them to talk reintroduces the always-online authority this stack exists to remove.
///
/// So a credential is worth one unit per verifier, not one unit in the universe. Options are
/// a shared ledger with its consensus cost, short epochs that bound the damage, or accepting
/// that relays each honour a credential once. None is free and the design should say which it
/// picked rather than implying the problem is solved.
#[derive(Default)]
pub struct SpendLedger {
    spent: BTreeSet<[u8; 32]>,
    records: Vec<SpendRecord>,
}

impl SpendLedger {
    pub fn new() -> Self {
        SpendLedger::default()
    }

    pub fn accept(
        &mut self,
        set: &IssuerSet,
        cred: &Credential,
    ) -> Result<SpendRecord, ValueError> {
        if witness_for(set.secret, &cred.serial) != cred.witness {
            return Err(ValueError::Invalid);
        }
        if !self.spent.insert(cred.serial) {
            return Err(ValueError::AlreadySpent);
        }
        let rec = SpendRecord {
            serial: cred.serial,
            units: UNIT,
        };
        self.records.push(rec.clone());
        Ok(rec)
    }

    pub fn spent_count(&self) -> usize {
        self.spent.len()
    }

    pub fn records(&self) -> &[SpendRecord] {
        &self.records
    }
}

/// Tracks how much service a relay has performed and how much it has drawn against it, so
/// credentials cannot be minted from nothing.
#[derive(Default)]
pub struct EarnLedger {
    earned: BTreeMap<[u8; 32], u64>,
    drawn: BTreeMap<[u8; 32], u64>,
}

impl EarnLedger {
    pub fn new() -> Self {
        EarnLedger::default()
    }

    /// Record service performed. In deployment this is attested by the party served.
    pub fn credit(&mut self, relay: [u8; 32], units: u64) {
        *self.earned.entry(relay).or_default() += units;
    }

    pub fn balance(&self, relay: &[u8; 32]) -> u64 {
        self.earned.get(relay).copied().unwrap_or(0)
            - self.drawn.get(relay).copied().unwrap_or(0)
    }

    /// Authorise issuance against earned service.
    pub fn draw(&mut self, warrant: &EarnedWarrant) -> Result<(), ValueError> {
        let available = self.balance(&warrant.relay);
        if warrant.units > available {
            return Err(ValueError::Unearned {
                requested: warrant.units,
                earned: available,
            });
        }
        *self.drawn.entry(warrant.relay).or_default() += warrant.units;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warrant(relay: u8, units: u64) -> EarnedWarrant {
        EarnedWarrant {
            relay: [relay; 32],
            units,
            epoch: 1,
        }
    }

    fn issue(set: &IssuerSet, w: &mut Wallet, which: &[usize]) -> Result<Credential, ValueError> {
        let req = w.request(warrant(1, 1));
        let partials: Vec<PartialCredential> =
            which.iter().map(|i| set.partial(*i, &req)).collect();
        w.assemble(set, &partials)
    }

    /// Sub-threshold partials must not produce a usable credential, not merely an error.
    ///
    /// The previous version asserted on the error's own `got` and `need` counters, which are
    /// computed from the length of the slice passed in. That holds however the cryptography
    /// behaves: a `combine` that reconstructed the secret from two of three partials would
    /// still have produced `BelowThreshold` from the arithmetic, because the count check runs
    /// first and never reaches the material.
    #[test]
    fn sub_threshold_partials_do_not_reconstruct_a_usable_credential() {
        let set = IssuerSet::new(3, 5, 1);
        let mut w = Wallet::new(9);
        let good = issue(&set, &mut w, &[0, 1, 2]).expect("a threshold subset must mint");

        // The count check, kept because it is the caller-facing behaviour.
        let mut w2 = Wallet::new(9);
        assert_eq!(
            issue(&set, &mut w2, &[0, 1]),
            Err(ValueError::BelowThreshold { got: 2, need: 3 })
        );

        // And the property underneath it, which the count check never reaches: fewer than a
        // threshold of shares do not reconstruct the secret.
        let secret = 0x0123_4567_89ab_cdefu128;
        let shares = shamir::split(secret, 3, 5, 1);
        assert_eq!(
            shamir::combine(&shares[..3]),
            Some(secret),
            "a threshold must recombine, or the negative below is vacuous"
        );
        assert_ne!(
            shamir::combine(&shares[..2]),
            Some(secret),
            "two shares reconstructed what three are supposed to"
        );
        let _ = good;
    }

    #[test]
    fn any_threshold_subset_produces_a_valid_credential() {
        let set = IssuerSet::new(3, 5, 1);

        // A fresh ledger per combination. Reusing one would reject the second credential as
        // a double spend, since a wallet seeded identically chooses the same serial, and
        // that rejection is correct behaviour rather than a failure of the subset.
        for combo in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let mut w = Wallet::new(9);
            let c = issue(&set, &mut w, &combo).unwrap();
            let mut led = SpendLedger::new();
            assert!(led.accept(&set, &c).is_ok(), "combo {combo:?} rejected");
        }
    }

    #[test]
    fn distinct_wallets_produce_distinct_credentials() {
        let set = IssuerSet::new(3, 5, 1);
        let mut led = SpendLedger::new();
        for seed in 0..5u64 {
            let mut w = Wallet::new(seed);
            let c = issue(&set, &mut w, &[0, 1, 2]).unwrap();
            assert!(led.accept(&set, &c).is_ok(), "seed {seed} collided");
        }
        assert_eq!(led.spent_count(), 5);
    }

    #[test]
    fn one_issuer_contributing_twice_does_not_reach_the_threshold() {
        let set = IssuerSet::new(3, 5, 1);
        let mut w = Wallet::new(9);
        let req = w.request(warrant(1, 1));
        let partials = vec![
            set.partial(0, &req),
            set.partial(0, &req),
            set.partial(1, &req),
        ];
        assert_eq!(
            w.assemble(&set, &partials),
            Err(ValueError::DuplicateIssuer(1))
        );
    }

    /// **The property this whole design exists for.** The issuers' view and the verifier's
    /// view have no field in common, so no amount of collusion between them links a spend to
    /// an acquisition.
    #[test]
    fn the_issuance_transcript_and_the_spend_transcript_share_nothing() {
        let set = IssuerSet::new(2, 3, 1);
        let mut w = Wallet::new(9);

        let req = w.request(warrant(1, 1));
        let partials = vec![set.partial(0, &req), set.partial(1, &req)];
        let cred = w.assemble(&set, &partials).unwrap();

        let mut led = SpendLedger::new();
        let rec = led.accept(&set, &cred).unwrap();

        // What the issuers saw, against what the verifier saw.
        assert_ne!(
            req.blinded, rec.serial,
            "the blinded commitment must not equal the serial"
        );
        // And the commitment is not derivable from the serial without the blinding, which
        // never left the wallet.
        let mut h = blake3::Hasher::new();
        h.update(b"karst.blind.v0");
        h.update(&rec.serial);
        h.update(&[0u8; 32]);
        assert_ne!(*h.finalize().as_bytes(), req.blinded);
    }

    #[test]
    fn every_credential_is_the_same_size_so_amount_leaks_nothing() {
        let set = IssuerSet::new(2, 3, 1);
        let mut led = SpendLedger::new();
        let mut sizes = BTreeSet::new();

        for seed in 0..8u64 {
            let mut w = Wallet::new(seed);
            let c = issue(&set, &mut w, &[0, 1]).unwrap();
            let rec = led.accept(&set, &c).unwrap();
            sizes.insert(rec.units);
            assert_eq!(std::mem::size_of_val(&c.serial), 32);
        }
        assert_eq!(sizes.len(), 1, "all credentials must carry one unit");
        assert_eq!(sizes.into_iter().next(), Some(UNIT));
    }

    #[test]
    fn a_serial_cannot_be_spent_twice_at_one_verifier() {
        let set = IssuerSet::new(2, 3, 1);
        let mut w = Wallet::new(9);
        let c = issue(&set, &mut w, &[0, 1]).unwrap();

        let mut led = SpendLedger::new();
        assert!(led.accept(&set, &c).is_ok());
        assert_eq!(led.accept(&set, &c), Err(ValueError::AlreadySpent));
        assert_eq!(led.spent_count(), 1);
    }

    /// The limit, tested so it cannot be quietly forgotten.
    #[test]
    fn two_disconnected_verifiers_both_accept_the_same_credential() {
        let set = IssuerSet::new(2, 3, 1);
        let mut w = Wallet::new(9);
        let c = issue(&set, &mut w, &[0, 1]).unwrap();

        let mut a = SpendLedger::new();
        let mut b = SpendLedger::new();
        assert!(a.accept(&set, &c).is_ok());
        assert!(
            b.accept(&set, &c).is_ok(),
            "offline verification cannot see another verifier's ledger"
        );
    }

    #[test]
    fn a_forged_credential_does_not_verify() {
        let set = IssuerSet::new(2, 3, 1);
        let mut w = Wallet::new(9);
        let mut c = issue(&set, &mut w, &[0, 1]).unwrap();
        c.serial[0] ^= 0xff;

        let mut led = SpendLedger::new();
        assert_eq!(led.accept(&set, &c), Err(ValueError::Invalid));
    }

    #[test]
    fn a_credential_from_another_issuer_set_does_not_verify() {
        let mine = IssuerSet::new(2, 3, 1);
        let theirs = IssuerSet::new(2, 3, 2);
        let mut w = Wallet::new(9);
        let c = issue(&theirs, &mut w, &[0, 1]).unwrap();

        let mut led = SpendLedger::new();
        assert_eq!(led.accept(&mine, &c), Err(ValueError::Invalid));
    }

    #[test]
    fn credentials_cannot_be_minted_from_nothing() {
        let mut earn = EarnLedger::new();
        let relay = [7u8; 32];

        assert_eq!(
            earn.draw(&EarnedWarrant { relay, units: 5, epoch: 1 }),
            Err(ValueError::Unearned { requested: 5, earned: 0 })
        );

        earn.credit(relay, 10);
        assert!(earn.draw(&EarnedWarrant { relay, units: 6, epoch: 1 }).is_ok());
        assert_eq!(earn.balance(&relay), 4);

        assert_eq!(
            earn.draw(&EarnedWarrant { relay, units: 5, epoch: 1 }),
            Err(ValueError::Unearned { requested: 5, earned: 4 })
        );
    }

    /// The loop that removes the bank: capacity is earned by providing capacity.
    #[test]
    fn service_converts_to_credentials_and_credentials_convert_to_service() {
        let set = IssuerSet::new(2, 3, 1);
        let mut earn = EarnLedger::new();
        let mut spend = SpendLedger::new();
        let relay = [3u8; 32];

        earn.credit(relay, 3);

        let mut w = Wallet::new(11);
        let mut minted = 0;
        for _ in 0..3 {
            let req = w.request(EarnedWarrant { relay, units: 1, epoch: 1 });
            earn.draw(&req.warrant).unwrap();
            let partials = vec![set.partial(0, &req), set.partial(1, &req)];
            let c = w.assemble(&set, &partials).unwrap();
            spend.accept(&set, &c).unwrap();
            minted += 1;
        }

        assert_eq!(minted, 3);
        assert_eq!(spend.spent_count(), 3);
        assert_eq!(earn.balance(&relay), 0, "no value created from nothing");
        // No bank was involved at any point in that loop.
    }
}
