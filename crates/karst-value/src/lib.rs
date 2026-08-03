//! KARST L14: capacity credentials that are earned and spent without linking the two.
//!
//! # The credential is real; the threshold is not, and the wallet's randomness is not
//!
//! A credential is an RFC 9474 blind signature (`blind`, over `blind-rsa-signatures`). An
//! issuer signs a blinded serial it cannot read, a verifier checks the result against the
//! issuer's **public** key, and no verifier can mint. That is the property the layer needs and
//! it now holds.
//!
//! Two things here still fall short and are not fixed by that:
//!
//! - **Threshold issuance is not composed.** The `shamir` module carries the structure and the
//!   credential path does not use it, so an issuer set is one key. Plurality of issuer sets is
//!   what error 03 actually demands and it is satisfied, since anyone may run a set and there
//!   is no registry; threshold *within* a set, which protects one set against a compromised or
//!   compelled member, is absent. Recovering it needs Coconut over a pairing curve or
//!   threshold RSA. (#133)
//! - **Serials come from the system CSPRNG and everything else in this module does not.** The
//!   double-spend and earn ledgers are models, and `IssuerSet` is not a deployment artifact.
//!
//! What is worth reading here is the *structure*: which acts are separated, what each ledger
//! observes, and why double-spend attribution can be made to work without identifying honest
//! spenders.
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

use rand::Rng;

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

/// An issuer set.
///
/// `threshold` is retained because the earn side still speaks in those terms; it is **not**
/// enforced by the credential, because threshold issuance is not composed with the blind
/// signature that replaced the placeholder (#133). The `Issuer` type that held one Shamir
/// share of a reconstructable key is gone with it: that arrangement returned the share itself
/// to whoever asked, so one honest issuance handed over the master secret.
///
/// What error 03 demands is **plurality of issuer sets**, and that holds: anyone may run one,
/// many coexist, and there is no registry. Threshold *within* a set is a different property
/// and it is absent.
pub struct IssuerSet {
    pub threshold: usize,
    key: blind::IssuerKey,
}

impl IssuerSet {
    /// An issuer set. Generating a key takes a moment; do it once and keep it.
    ///
    /// `threshold` is retained in the type because the earn side still speaks in those terms,
    /// and it is **not** enforced by the credential: see the note on plurality below.
    pub fn new(threshold: usize, _count: usize) -> Result<Self, ValueError> {
        Ok(IssuerSet {
            threshold,
            key: blind::IssuerKey::generate(blind::ISSUER_BITS).map_err(|_| ValueError::Invalid)?,
        })
    }

    /// What a verifier needs, and all it needs.
    ///
    /// A verifier holds a public key and cannot mint. That is the difference from a symmetric
    /// tag, where verification and forgery are the same capability.
    pub fn public(&self) -> blind::IssuerPublic {
        self.key.public()
    }

    /// Sign a blinded request, learning nothing about the credential it becomes.
    ///
    /// The response is a function of the request. An issuance protocol whose response is a
    /// function of the issuer's *key* instead hands that key to the requester, which is what
    /// returning a Shamir share did.
    pub fn sign(&self, req: &IssuanceRequest) -> Result<blind::BlindSignature, ValueError> {
        self.key
            .sign_blinded(&req.blinded)
            .map_err(|_| ValueError::Invalid)
    }
}

/// What a holder sends to issuers.
///
/// Carries a **blinded** commitment and a warrant proving service was performed. It does not
/// carry the serial, and the serial is what a verifier later sees. That gap is the whole
/// design.
#[derive(Debug)]
pub struct IssuanceRequest {
    /// An RFC 9474 blind message. Carries no information about the serial inside it.
    pub blinded: blind::BlindedMessage,
    pub warrant: EarnedWarrant,
}

/// Proof that a relay carried traffic, which is how credentials enter circulation.
///
/// **Signed by whoever received the service**, and the signature is checked. This is the
/// acquisition side, and it is deliberately linkable: it says a relay did work, which is
/// public anyway.
///
/// The struct carried no authenticator while its documentation said it was signed, so
/// `EarnLedger::draw` accepted any warrant a caller constructed. An attacker forged warrants
/// naming any relay, drained the balance that relay had worked for, and minted credentials
/// against work it had not done. A comment describing a check nobody performs is worse than
/// no comment, because a reader who believes it stops looking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarnedWarrant {
    pub relay: [u8; 32],
    pub units: u64,
    pub epoch: u64,
    /// The served party's key, which is who attests that the work happened.
    pub served: [u8; 32],
    /// Makes two attestations for the same work distinct.
    ///
    /// Without it, a served party attesting twice for the same relay, units and epoch signs
    /// byte-identical warrants, and a ledger cannot tell an honest second attestation from a
    /// replay of the first.
    nonce: [u8; 16],
    signature: [u8; 64],
}

impl EarnedWarrant {
    /// What a served party signs to attest that a relay carried its traffic.
    fn signing_bytes(
        relay: &[u8; 32],
        units: u64,
        epoch: u64,
        served: &[u8; 32],
        nonce: &[u8; 16],
    ) -> Vec<u8> {
        let mut v = b"karst.value.v2.warrant".to_vec();
        v.extend_from_slice(relay);
        v.extend_from_slice(&units.to_le_bytes());
        v.extend_from_slice(&epoch.to_le_bytes());
        v.extend_from_slice(served);
        v.extend_from_slice(nonce);
        v
    }

    /// Attest that `relay` carried `units` for the signer, in `epoch`.
    pub fn attest(served: &karst_id::Identity, relay: [u8; 32], units: u64, epoch: u64) -> Self {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill(&mut nonce);
        let key = served.key_bytes();
        let sig = served
            .sign(&Self::signing_bytes(&relay, units, epoch, &key, &nonce))
            .to_bytes();
        EarnedWarrant {
            relay,
            units,
            epoch,
            served: key,
            nonce,
            signature: sig,
        }
    }

    /// Whether the named served party really signed this.
    pub fn verify(&self) -> Result<(), ValueError> {
        let peer = karst_id::Peer::from_key_bytes(&self.served).map_err(|_| ValueError::Invalid)?;
        peer.verify(
            &Self::signing_bytes(
                &self.relay,
                self.units,
                self.epoch,
                &self.served,
                &self.nonce,
            ),
            &karst_id::Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ValueError::Invalid)
    }
}

// ---------------------------------------------------------------- credential

/// A spendable unit of capacity.
///
/// Fixed size, fixed value, and carrying nothing that appears in the issuance transcript.
#[derive(Clone)]
pub struct Credential {
    /// Chosen by the holder, never shown to an issuer, revealed only when spent so that
    /// double spending can be caught.
    pub serial: [u8; 32],
    /// The issuer's signature over the serial, produced without the issuer seeing it.
    signature: blind::Signature,
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

/// A holder's wallet: serials it has chosen and the blinding it used.
pub struct Wallet {
    pending: Vec<([u8; 32], blind::Blinding)>,
}

impl Default for Wallet {
    fn default() -> Self {
        Wallet::new()
    }
}

impl Wallet {
    /// A wallet draws serials and blinding factors from the system CSPRNG.
    ///
    /// There is no seeded constructor. A wallet whose serials are a deterministic stream from
    /// a guessable seed is a wallet whose every future spend is predictable.
    pub fn new() -> Self {
        Wallet {
            pending: Vec::new(),
        }
    }

    /// Choose a serial, blind it, and ask for issuance against earned service.
    ///
    /// The issuer sees an RFC 9474 blind message. Recovering the serial from it is not a
    /// matter of not having the blinding factor: every serial is consistent with every blind
    /// message, so the issuer's view carries no information about which one it signed.
    pub fn request(
        &mut self,
        pk: &blind::IssuerPublic,
        warrant: EarnedWarrant,
    ) -> Result<IssuanceRequest, ValueError> {
        let mut serial = [0u8; 32];
        rand::thread_rng().fill(&mut serial);
        let (blinded, blinding) = blind::blind(pk, &serial).map_err(|_| ValueError::Invalid)?;
        self.pending.push((serial, blinding));
        Ok(IssuanceRequest { blinded, warrant })
    }

    /// Unblind the issuer's signature into a spendable credential.
    ///
    /// The issuer's work is checked here, against its public key, before the credential is
    /// carried away. A holder who found out at spending time would be identified at exactly
    /// the moment anonymity matters, so a malicious issuer fails at issuance instead.
    pub fn assemble(
        &mut self,
        pk: &blind::IssuerPublic,
        sig: &blind::BlindSignature,
    ) -> Result<Credential, ValueError> {
        let (serial, blinding) = self.pending.pop().ok_or(ValueError::Invalid)?;
        let signature =
            blind::unblind(pk, &serial, &blinding, sig).map_err(|_| ValueError::Invalid)?;
        Ok(Credential { serial, signature })
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

    /// Accept a credential, against the issuer's **public** key.
    ///
    /// A verifier that needed the issuing secret to check a credential could also mint one.
    pub fn accept(
        &mut self,
        pk: &blind::IssuerPublic,
        cred: &Credential,
    ) -> Result<SpendRecord, ValueError> {
        if pk.verify(&cred.serial, &cred.signature).is_err() {
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
    /// Warrants already drawn against, so one cannot be presented twice.
    spent: BTreeSet<[u8; 16]>,
    /// Warrants older than this are refused. `epoch` was stored and never read, so a warrant
    /// never expired and there was no replay window at all.
    horizon: u64,
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
        self.earned.get(relay).copied().unwrap_or(0) - self.drawn.get(relay).copied().unwrap_or(0)
    }

    /// Refuse warrants from before this epoch.
    pub fn advance_to(&mut self, epoch: u64) {
        self.horizon = self.horizon.max(epoch);
    }

    /// Authorise issuance against earned service.
    ///
    /// The signature is checked first, because everything after it is arithmetic on numbers
    /// the warrant supplies.
    pub fn draw(&mut self, warrant: &EarnedWarrant) -> Result<(), ValueError> {
        warrant.verify()?;
        if warrant.epoch < self.horizon {
            return Err(ValueError::Invalid);
        }
        if !self.spent.insert(warrant.nonce) {
            return Err(ValueError::AlreadySpent);
        }
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

    /// A forged warrant does not mint, and does not drain the relay it names.
    ///
    /// The struct carried no authenticator while its doc said it was signed, so `draw`
    /// accepted anything a caller constructed. An attacker named any relay, spent down the
    /// balance that relay had worked for, and minted against work it had not done.
    #[test]
    fn a_warrant_nobody_signed_does_not_draw() {
        let relay = [3u8; 32];
        let mut earn = EarnLedger::new();
        earn.credit(relay, 10);

        // An attacker can construct the public fields; it cannot produce the signature.
        let honest = EarnedWarrant::attest(&served(), relay, 4, 1);
        let mut forged = honest.clone();
        forged.units = 9;
        assert_eq!(earn.draw(&forged), Err(ValueError::Invalid));
        assert_eq!(earn.balance(&relay), 10, "a forgery moved the balance");

        // And a warrant naming a different served party than the one who signed.
        let mut impersonating = honest.clone();
        impersonating.served = karst_id::Identity::from_seed([9u8; 32]).key_bytes();
        assert_eq!(earn.draw(&impersonating), Err(ValueError::Invalid));

        // The honest one still works, so the negatives above are not vacuous.
        assert!(earn.draw(&honest).is_ok());
        assert_eq!(earn.balance(&relay), 6);
    }

    /// One attestation authorises one draw.
    #[test]
    fn a_warrant_cannot_be_presented_twice() {
        let relay = [4u8; 32];
        let mut earn = EarnLedger::new();
        earn.credit(relay, 10);

        let w = EarnedWarrant::attest(&served(), relay, 3, 1);
        assert!(earn.draw(&w).is_ok());
        assert_eq!(earn.draw(&w), Err(ValueError::AlreadySpent));
        assert_eq!(earn.balance(&relay), 7, "a replay drew twice");

        // Two honest attestations for identical work are distinct and both draw.
        let a = EarnedWarrant::attest(&served(), relay, 2, 1);
        let b = EarnedWarrant::attest(&served(), relay, 2, 1);
        assert_ne!(a, b, "identical work must not produce identical warrants");
        assert!(earn.draw(&a).is_ok());
        assert!(earn.draw(&b).is_ok());
    }

    /// A warrant from before the horizon is refused, so `epoch` is read rather than stored.
    #[test]
    fn a_stale_warrant_is_refused() {
        let relay = [5u8; 32];
        let mut earn = EarnLedger::new();
        earn.credit(relay, 10);
        earn.advance_to(7);

        assert_eq!(
            earn.draw(&EarnedWarrant::attest(&served(), relay, 1, 6)),
            Err(ValueError::Invalid)
        );
        assert!(earn
            .draw(&EarnedWarrant::attest(&served(), relay, 1, 7))
            .is_ok());
    }

    /// The party attesting that a relay carried its traffic.
    fn served() -> karst_id::Identity {
        karst_id::Identity::from_seed([77u8; 32])
    }

    fn warrant(relay: u8, units: u64) -> EarnedWarrant {
        EarnedWarrant::attest(
            &karst_id::Identity::from_seed([77u8; 32]),
            [relay; 32],
            units,
            1,
        )
    }

    /// One issuer set, generated once. RSA key generation is slow.
    fn set() -> &'static IssuerSet {
        use std::sync::OnceLock;
        static S: OnceLock<IssuerSet> = OnceLock::new();
        S.get_or_init(|| IssuerSet::new(1, 1).expect("issuer set"))
    }

    fn issue(set: &IssuerSet, w: &mut Wallet) -> Result<Credential, ValueError> {
        let pk = set.public();
        let req = w.request(&pk, warrant(1, 1))?;
        let sig = set.sign(&req)?;
        w.assemble(&pk, &sig)
    }

    /// A verifier holds a public key and cannot mint with it.
    ///
    /// The credential used to be a 61-bit symmetric tag recomputed from the issuing secret, so
    /// every verifier held everything needed to forge, and the key itself fell to ~2^61 offline
    /// hashes against one observed credential. Verification against a public key is the whole
    /// difference between a credential and a shared password.
    #[test]
    fn a_verifier_can_check_a_credential_and_cannot_mint_one() {
        let set = set();
        let mut w = Wallet::new();
        let cred = issue(set, &mut w).expect("issuance");

        let pk = set.public();
        let mut ledger = SpendLedger::new();
        assert!(ledger.accept(&pk, &cred).is_ok());

        // Everything a verifier holds is public, and a different issuer's key does not accept
        // this credential, so holding one verifier's state mints nothing.
        let other = IssuerSet::new(1, 1).unwrap();
        let mut l2 = SpendLedger::new();
        assert_eq!(l2.accept(&other.public(), &cred), Err(ValueError::Invalid));
    }

    /// The issuance transcript and the spend transcript share no field.
    #[test]
    fn issuance_and_spending_share_nothing() {
        let set = set();
        let pk = set.public();
        let mut w = Wallet::new();
        let req = w.request(&pk, warrant(1, 1)).unwrap();
        let seen_by_issuer = req.blinded.to_bytes();

        let sig = set.sign(&req).unwrap();
        let cred = w.assemble(&pk, &sig).unwrap();

        assert!(
            !seen_by_issuer.windows(32).any(|win| win == cred.serial),
            "the serial appeared in what the issuer saw"
        );
    }

    #[test]
    fn distinct_wallets_produce_distinct_credentials() {
        let set = set();
        let pk = set.public();
        let mut led = SpendLedger::new();
        for i in 0..3u32 {
            let mut w = Wallet::new();
            let c = issue(set, &mut w).unwrap();
            assert!(led.accept(&pk, &c).is_ok(), "credential {i} collided");
        }
        assert_eq!(led.spent_count(), 3);
    }

    /// Two wallets asking for the same thing present different values to the issuer.
    ///
    /// This is the testable shadow of unlinkability, not unlinkability itself. That property
    /// rests on the blind signature construction and on nothing observable from here, and a
    /// test that appeared to establish it would be worse than none.
    #[test]
    fn the_commitment_is_not_a_function_of_the_warrant() {
        let set = set();
        let pk = set.public();
        let same = warrant(1, 1);

        let mut blinded = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let mut w = Wallet::new();
            let req = w.request(&pk, same.clone()).unwrap();
            assert!(
                blinded.insert(req.blinded.to_bytes()),
                "two requests for the same warrant produced the same commitment"
            );
        }
    }

    #[test]
    fn every_credential_is_the_same_size_so_amount_leaks_nothing() {
        let set = set();
        let pk = set.public();
        let mut led = SpendLedger::new();
        let mut sizes = BTreeSet::new();

        for _ in 0..8u64 {
            let mut w = Wallet::new();
            let c = issue(set, &mut w).unwrap();
            let rec = led.accept(&pk, &c).unwrap();
            sizes.insert(rec.units);
            assert_eq!(std::mem::size_of_val(&c.serial), 32);
        }
        assert_eq!(sizes.len(), 1, "all credentials must carry one unit");
        assert_eq!(sizes.into_iter().next(), Some(UNIT));
    }

    #[test]
    fn a_serial_cannot_be_spent_twice_at_one_verifier() {
        let set = set();
        let pk = set.public();
        let mut w = Wallet::new();
        let c = issue(set, &mut w).unwrap();

        let mut led = SpendLedger::new();
        assert!(led.accept(&pk, &c).is_ok());
        assert_eq!(led.accept(&pk, &c), Err(ValueError::AlreadySpent));
        assert_eq!(led.spent_count(), 1);
    }

    /// The limit, tested so it cannot be quietly forgotten.
    #[test]
    fn two_disconnected_verifiers_both_accept_the_same_credential() {
        let set = set();
        let pk = set.public();
        let mut w = Wallet::new();
        let c = issue(set, &mut w).unwrap();

        let mut a = SpendLedger::new();
        let mut b = SpendLedger::new();
        assert!(a.accept(&pk, &c).is_ok());
        assert!(
            b.accept(&pk, &c).is_ok(),
            "offline verification cannot see another verifier's ledger"
        );
    }

    #[test]
    fn a_forged_credential_does_not_verify() {
        let set = set();
        let pk = set.public();
        let mut w = Wallet::new();
        let mut c = issue(set, &mut w).unwrap();
        c.serial[0] ^= 0xff;

        let mut led = SpendLedger::new();
        assert_eq!(led.accept(&pk, &c), Err(ValueError::Invalid));
    }

    #[test]
    fn a_credential_from_another_issuer_set_does_not_verify() {
        let mine = set();
        let theirs = IssuerSet::new(1, 1).unwrap();
        let mut w = Wallet::new();
        let c = issue(&theirs, &mut w).unwrap();

        let mut led = SpendLedger::new();
        assert_eq!(led.accept(&mine.public(), &c), Err(ValueError::Invalid));
    }

    #[test]
    fn credentials_cannot_be_minted_from_nothing() {
        let mut earn = EarnLedger::new();
        let relay = [7u8; 32];

        assert_eq!(
            earn.draw(&EarnedWarrant::attest(&served(), relay, 5, 1)),
            Err(ValueError::Unearned {
                requested: 5,
                earned: 0
            })
        );

        earn.credit(relay, 10);
        assert!(earn
            .draw(&EarnedWarrant::attest(&served(), relay, 6, 1))
            .is_ok());
        assert_eq!(earn.balance(&relay), 4);

        assert_eq!(
            earn.draw(&EarnedWarrant::attest(&served(), relay, 5, 1)),
            Err(ValueError::Unearned {
                requested: 5,
                earned: 4
            })
        );
    }

    /// The loop that removes the bank: capacity is earned by providing capacity.
    #[test]
    fn service_converts_to_credentials_and_credentials_convert_to_service() {
        let set = set();
        let pk = set.public();
        let mut earn = EarnLedger::new();
        let mut spend = SpendLedger::new();
        let relay = [3u8; 32];

        earn.credit(relay, 3);

        let mut w = Wallet::new();
        let mut minted = 0;
        for _ in 0..3 {
            let req = w
                .request(&pk, EarnedWarrant::attest(&served(), relay, 1, 1))
                .unwrap();
            earn.draw(&req.warrant).unwrap();
            let sig = set.sign(&req).unwrap();
            let c = w.assemble(&pk, &sig).unwrap();
            spend.accept(&pk, &c).unwrap();
            minted += 1;
        }

        assert_eq!(minted, 3);
        assert_eq!(spend.spent_count(), 3);
        assert_eq!(earn.balance(&relay), 0, "no value created from nothing");
        // No bank was involved at any point in that loop.
    }
}
