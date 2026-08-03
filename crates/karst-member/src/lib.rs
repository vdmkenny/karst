//! L5 Membership.
//!
//!
//! # What this does not do, first, because the literature is unambiguous
//!
//! It does **not** provide membership concealment in the sense Vasserman, Jansen, Tyra, Hopper
//! and Kim define (*Membership-Concealing Overlay Networks*, CCS 2009). Two reasons, and both
//! are theirs rather than mine.
//!
//! Their construction requires a **Membership and Invitation Authority**: a trusted central
//! party that issues keys, handles every invitation, and enforces a global degree constraint.
//! This design cannot have one, so it cannot have their result.
//!
//! And they prove the ceiling anyway. No overlay permitting peer communication can hold
//! exposure below `Theta(L + G)` in the adversary's monitoring and corruption budget, because
//! some node has to deliver messages to each identity the adversary controls or watches.
//! **Linear exposure is the floor**, not a weakness of any particular scheme.
//!
//! # What the deployed attempt achieved
//!
//! Tor bridges are membership concealment in production, and the record should be read before
//! anyone designs another one. China broke the HTTPS distribution channel in September 2009 and
//! the Gmail one in March 2010, in Dingledine's words "by just pretending to be enough
//! legitimate users from enough different subnets". By 2011 the pools in distribution were 176
//! bridges by HTTPS and 201 by mail, against a state.
//!
//! Ling, Luo, Yu, Yang and Fu (INFOCOM 2012) then showed distribution was not the weak part.
//! One malicious middle relay, run for fourteen days, enumerated 2,369 bridges: as many as a
//! month of enumeration across 500 PlanetLab nodes and 2,000 mail accounts. Tor's structural
//! answer, proposal 188 on bridge guards, is still marked Reserve, shelved in 2020 on the
//! grounds that the attack was not observed in use rather than that it had been fixed.
//!
//! # And social-graph admission is worse than nothing
//!
//! The SybilGuard and SybilLimit family assumes sybils form a tightly knit region joined to the
//! honest graph by a sparse cut. Yang and colleagues instrumented a live network with hundreds
//! of thousands of real sybils and found they do not: they integrate like ordinary users, and
//! most sybil-to-sybil links are accidental rather than intended. That is a measurement
//! refutation rather than a modelling quibble.
//!
//! Alvisi and colleagues then measured those schemes under the real attack shape, scoring the
//! probability that a random honest node ranks above a random sybil, where 0.5 is a coin flip:
//! SybilLimit 0.45, SybilGuard 0.44, Gatekeeper 0.49, and one variant at 0.34. **Four of five
//! perform at or below chance.** Mohaisen, Yun and Kim had already shown the mixing-time
//! assumption fails on real graphs, and worse, that the graphs with genuine trust semantics are
//! the slow-mixing ones. So there is no admission decision to make here, and none is made.
//!
//! # What is left, and it is not nothing
//!
//! Two things this design can honestly claim.
//!
//! **There is no roll.** No registry, no directory of members, no list anyone holds. That is
//! weaker than concealment: an adversary who watches enough of the network still learns who is
//! on it, at the linear rate above. What it removes is the single object whose seizure hands
//! over everyone at once.
//!
//! **Introduction is a relationship rather than an admission.** Two parties who already share a
//! contact can discover that fact without either revealing their contacts, and act on it. That
//! is balanced two-party private set intersection, which unlike almost everything else in this
//! area is cheap: at a thousand contacts each side it is tens of kilobytes and milliseconds.
//!
//! It is worth knowing that nobody ships it. A survey of eleven messengers found five uploading
//! contacts in plaintext, five uploading trivially reversible hashes, one using trusted
//! hardware, and none using PSI. Signal evaluated it and chose an enclave, judging the
//! non-collusion assumption behind the fast multi-server designs unrealistic. But their problem
//! is a phone against a billion-row registry, which is the **unbalanced** case. Two peers
//! comparing address books is the balanced case, and the cost difference is enormous.
//!
//! # A responder proves it used its own key
//!
//! The protocol is a **verifiable** oblivious pseudorandom function, RFC 9497, ciphersuite
//! OPRF(ristretto255, SHA-512), from the `voprf` crate. An initiator blinds its contacts, a
//! responder evaluates them under a key it has published, and returns the evaluations with a
//! proof that binds every one of them to that key. The responder also sends its own contacts
//! under the same key, and the initiator intersects.
//!
//! Two properties follow, and the second is the one that took a rewrite to get.
//!
//! **A responder cannot answer under a key it did not publish.** The proof is checked before
//! any evaluation is believed, so an evaluation under a second key is refused rather than
//! silently producing a wrong answer.
//!
//! **A responder holding nothing cannot make everything look shared.** RFC 9497 binds the
//! input into the output, so producing the tag for a contact requires knowing that contact,
//! and a responder only ever sees it blinded. The forgery is unavailable rather than merely
//! detectable.
//!
//! The earlier version gave both sides output in a **single exchange**, which is not what
//! Meadows specifies: the paper's protocol is one-sided, and the initiator computes its
//! comparison set locally and never transmits it. Collapsing two instances into one required
//! transmitting that set to the party it exists to constrain, so a responder with no shared
//! contact could return it and be believed about every contact the initiator held. That is
//! the introduction credential forged from nothing.
//!
//! So this runs in **two directions rather than one**, each an independent instance with its
//! own key and proof. It costs a second round, and it is the reason an answer can be believed.
//!
//! # The abuse that PSI cannot prevent
//!
//! A party who submits a set of one learns whether the other holds that one element. This is
//! inherent: PSI computes an intersection, and an intersection with a singleton is a membership
//! query. Padding hides set *size*, not this. So an introduction protocol built on PSI is a
//! membership oracle for anyone willing to run it repeatedly, and the only real defences are
//! rate limiting and refusing to run it with strangers, neither of which is cryptography.

use karst_id::Address;
use voprf::{Ristretto255, VoprfClient, VoprfServer};

/// The RFC 9497 ciphersuite this uses: OPRF(ristretto255, SHA-512), verifiable mode.
type Suite = Ristretto255;

/// A PRF output. Two parties compute the same one for the same contact under one party's key.
pub type Tag = [u8; 64];

/// The number of entries every exchange is padded to.
///
/// Set size is otherwise visible, and set size is informative: a party with four contacts and a
/// party with four hundred are different kinds of participant. Padding costs bandwidth linear
/// in the bucket and buys that one fact.
pub const BUCKET: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiError {
    /// The answer did not carry a valid proof under the responder's published key, so the
    /// responder did not use the key it committed to.
    Unproven,
    /// The answer was not shaped like an answer to the question asked.
    Malformed,
}

impl core::fmt::Display for PsiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PsiError::Unproven => write!(f, "the responder did not prove it used its own key"),
            PsiError::Malformed => write!(f, "malformed answer"),
        }
    }
}

impl std::error::Error for PsiError {}

/// Filler inputs, so a set is padded to the bucket without the padding being recognisable.
///
/// Derived from a per-exchange secret. A fixed pad would be a constant every observer learns
/// once and then subtracts.
fn filler(secret: &[u8; 32], i: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.member.v2.filler");
    h.update(secret);
    h.update(&(i as u64).to_le_bytes());
    h.finalize().as_bytes().to_vec()
}

/// What a contact is called when it goes into the function.
fn input_of(a: &Address) -> Vec<u8> {
    let mut v = b"karst.member.v2.contact".to_vec();
    v.extend_from_slice(a.as_bytes());
    v
}

/// One side of an intersection.
///
/// A party is both a responder, holding an OPRF key others evaluate under, and an initiator,
/// asking under someone else's. The two roles use the same contact list and are otherwise
/// independent.
pub struct Party {
    server: VoprfServer<Suite>,
    pad: [u8; 32],
    contacts: Vec<Address>,
}

/// What an initiator sends: one blinded element per bucket slot.
pub struct Ask {
    pub blinded: Vec<voprf::BlindedElement<Suite>>,
    states: Vec<VoprfClient<Suite>>,
    /// The inputs, in bucket order. Filler slots hold no address.
    inputs: Vec<(Vec<u8>, Option<Address>)>,
}

/// What a responder sends back.
///
/// The proof is the whole difference from the earlier protocol. It binds every evaluation to
/// the key the responder published, so the responder cannot answer with one key and describe
/// its own set under another.
pub struct Answer {
    pub evaluated: Vec<voprf::EvaluationElement<Suite>>,
    pub proof: voprf::Proof<Suite>,
    /// The responder's own contacts under its own key, shuffled and padded.
    pub theirs: Vec<Tag>,
}

impl Party {
    pub fn new(contacts: &[Address]) -> Self {
        use rand::RngCore;
        let mut pad = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pad);
        Party {
            server: VoprfServer::<Suite>::new(&mut rand::rngs::OsRng)
                .expect("ristretto255 key generation"),
            pad,
            contacts: contacts.to_vec(),
        }
    }

    /// Deterministic construction, for tests that need a fixed transcript.
    pub fn from_seed(contacts: &[Address], seed: [u8; 32]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"karst.member.v2.party");
        h.update(&seed);
        let mut wide = [0u8; 64];
        h.finalize_xof().fill(&mut wide);
        let mut pad = [0u8; 32];
        pad.copy_from_slice(&wide[..32]);
        Party {
            server: VoprfServer::<Suite>::new_from_seed(&wide, b"karst.member.v2")
                .expect("ristretto255 key derivation"),
            pad,
            contacts: contacts.to_vec(),
        }
    }

    /// How many contacts this party actually holds. Never sent.
    pub fn held(&self) -> usize {
        self.contacts.len()
    }

    /// The key others evaluate under. Published, and the thing a proof is checked against.
    pub fn public_key(&self) -> <<Suite as voprf::CipherSuite>::Group as voprf::Group>::Elem {
        self.server.get_public_key()
    }

    /// Ask another party to evaluate this party's contacts under its key.
    pub fn ask(&self) -> Ask {
        let mut inputs: Vec<(Vec<u8>, Option<Address>)> = self
            .contacts
            .iter()
            .map(|a| (input_of(a), Some(*a)))
            .collect();
        for i in inputs.len()..BUCKET {
            inputs.push((filler(&self.pad, i), None));
        }
        // Ordered by the input bytes, so position is a function of the contact rather than of
        // insertion order. Sending them as stored would say which contacts are oldest.
        inputs.sort_by(|a, b| a.0.cmp(&b.0));

        let mut blinded = Vec::with_capacity(inputs.len());
        let mut states = Vec::with_capacity(inputs.len());
        for (bytes, _) in &inputs {
            let r = VoprfClient::<Suite>::blind(bytes, &mut rand::rngs::OsRng)
                .expect("a non-empty input blinds");
            blinded.push(r.message);
            states.push(r.state);
        }
        Ask {
            blinded,
            states,
            inputs,
        }
    }

    /// Evaluate an initiator's blinded contacts, prove it, and describe this party's own set.
    ///
    /// The proof covers every evaluation at once and is checked against `public_key`.
    pub fn answer(&self, ask: &[voprf::BlindedElement<Suite>]) -> Result<Answer, PsiError> {
        let batch = self
            .server
            .batch_blind_evaluate(&mut rand::rngs::OsRng, &ask.to_vec())
            .map_err(|_| PsiError::Malformed)?;

        let mut theirs: Vec<Tag> = self
            .contacts
            .iter()
            .map(|a| {
                let out = self
                    .server
                    .evaluate(&input_of(a))
                    .expect("a non-empty input evaluates");
                let mut t = [0u8; 64];
                t.copy_from_slice(&out);
                t
            })
            .collect();
        // Pad to the bucket with values indistinguishable from outputs, and shuffle, because
        // the order this party stores its own contacts in is not the initiator's business.
        for i in theirs.len()..BUCKET {
            let mut t = [0u8; 64];
            let mut h = blake3::Hasher::new();
            h.update(b"karst.member.v2.own-filler");
            h.update(&self.pad);
            h.update(&(i as u64).to_le_bytes());
            h.finalize_xof().fill(&mut t);
            theirs.push(t);
        }
        theirs.sort_unstable();

        Ok(Answer {
            evaluated: batch.messages,
            proof: batch.proof,
            theirs,
        })
    }
}

impl Ask {
    /// Which of this party's contacts the responder also holds.
    ///
    /// **The proof is verified before anything is believed.** Without it a responder could
    /// evaluate under one key and describe its own set under another, which made every contact
    /// appear shared to a responder holding none.
    ///
    /// After verification the comparison is a plain set membership on PRF outputs, and the
    /// forgery is not merely detected but unavailable: RFC 9497 binds the input into the
    /// output, so producing the tag for a contact requires knowing that contact, and the
    /// responder only ever saw it blinded.
    pub fn learn(
        &self,
        answer: &Answer,
        responder_key: <<Suite as voprf::CipherSuite>::Group as voprf::Group>::Elem,
    ) -> Result<Vec<Address>, PsiError> {
        if answer.evaluated.len() != self.blinded.len() {
            return Err(PsiError::Malformed);
        }
        let raw_inputs: Vec<&[u8]> = self.inputs.iter().map(|(b, _)| b.as_slice()).collect();
        let outputs = VoprfClient::<Suite>::batch_finalize(
            &raw_inputs,
            &self.states,
            &answer.evaluated,
            &answer.proof,
            responder_key,
        )
        .map_err(|_| PsiError::Unproven)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PsiError::Unproven)?;

        let theirs: std::collections::BTreeSet<Tag> = answer.theirs.iter().copied().collect();
        Ok(self
            .inputs
            .iter()
            .zip(outputs)
            .filter_map(|((_, addr), out)| {
                let a = (*addr)?;
                let mut t = [0u8; 64];
                t.copy_from_slice(&out);
                theirs.contains(&t).then_some(a)
            })
            .collect())
    }
}

/// Run the exchange in both directions and return what each side learns.
///
/// **Two runs, not one.** Meadows specifies one-sided output, and the earlier attempt to give
/// both sides output in a single exchange had to transmit the initiator's comparison set to
/// the party that set exists to constrain. Each direction here is an independent verifiable
/// OPRF with its own key and its own proof, so neither party's soundness rests on the other's
/// honesty. It costs a second round and it is the reason the answer can be believed.
pub fn exchange(a: &Party, b: &Party) -> (Vec<Address>, Vec<Address>) {
    let a_asks = a.ask();
    let from_b = b.answer(&a_asks.blinded).expect("well-formed ask");
    let a_sees = a_asks
        .learn(&from_b, b.server.get_public_key())
        .expect("an honest responder proves");

    let b_asks = b.ask();
    let from_a = a.answer(&b_asks.blinded).expect("well-formed ask");
    let b_sees = b_asks
        .learn(&from_a, a.server.get_public_key())
        .expect("an honest responder proves");

    (a_sees, b_sees)
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_id::Identity;

    fn addr(n: u32) -> Address {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        Identity::from_seed(seed).address()
    }

    fn set(range: std::ops::Range<u32>) -> Vec<Address> {
        range.map(addr).collect()
    }

    /// Two parties learn exactly what they share, and nothing else.
    #[test]
    fn an_exchange_yields_the_intersection() {
        let a = Party::new(&set(0..40));
        let b = Party::new(&set(30..70));
        let (a_sees, b_sees) = exchange(&a, &b);

        let expected: std::collections::BTreeSet<Address> = set(30..40).into_iter().collect();
        assert_eq!(
            a_sees
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
        assert_eq!(
            b_sees
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
    }

    /// Disjoint sets reveal nothing at all.
    #[test]
    fn disjoint_contacts_yield_nothing() {
        let a = Party::new(&set(0..50));
        let b = Party::new(&set(100..150));
        let (x, y) = exchange(&a, &b);
        assert!(x.is_empty());
        assert!(y.is_empty());
    }

    /// The wire form is the same size whatever a party holds.
    ///
    /// Set size is informative on its own: a party with four contacts and a party with four
    /// hundred are different kinds of participant, and one of them is far easier to identify.
    #[test]
    fn an_ask_is_the_same_size_whatever_is_held() {
        for n in [0usize, 1, 7, 200] {
            let cs: Vec<Address> = (0..n as u32).map(addr).collect();
            assert_eq!(Party::new(&cs).ask().blinded.len(), BUCKET, "n = {n}");
        }
    }

    #[test]
    fn the_same_contacts_produce_different_wire_values_each_time() {
        let cs: Vec<Address> = (0..5).map(addr).collect();
        let p = Party::new(&cs);
        let one = p.ask();
        let two = p.ask();
        let ser = |a: &Ask| -> Vec<Vec<u8>> {
            a.blinded.iter().map(|b| b.serialize().to_vec()).collect()
        };
        assert_ne!(ser(&one), ser(&two), "blinding must be fresh per exchange");
    }

    /// A responder holding nothing must not be able to make everything look shared.
    ///
    /// This is #147. The earlier protocol gave both sides output in one exchange, which meant
    /// transmitting the initiator's comparison set to the responder, and a responder could
    /// simply echo it: every contact appeared shared to a party holding none, which forges the
    /// introduction credential from nothing.
    #[test]
    fn a_responder_holding_nothing_cannot_forge_a_shared_contact() {
        let mine: Vec<Address> = (0..8).map(addr).collect();
        let me = Party::new(&mine);
        let liar = Party::new(&[]);

        let ask = me.ask();
        let mut answer = liar.answer(&ask.blinded).unwrap();

        // The liar's best move is to claim its own set is whatever it just evaluated. It
        // cannot: RFC 9497 binds the input into the output, and the liar never saw the inputs.
        answer.theirs = answer
            .evaluated
            .iter()
            .map(|e| {
                let mut t = [0u8; 64];
                let s = e.serialize();
                t[..s.len().min(64)].copy_from_slice(&s[..s.len().min(64)]);
                t
            })
            .collect();
        answer.theirs.sort_unstable();

        let seen = ask.learn(&answer, liar.public_key()).unwrap();
        assert!(
            seen.is_empty(),
            "a responder with no contacts forged {seen:?}"
        );
    }

    /// A responder that answers under a key it did not publish is refused, not believed.
    #[test]
    fn an_answer_under_the_wrong_key_does_not_verify() {
        let mine: Vec<Address> = (0..4).map(addr).collect();
        let me = Party::new(&mine);
        let them = Party::new(&mine);
        let other = Party::new(&mine);

        let ask = me.ask();
        let answer = them.answer(&ask.blinded).unwrap();

        assert_eq!(
            ask.learn(&answer, other.public_key()),
            Err(PsiError::Unproven),
            "an evaluation was accepted against a key that did not produce it"
        );
        // And against the right key it works, so the negative above is not vacuous.
        assert_eq!(ask.learn(&answer, them.public_key()).unwrap().len(), 4);
    }

    /// A tampered evaluation is refused by the proof rather than producing a wrong answer.
    #[test]
    fn a_tampered_evaluation_is_refused() {
        let mine: Vec<Address> = (0..4).map(addr).collect();
        let me = Party::new(&mine);
        let them = Party::new(&mine);

        let ask = me.ask();
        let mut answer = them.answer(&ask.blinded).unwrap();
        answer.evaluated.swap(0, 1);

        assert_eq!(
            ask.learn(&answer, them.public_key()),
            Err(PsiError::Unproven)
        );
    }

    /// An answer of the wrong shape is refused rather than half-processed.
    #[test]
    fn a_truncated_answer_is_refused() {
        let mine: Vec<Address> = (0..4).map(addr).collect();
        let me = Party::new(&mine);
        let them = Party::new(&mine);
        let ask = me.ask();
        let mut answer = them.answer(&ask.blinded).unwrap();
        answer.evaluated.truncate(BUCKET - 1);
        assert_eq!(
            ask.learn(&answer, them.public_key()),
            Err(PsiError::Malformed)
        );
    }

    #[test]
    fn a_set_larger_than_the_bucket_is_not_silently_truncated() {
        let cs: Vec<Address> = (0..BUCKET as u32 + 10).map(addr).collect();
        let p = Party::new(&cs);
        assert!(
            p.ask().blinded.len() >= p.held(),
            "contacts were dropped to fit the bucket"
        );
    }

    /// A party who submits a set of one learns whether the other holds that one element.
    ///
    /// Inherent to PSI: an intersection with a singleton is a membership query, and padding
    /// hides set size rather than this. Recorded as a test so it is a known property rather
    /// than a discovery.
    #[test]
    fn a_singleton_probe_learns_membership_and_nothing_stops_it() {
        let target = addr(42);
        let holder = Party::new(&[target, addr(1), addr(2)]);
        let prober = Party::new(&[target]);

        let ask = prober.ask();
        let answer = holder.answer(&ask.blinded).unwrap();
        assert_eq!(
            ask.learn(&answer, holder.public_key()).unwrap(),
            vec![target]
        );
    }

    #[test]
    fn both_sides_agree_on_what_is_shared() {
        for n in [0u32, 1, 7, 40] {
            let a = Party::new(&set(0..50));
            // Saturating, because 50 - n underflows for large n and a u32 underflow panics in
            // debug while wrapping silently in release. A test that only fails in one profile
            // is a test that gets discovered by somebody else.
            let lo = 50u32.saturating_sub(n);
            let b = Party::new(&set(lo..50 + n.max(1)));
            let (x, y) = exchange(&a, &b);
            let xs: std::collections::BTreeSet<_> = x.into_iter().collect();
            let ys: std::collections::BTreeSet<_> = y.into_iter().collect();
            assert_eq!(xs, ys, "the two sides disagreed at n={n}");
        }
    }

    /// A party must not learn a contact it does not hold, even if the other side holds it.
    #[test]
    fn neither_side_learns_the_others_unshared_contacts() {
        let a = Party::new(&set(0..10));
        let b = Party::new(&set(5..30));
        let (a_sees, b_sees) = exchange(&a, &b);

        for got in a_sees.iter().chain(b_sees.iter()) {
            assert!(
                set(5..10).contains(got),
                "a party learned {got:?}, which is not in the intersection"
            );
        }
    }
}
