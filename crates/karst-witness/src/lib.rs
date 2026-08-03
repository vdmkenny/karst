//! L8 Witness.
//!
//! A publisher signing how much they have published (L15's census) catches somebody between
//! them and a reader dropping entries. It does not catch the publisher, or a colluding set of
//! replicas, showing **one reader one consistent history and another reader a different one**.
//! Both readers see a signed, current, internally consistent view, and neither has anything to
//! compare against.
//!
//! Comparing across replicas does not help, because a jointly stale set agrees with itself.
//! Comparing across readers would help and requires readers to talk to each other, which is
//! where Certificate Transparency spent a decade: its gossip specification expired without
//! becoming an RFC, adoption of the feedback endpoints reached 0.015% of domains, and what
//! shipped instead was sampled reporting to a party that also operates logs.
//!
//! The direction the field moved to is **witness cosigning** (Syta, Tamas, Visher, Wolinsky,
//! Jovanovic, Gasser, Gailly, Khoffi, Ford, *Keeping Authorities Honest or Bust with
//! Decentralized Witness Cosigning*, IEEE S&P 2016). A witness countersigns a checkpoint only
//! if it extends what that witness has already seen. Producing a split view then requires
//! corrupting witnesses rather than fooling a reader.
//!
//! # A witness can refuse and cannot lie
//!
//! It never originates a statement. It countersigns a publisher's own signed checkpoint or
//! declines, so adding witnesses adds parties who can **withhold** and none who can
//! **substitute** — the same shape as adding replicas, and the reason both are cheap to add.
//!
//! What a witness can do is sign two conflicting checkpoints at one sequence. That is not
//! deniable: the two signatures are portable evidence, verifiable by anyone, naming the
//! witness. A witness cannot equivocate quietly, only expensively.
//!
//! # Witness sets belong to readers
//!
//! A single global witness set is exactly the privileged set L16 exists to prevent, and a
//! captured one captures everything at once. So a reader chooses their own witnesses and their
//! own threshold, as they already choose trust weights at L15 and replicas at L7. Two readers
//! who disagree about whom to believe get different answers, which is the same cost as there
//! being no global index and buys the same thing.

use std::collections::BTreeMap;

use karst_id::{Address, Identity, Signature};
use karst_object::{Cid, Dec, Enc, Object, ObjectError};

pub const CHECKPOINT_KIND: &str = "karst.witness.checkpoint.v1";

/// What a publisher asks witnesses to countersign.
///
/// Deliberately tiny: a witness should be able to check it without holding the content, or
/// witnessing would cost as much as replicating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub publisher: Address,
    /// Monotonic per publisher. A witness refuses anything not strictly greater.
    pub sequence: u64,
    /// Commitment to the publisher's state at this sequence.
    pub digest: Cid,
    /// Hash of the checkpoint this one continues, or `None` for the first.
    ///
    /// Without this, "extends what the witness has already seen" degenerates into "the number
    /// went up", and a publisher keeping two histories on disjoint sequence numbers gets both
    /// countersigned by every honest witness. Neither is refused, and the pair is not even
    /// evidence, because equivocation is defined at a shared sequence. The split view the
    /// whole layer exists to prevent survives untouched.
    pub prev: Option<Cid>,
}

impl Checkpoint {
    /// The bytes a witness signs.
    ///
    /// Includes the publisher, so a countersignature for one publisher cannot be replayed as a
    /// countersignature for another.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.str("karst.witness.checkpoint.v1")
            .addr(&self.publisher)
            .u64(self.sequence)
            .cid(&self.digest)
            .opt_cid(self.prev.as_ref());
        e.finish()
    }

    /// This checkpoint's own identity, which the next one links back to.
    pub fn id(&self) -> Cid {
        Cid::of(&self.signing_bytes())
    }

    pub fn publish(&self, publisher: &Identity) -> Object {
        let mut e = Enc::new();
        e.u64(self.sequence)
            .cid(&self.digest)
            .opt_cid(self.prev.as_ref());
        // The lineage link is carried at L6 as well, so an object holding a checkpoint
        // supersedes the object holding the one before it.
        Object::create(
            publisher,
            CHECKPOINT_KIND,
            self.sequence,
            e.finish(),
            self.prev,
        )
    }

    pub fn from_object(obj: &Object) -> Result<Checkpoint, ObjectError> {
        if obj.kind != CHECKPOINT_KIND {
            return Err(ObjectError::CidMismatch);
        }
        let publisher = obj.verify()?;
        let mut d = Dec::new(&obj.payload);
        let sequence = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        let digest = d.cid().map_err(|_| ObjectError::CidMismatch)?;
        let prev = d.opt_cid().map_err(|_| ObjectError::CidMismatch)?;
        d.end().map_err(|_| ObjectError::CidMismatch)?;
        Ok(Checkpoint {
            publisher,
            sequence,
            digest,
            prev,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The sequence did not advance.
    NotForward { seen: u64, offered: u64 },
    /// Same sequence, different digest. The publisher is equivocating.
    Equivocation { seen: Cid, offered: Cid },
    /// Does not link back to what this witness last countersigned.
    NotAChain,
    /// The publisher did not sign it, so there is nothing to witness.
    Unsigned,
}

/// One witness's memory of what it has countersigned.
pub struct Witness {
    identity: Identity,
    /// Highest checkpoint seen per publisher.
    seen: BTreeMap<Address, Checkpoint>,
}

impl Witness {
    pub fn new(identity: Identity) -> Self {
        Witness {
            identity,
            seen: BTreeMap::new(),
        }
    }

    pub fn address(&self) -> Address {
        self.identity.address()
    }

    /// The verifying key, which is what a countersignature is checked against.
    ///
    /// An address is the **hash** of this and cannot verify anything, so a witness has to
    /// publish the key itself alongside its signature.
    pub fn key(&self) -> [u8; 32] {
        self.identity.key_bytes()
    }

    /// Countersign a checkpoint **the publisher signed**, or refuse and say why.
    ///
    /// Takes a signed object rather than a bare struct, and that is the whole of the fix for a
    /// defect that made this layer worse than useless. Taking a struct meant `publisher` was a
    /// field an attacker filled in, so anyone could:
    ///
    /// - mint a checkpoint naming a victim at `u64::MAX` and permanently prevent that victim
    ///   from ever being countersigned by this witness again;
    /// - mint a checkpoint naming a victim and walk it to a reader's own chosen witnesses,
    ///   who could not refuse because they could not check authorship, so a reader accepted at
    ///   full threshold a digest the publisher never made. **The witnesses substituted**,
    ///   which is exactly the thing this module claims cannot happen;
    /// - front-run a publisher's real checkpoint, so the publisher's own identical request was
    ///   then refused as not-forward and could never reach threshold.
    ///
    /// A repeat of the exact same checkpoint returns the same signature rather than a refusal,
    /// so front-running is not merely unauthenticated but pointless.
    pub fn cosign(&mut self, obj: &Object) -> Result<Signature, Refusal> {
        let c = Checkpoint::from_object(obj).map_err(|_| Refusal::Unsigned)?;
        if let Some(prev) = self.seen.get(&c.publisher) {
            // Idempotent: the same checkpoint twice is not a conflict.
            if c.sequence == prev.sequence && c.digest == prev.digest && c.prev == prev.prev {
                return Ok(self.identity.sign(&c.signing_bytes()));
            }
            if c.sequence == prev.sequence && c.digest != prev.digest {
                return Err(Refusal::Equivocation {
                    seen: prev.digest,
                    offered: c.digest,
                });
            }
            if c.sequence <= prev.sequence {
                return Err(Refusal::NotForward {
                    seen: prev.sequence,
                    offered: c.sequence,
                });
            }
            // Advancing is not enough. It has to advance from **this**, or two histories on
            // disjoint sequence numbers both get countersigned.
            if c.prev != Some(prev.id()) {
                return Err(Refusal::NotAChain);
            }
        } else if c.prev.is_some() {
            // A witness joining mid-chain has nothing to check the link against, and accepting
            // it would let a publisher present any starting point it liked. Refusing means a
            // new witness must be introduced at a point the publisher is willing to restate.
            return Err(Refusal::NotAChain);
        }
        self.seen.insert(c.publisher, c);
        Ok(self.identity.sign(&c.signing_bytes()))
    }

    /// The highest checkpoint this witness has countersigned for a publisher.
    pub fn latest(&self, publisher: &Address) -> Option<&Checkpoint> {
        self.seen.get(publisher)
    }
}

/// A checkpoint with the countersignatures gathered for it.
#[derive(Debug, Clone)]
pub struct Cosigned {
    pub checkpoint: Checkpoint,
    /// The publisher's own signed object, retained so a reader can verify it.
    ///
    /// Held rather than discarded because the reader must check the same thing the witness
    /// checked. Verifying only witness-side left the reader accepting, at full threshold, a
    /// digest the publisher never made: captured witnesses simply never called `cosign` and
    /// signed whatever they liked. That is substitution by witnesses, which is the one thing
    /// this module says cannot happen, and it survived the fix that was supposed to remove it
    /// because the fix was applied to one side of the exchange only.
    signed: Object,
    /// Keyed by verifying key, because an address is its hash and verifies nothing.
    signatures: BTreeMap<[u8; 32], Signature>,
}

impl Cosigned {
    /// Build from the publisher's signed object, verifying it.
    pub fn new(obj: &Object) -> Result<Self, ObjectError> {
        let checkpoint = Checkpoint::from_object(obj)?;
        Ok(Cosigned {
            checkpoint,
            signed: obj.clone(),
            signatures: BTreeMap::new(),
        })
    }

    /// Re-verify the publisher's signature and that it matches the checkpoint carried here.
    pub fn publisher_signature_holds(&self) -> bool {
        match Checkpoint::from_object(&self.signed) {
            Ok(c) => c == self.checkpoint,
            Err(_) => false,
        }
    }

    /// Attach a countersignature, verifying it first.
    ///
    /// Verification here rather than at the reader, so an unverified signature never enters the
    /// structure and a count of signatures is always a count of valid ones.
    pub fn attach(&mut self, key: [u8; 32], sig: Signature) -> bool {
        let Ok(peer) = karst_id::Peer::from_key_bytes(&key) else {
            return false;
        };
        if peer.verify(&self.checkpoint.signing_bytes(), &sig).is_err() {
            return false;
        }
        self.signatures.insert(key, sig);
        true
    }

    pub fn witnesses(&self) -> impl Iterator<Item = Address> + '_ {
        self.signatures
            .keys()
            .filter_map(|k| karst_id::Peer::from_key_bytes(k).ok().map(|p| p.address()))
    }

    /// How many of a reader's chosen witnesses countersigned this.
    ///
    /// Counting only chosen ones is the point. A thousand signatures from witnesses a reader
    /// never picked is a thousand identities somebody minted.
    pub fn support(&self, chosen: &[Address]) -> usize {
        let present: std::collections::BTreeSet<Address> = self.witnesses().collect();
        // Deduplicated, so a witness listed twice in a reader's own list does not satisfy a
        // threshold of two on its own.
        let unique: std::collections::BTreeSet<&Address> = chosen.iter().collect();
        unique.into_iter().filter(|w| present.contains(*w)).count()
    }
}

/// A reader's own witnesses, and how many must agree.
#[derive(Debug, Clone)]
pub struct WitnessPolicy {
    pub chosen: Vec<Address>,
    pub threshold: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Enough chosen witnesses countersigned, and it advances on what the reader held.
    Accepted,
    /// Fewer chosen witnesses than the threshold.
    Undersigned { support: usize, threshold: usize },
    /// Older than what the reader already holds, or the same sequence with a different digest.
    NotForward,
    /// Does not link back to what the reader already holds.
    ///
    /// Distinct from `NotForward` because the failures are different: one is a publisher going
    /// backwards, the other is a publisher offering a history that shares no ancestor with the
    /// reader's. A higher sequence number is not evidence of continuing anything.
    NotAChain,
    /// The publisher did not sign what is being offered.
    Unsigned,
    /// The reader's own policy is unusable.
    BadPolicy,
}

impl WitnessPolicy {
    pub fn new(chosen: Vec<Address>, threshold: usize) -> Self {
        WitnessPolicy { chosen, threshold }
    }

    /// Decide whether to accept a cosigned checkpoint over one already held.
    pub fn accept(&self, held: Option<&Checkpoint>, offered: &Cosigned) -> Acceptance {
        // A threshold of zero accepts anything, including something with no countersignatures
        // and no authentication at all. That is not a policy a reader means to hold.
        if self.threshold == 0 {
            return Acceptance::BadPolicy;
        }
        // The reader checks the publisher's signature, not only the witnesses'. Witnesses that
        // never ran `cosign` can still produce valid countersignatures over anything.
        if !offered.publisher_signature_holds() {
            return Acceptance::Unsigned;
        }
        if let Some(h) = held {
            let c = &offered.checkpoint;
            if c.publisher != h.publisher
                || c.sequence < h.sequence
                || (c.sequence == h.sequence && c.digest != h.digest)
            {
                return Acceptance::NotForward;
            }
            // Advancing is not continuing. Without this, a publisher offers a fresh
            // high-sequence checkpoint with no `prev` to witnesses who have never seen them,
            // those witnesses honestly countersign because they have no prior state, and the
            // reader moves onto a history sharing no ancestor with what it held. The witness
            // enforces this and the reader did not, which is the same rule missing from the
            // other side of the same exchange.
            if c.sequence > h.sequence && c.prev != Some(h.id()) {
                return Acceptance::NotAChain;
            }
        }
        let support = offered.support(&self.chosen);
        if support < self.threshold {
            return Acceptance::Undersigned {
                support,
                threshold: self.threshold,
            };
        }
        Acceptance::Accepted
    }
}

/// Two countersignatures by one witness over conflicting checkpoints at one sequence.
///
/// Portable, verifiable by anyone, and naming the witness. A witness can equivocate; it cannot
/// do so deniably.
#[derive(Debug, Clone)]
pub struct Equivocation {
    /// The witness's verifying key, not its address, for the same reason as above.
    pub witness: [u8; 32],
    pub a: Checkpoint,
    pub sig_a: Signature,
    pub b: Checkpoint,
    pub sig_b: Signature,
}

impl Equivocation {
    /// Which witness this accuses.
    pub fn accused(&self) -> Option<Address> {
        karst_id::Peer::from_key_bytes(&self.witness)
            .ok()
            .map(|p| p.address())
    }

    /// Check the evidence rather than taking anyone's word for it.
    pub fn is_valid(&self) -> bool {
        if self.a.publisher != self.b.publisher
            || self.a.sequence != self.b.sequence
            || self.a.digest == self.b.digest
        {
            return false;
        }
        let Ok(peer) = karst_id::Peer::from_key_bytes(&self.witness) else {
            return false;
        };
        peer.verify(&self.a.signing_bytes(), &self.sig_a).is_ok()
            && peer.verify(&self.b.signing_bytes(), &self.sig_b).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(n: u32) -> Identity {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        Identity::from_seed(seed)
    }

    /// A chain of checkpoints for one publisher, each linking to the last.
    fn chain(pubr: &Identity, digests: &[u8]) -> Vec<(Checkpoint, Object)> {
        let mut out: Vec<(Checkpoint, Object)> = Vec::new();
        let mut prev = None;
        for (i, d) in digests.iter().enumerate() {
            let c = Checkpoint {
                publisher: pubr.address(),
                sequence: i as u64 + 1,
                digest: Cid::of(&[*d]),
                prev,
            };
            prev = Some(c.id());
            let obj = c.publish(pubr);
            out.push((c, obj));
        }
        out
    }

    /// A witness countersigns a signed checkpoint that continues the chain.
    #[test]
    fn a_witness_countersigns_a_forward_checkpoint() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));
        let ch = chain(&pubr, &[1, 2, 3]);
        for (_, obj) in &ch {
            assert!(w.cosign(obj).is_ok());
        }
        assert_eq!(w.latest(&pubr.address()).unwrap().sequence, 3);
    }

    /// Nothing unsigned is ever countersigned.
    ///
    /// The publisher field used to be a struct field an attacker filled in, so anyone could
    /// name a victim and have honest witnesses countersign a digest that victim never made.
    #[test]
    fn a_witness_refuses_anything_the_publisher_did_not_sign() {
        let victim = ident(1);
        let attacker = ident(2);
        let mut w = Witness::new(ident(100));

        // A checkpoint naming the victim, signed by the attacker.
        let forged = Checkpoint {
            publisher: victim.address(),
            sequence: 1,
            digest: Cid::of(b"not mine"),
            prev: None,
        }
        .publish(&attacker);

        // It is signed, so it verifies, but as the attacker rather than the victim.
        let recovered = Checkpoint::from_object(&forged).unwrap();
        assert_eq!(recovered.publisher, attacker.address());
        assert_ne!(recovered.publisher, victim.address());

        // So countersigning it records nothing against the victim.
        assert!(w.cosign(&forged).is_ok());
        assert!(
            w.latest(&victim.address()).is_none(),
            "an attacker poisoned a witness against a victim"
        );
    }

    /// A stranger must not be able to lock a publisher out permanently.
    ///
    /// Naming a victim at u64::MAX used to set that witness's memory forever, and there is no
    /// eviction, so every genuine checkpoint from the victim was refused for the life of the
    /// process.
    #[test]
    fn a_stranger_cannot_lock_a_publisher_out_of_a_witness() {
        let victim = ident(1);
        let attacker = ident(2);
        let mut w = Witness::new(ident(100));

        let poison = Checkpoint {
            publisher: victim.address(),
            sequence: u64::MAX,
            digest: Cid::of(b"x"),
            prev: None,
        }
        .publish(&attacker);
        let _ = w.cosign(&poison);

        // The victim's own first checkpoint still works.
        let ch = chain(&victim, &[7]);
        assert!(w.cosign(&ch[0].1).is_ok());
        assert_eq!(w.latest(&victim.address()).unwrap().sequence, 1);
    }

    /// Front-running a publisher's own checkpoint must not deny them the signature.
    #[test]
    fn an_exact_repeat_returns_a_signature_rather_than_a_refusal() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));
        let ch = chain(&pubr, &[1]);
        let first = w.cosign(&ch[0].1).unwrap();
        let again = w.cosign(&ch[0].1).unwrap();
        assert_eq!(first.to_bytes(), again.to_bytes());
    }

    /// Advancing the sequence is not enough; it has to continue the chain.
    ///
    /// Otherwise a publisher keeps two histories on disjoint sequence numbers, every honest
    /// witness countersigns both, and the pair is not even evidence because equivocation is
    /// defined at a shared sequence.
    #[test]
    fn two_histories_on_disjoint_sequences_do_not_both_get_countersigned() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));

        let history_a = chain(&pubr, &[1, 2]);
        assert!(w.cosign(&history_a[0].1).is_ok());
        assert!(w.cosign(&history_a[1].1).is_ok());

        // A second history that never reuses a sequence number, and never links to A.
        let forked = Checkpoint {
            publisher: pubr.address(),
            sequence: 9,
            digest: Cid::of(b"other history"),
            prev: None,
        }
        .publish(&pubr);
        assert_eq!(w.cosign(&forked), Err(Refusal::NotAChain));

        // Even one that links to the wrong place.
        let wrong_link = Checkpoint {
            publisher: pubr.address(),
            sequence: 9,
            digest: Cid::of(b"other history"),
            prev: Some(history_a[0].0.id()),
        }
        .publish(&pubr);
        assert_eq!(w.cosign(&wrong_link), Err(Refusal::NotAChain));
    }

    /// A witness refuses a regression.
    #[test]
    fn a_witness_refuses_a_regression() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));
        let ch = chain(&pubr, &[1, 2, 3, 4, 5]);
        for (_, obj) in &ch {
            w.cosign(obj).unwrap();
        }
        assert_eq!(
            w.cosign(&ch[2].1),
            Err(Refusal::NotForward {
                seen: 5,
                offered: 3
            })
        );
    }

    /// A publisher showing two digests at one sequence is caught.
    #[test]
    fn a_witness_catches_a_publisher_equivocating() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));
        let ch = chain(&pubr, &[1]);
        w.cosign(&ch[0].1).unwrap();

        let conflicting = Checkpoint {
            publisher: pubr.address(),
            sequence: 1,
            digest: Cid::of(b"different"),
            prev: None,
        }
        .publish(&pubr);
        assert!(matches!(
            w.cosign(&conflicting),
            Err(Refusal::Equivocation { .. })
        ));
    }

    /// A witness joining mid-chain has nothing to check against and says so.
    #[test]
    fn a_witness_will_not_start_partway_through_a_chain() {
        let pubr = ident(1);
        let ch = chain(&pubr, &[1, 2, 3]);
        let mut fresh = Witness::new(ident(101));
        assert_eq!(fresh.cosign(&ch[2].1), Err(Refusal::NotAChain));
        // It has to be introduced at a point the publisher restates.
        assert!(fresh.cosign(&ch[0].1).is_ok());
    }

    /// Publishers do not share a sequence space.
    #[test]
    fn publishers_do_not_share_a_sequence_space() {
        let a = ident(1);
        let b = ident(2);
        let mut w = Witness::new(ident(100));
        for (_, obj) in chain(&a, &[1, 2, 3, 4, 5]) {
            w.cosign(&obj).unwrap();
        }
        assert!(w.cosign(&chain(&b, &[1])[0].1).is_ok());
    }

    /// A countersignature for one publisher must not be replayable for another.
    #[test]
    fn a_countersignature_names_its_publisher() {
        let a = ident(1);
        let b = ident(2);
        let mut w = Witness::new(ident(100));
        let ch_a = chain(&a, &[5]);
        let sig = w.cosign(&ch_a[0].1).unwrap();

        let ch_b = chain(&b, &[5]);
        let mut lifted = Cosigned::new(&ch_b[0].1).unwrap();
        assert!(!lifted.attach(w.key(), sig));
    }

    /// A forged countersignature is refused on attachment.
    #[test]
    fn a_forged_countersignature_is_refused_on_attachment() {
        let pubr = ident(1);
        let honest = ident(100);
        let forger = ident(101);
        let built = chain(&pubr, &[1]);
        let c = built[0].0;
        let mut cos = Cosigned::new(&built[0].1).unwrap();
        assert!(!cos.attach(honest.key_bytes(), forger.sign(&c.signing_bytes())));
        assert_eq!(cos.witnesses().count(), 0);
    }

    /// A reader counts only witnesses they chose.
    #[test]
    fn signatures_from_unchosen_witnesses_do_not_count() {
        let pubr = ident(1);
        let ch = chain(&pubr, &[1]);
        let mut cos = Cosigned::new(&ch[0].1).unwrap();
        let mine: Vec<Address> = (200..203u32).map(|i| ident(i).address()).collect();

        for i in 1_000..11_000u32 {
            let mut w = Witness::new(ident(i));
            let sig = w.cosign(&ch[0].1).unwrap();
            assert!(cos.attach(w.key(), sig));
        }
        assert_eq!(cos.witnesses().count(), 10_000);
        assert_eq!(
            WitnessPolicy::new(mine, 2).accept(None, &cos),
            Acceptance::Undersigned {
                support: 0,
                threshold: 2
            }
        );
    }

    /// A duplicated witness in a reader's own list must not satisfy a threshold twice.
    #[test]
    fn a_duplicated_witness_counts_once() {
        let pubr = ident(1);
        let ch = chain(&pubr, &[1]);
        let mut cos = Cosigned::new(&ch[0].1).unwrap();
        let mut w = Witness::new(ident(200));
        cos.attach(w.key(), w.cosign(&ch[0].1).unwrap());

        let doubled = vec![ident(200).address(), ident(200).address()];
        assert!(
            matches!(
                WitnessPolicy::new(doubled, 2).accept(None, &cos),
                Acceptance::Undersigned { support: 1, .. }
            ),
            "one witness satisfied a threshold of two by being listed twice"
        );
    }

    /// A threshold is met only by chosen witnesses.
    #[test]
    fn a_threshold_is_met_by_chosen_witnesses() {
        let pubr = ident(1);
        let ch = chain(&pubr, &[1]);
        let mut cos = Cosigned::new(&ch[0].1).unwrap();
        let chosen: Vec<Address> = (200..204u32).map(|i| ident(i).address()).collect();

        for i in 200..202u32 {
            let mut w = Witness::new(ident(i));
            cos.attach(w.key(), w.cosign(&ch[0].1).unwrap());
        }
        let policy = WitnessPolicy::new(chosen, 3);
        assert!(matches!(
            policy.accept(None, &cos),
            Acceptance::Undersigned { support: 2, .. }
        ));

        let mut w = Witness::new(ident(202));
        cos.attach(w.key(), w.cosign(&ch[0].1).unwrap());
        assert_eq!(policy.accept(None, &cos), Acceptance::Accepted);
    }

    /// A reader refuses a rollback even when fully countersigned.
    #[test]
    fn a_reader_refuses_a_rollback_even_when_fully_countersigned() {
        let pubr = ident(1);
        let ch = chain(&pubr, &[1, 2, 3, 4]);
        let newer = ch[3].0;
        let _older = ch[1].0;

        let mut cos = Cosigned::new(&ch[1].1).unwrap();
        let chosen: Vec<Address> = (200..203u32).map(|i| ident(i).address()).collect();
        for i in 200..203u32 {
            let mut w = Witness::new(ident(i));
            cos.attach(w.key(), w.cosign(&ch[0].1).unwrap());
            cos.attach(w.key(), w.cosign(&ch[1].1).unwrap());
        }
        let policy = WitnessPolicy::new(chosen, 3);
        assert_eq!(cos.support(&policy.chosen), 3);
        assert_eq!(policy.accept(Some(&newer), &cos), Acceptance::NotForward);
    }

    /// Equivocation by a witness is provable by anyone.
    #[test]
    fn equivocation_by_a_witness_is_provable_by_anyone() {
        let pubr = ident(1);
        let bad = ident(100);
        let a = Checkpoint {
            publisher: pubr.address(),
            sequence: 3,
            digest: Cid::of(&[1]),
            prev: None,
        };
        let b = Checkpoint {
            publisher: pubr.address(),
            sequence: 3,
            digest: Cid::of(&[2]),
            prev: None,
        };

        let proof = Equivocation {
            witness: bad.key_bytes(),
            a,
            sig_a: bad.sign(&a.signing_bytes()),
            b,
            sig_b: bad.sign(&b.signing_bytes()),
        };
        assert!(proof.is_valid());
        assert_eq!(proof.accused(), Some(bad.address()));

        let honest = ident(101);
        let framed = Equivocation {
            witness: honest.key_bytes(),
            a,
            sig_a: bad.sign(&a.signing_bytes()),
            b,
            sig_b: bad.sign(&b.signing_bytes()),
        };
        assert!(!framed.is_valid(), "an honest witness was framed");
    }

    /// A non-conflict is not evidence.
    #[test]
    fn a_non_conflict_is_not_evidence() {
        let pubr = ident(1);
        let w = ident(100);
        let a = Checkpoint {
            publisher: pubr.address(),
            sequence: 3,
            digest: Cid::of(&[1]),
            prev: None,
        };
        let b = Checkpoint {
            publisher: pubr.address(),
            sequence: 4,
            digest: Cid::of(&[2]),
            prev: Some(a.id()),
        };
        assert!(!Equivocation {
            witness: w.key_bytes(),
            a,
            sig_a: w.sign(&a.signing_bytes()),
            b,
            sig_b: w.sign(&b.signing_bytes()),
        }
        .is_valid());
    }

    /// A captured witness set can stall and cannot forge.
    #[test]
    fn a_captured_witness_set_can_only_stall() {
        let pubr = ident(1);
        let ch = chain(&pubr, &[1]);
        let chosen: Vec<Address> = (200..203u32).map(|i| ident(i).address()).collect();
        let cos = Cosigned::new(&ch[0].1).unwrap();
        assert!(matches!(
            WitnessPolicy::new(chosen, 2).accept(None, &cos),
            Acceptance::Undersigned { support: 0, .. }
        ));
    }
    /// A reader must verify the publisher's signature, not only the witnesses'.
    ///
    /// Captured witnesses never call `cosign`; they run whatever code they like and can
    /// countersign anything. Verifying only on the witness side left the reader accepting, at
    /// full threshold, a digest the publisher never made. That is substitution by witnesses,
    /// which this module says cannot happen, and it survived the fix meant to remove it because
    /// the fix was applied to one side of the exchange only.
    #[test]
    fn a_captured_witness_set_cannot_forge_a_checkpoint() {
        let alice = ident(1);
        let w1 = ident(500);
        let w2 = ident(501);
        let chosen = vec![w1.address(), w2.address(), ident(502).address()];
        let policy = WitnessPolicy::new(chosen, 2);

        // The adversary invents a checkpoint naming alice and signs it with its own key,
        // because only the witness keys are theirs.
        let forged = Checkpoint {
            publisher: alice.address(),
            sequence: 5,
            digest: Cid::of(b"never published"),
            prev: None,
        };
        let signed_by_adversary = forged.publish(&w1);
        let cos = Cosigned::new(&signed_by_adversary).unwrap();

        // The checkpoint that comes back names the adversary, because the publisher is taken
        // from the verified signature and never from the payload. The adversary cannot even
        // construct a Cosigned that claims to be alice's.
        assert_ne!(cos.checkpoint.publisher, alice.address());
        assert_eq!(cos.checkpoint.publisher, w1.address());

        // Countersignatures over the adversary's own bytes still verify, so support is real,
        // and the object is genuinely signed. What a reader gets is a checkpoint by w1, which
        // is not a claim about alice at all.
        let mut cos = cos;
        assert!(cos.attach(w1.key_bytes(), w1.sign(&cos.checkpoint.signing_bytes())));
        assert!(cos.attach(w2.key_bytes(), w2.sign(&cos.checkpoint.signing_bytes())));
        assert_eq!(cos.support(&policy.chosen), 2);

        // A reader tracking alice compares against what it holds for alice and sees a
        // different publisher.
        let alice_chain = chain(&alice, &[1]);
        assert_eq!(
            policy.accept(Some(&alice_chain[0].0), &cos),
            Acceptance::NotForward,
            "a checkpoint by somebody else was accepted as alice's"
        );
    }

    /// A reader refuses a history that shares no ancestor with what it holds.
    ///
    /// The witness enforces the chain and the reader did not, so a publisher offering a fresh
    /// high-sequence checkpoint to witnesses who had never seen them got honest
    /// countersignatures and moved the reader onto a fabricated history.
    #[test]
    fn a_reader_refuses_a_higher_sequence_that_does_not_continue_its_chain() {
        let alice = ident(1);
        let real = chain(&alice, &[1, 2, 3]);
        let held = real[2].0;

        // A fresh history at a higher sequence, with no link back.
        let fabricated = Checkpoint {
            publisher: alice.address(),
            sequence: 9,
            digest: Cid::of(b"fabricated"),
            prev: None,
        };
        let obj = fabricated.publish(&alice);
        let mut cos = Cosigned::new(&obj).unwrap();

        // Two honest witnesses that have never seen alice countersign it, correctly, because
        // they have no prior state to contradict.
        let chosen: Vec<Address> = (700..702u32).map(|i| ident(i).address()).collect();
        for i in 700..702u32 {
            let mut w = Witness::new(ident(i));
            let sig = w
                .cosign(&obj)
                .expect("a fresh witness has nothing to refuse");
            cos.attach(w.key(), sig);
        }
        let policy = WitnessPolicy::new(chosen, 2);
        assert_eq!(cos.support(&policy.chosen), 2);
        assert_eq!(policy.accept(Some(&held), &cos), Acceptance::NotAChain);
    }

    /// A threshold of zero is not a policy.
    #[test]
    fn a_threshold_of_zero_is_refused_rather_than_satisfied() {
        let pubr = ident(1);
        let ch = chain(&pubr, &[1]);
        let cos = Cosigned::new(&ch[0].1).unwrap();
        assert_eq!(
            WitnessPolicy::new(vec![], 0).accept(None, &cos),
            Acceptance::BadPolicy
        );
    }

    /// A tampered object must be refused as unsigned, which the existing test never reaches.
    ///
    /// `a_witness_refuses_anything_the_publisher_did_not_sign` only ever feeds `cosign` objects
    /// that are correctly signed by *somebody*, so `Refusal::Unsigned` is never returned and
    /// the branch that produces it is untested. Deleting the `from_object` call and trusting
    /// the payload would have left that test passing.
    #[test]
    fn a_tampered_checkpoint_object_is_refused_as_unsigned() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));
        let ch = chain(&pubr, &[1]);

        let mut bad = ch[0].1.clone();
        bad.payload[0] ^= 0x01;
        assert_eq!(w.cosign(&bad), Err(Refusal::Unsigned));
        // Nothing was recorded, so a tampered offer cannot poison the witness either.
        assert!(w.latest(&pubr.address()).is_none());

        // Wrong kind entirely.
        let not_a_checkpoint =
            karst_object::Object::create(&pubr, "karst.something.else", 0, vec![1, 2, 3], None);
        assert_eq!(w.cosign(&not_a_checkpoint), Err(Refusal::Unsigned));

        // And the untampered one still works, so the refusals above are about the tampering.
        assert!(w.cosign(&ch[0].1).is_ok());
    }

    /// Two more non-conflicts that are not evidence.
    ///
    /// The existing test tries only differing sequences. A pair naming two different publishers
    /// at one sequence, and a pair that is the same checkpoint twice, are both shapes an
    /// accuser could assemble, and neither is equivocation.
    #[test]
    fn a_pair_across_publishers_or_a_repeat_is_not_evidence() {
        let a_pub = ident(1);
        let b_pub = ident(2);
        let w = ident(100);

        let a = Checkpoint {
            publisher: a_pub.address(),
            sequence: 3,
            digest: Cid::of(&[1]),
            prev: None,
        };
        let b = Checkpoint {
            publisher: b_pub.address(),
            sequence: 3,
            digest: Cid::of(&[2]),
            prev: None,
        };
        // Different publishers: a witness may sign for both and has contradicted nothing.
        assert!(!Equivocation {
            witness: w.key_bytes(),
            a,
            sig_a: w.sign(&a.signing_bytes()),
            b,
            sig_b: w.sign(&b.signing_bytes()),
        }
        .is_valid());

        // The same checkpoint twice is not two statements.
        assert!(!Equivocation {
            witness: w.key_bytes(),
            a,
            sig_a: w.sign(&a.signing_bytes()),
            b: a,
            sig_b: w.sign(&a.signing_bytes()),
        }
        .is_valid());

        // Positive control: a genuine conflict at one sequence for one publisher is evidence.
        let conflicting = Checkpoint {
            publisher: a_pub.address(),
            sequence: 3,
            digest: Cid::of(&[9]),
            prev: None,
        };
        assert!(Equivocation {
            witness: w.key_bytes(),
            a,
            sig_a: w.sign(&a.signing_bytes()),
            b: conflicting,
            sig_b: w.sign(&conflicting.signing_bytes()),
        }
        .is_valid());
    }
}
