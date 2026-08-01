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
            .cid(&self.digest);
        e.finish()
    }

    pub fn publish(&self, publisher: &Identity) -> Object {
        let mut e = Enc::new();
        e.u64(self.sequence).cid(&self.digest);
        Object::create(publisher, CHECKPOINT_KIND, self.sequence, e.finish(), None)
    }

    pub fn from_object(obj: &Object) -> Result<Checkpoint, ObjectError> {
        if obj.kind != CHECKPOINT_KIND {
            return Err(ObjectError::CidMismatch);
        }
        let publisher = obj.verify()?;
        let mut d = Dec::new(&obj.payload);
        let sequence = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        let digest = d.cid().map_err(|_| ObjectError::CidMismatch)?;
        d.end().map_err(|_| ObjectError::CidMismatch)?;
        Ok(Checkpoint {
            publisher,
            sequence,
            digest,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The sequence did not advance.
    NotForward { seen: u64, offered: u64 },
    /// Same sequence, different digest. The publisher is equivocating.
    Equivocation { seen: Cid, offered: Cid },
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

    /// Countersign, or refuse and say why.
    ///
    /// A witness signs nothing it originated. It attests only that this checkpoint extends what
    /// it has already seen from this publisher, which is the whole of what it knows and the
    /// whole of what it claims.
    pub fn cosign(&mut self, c: &Checkpoint) -> Result<Signature, Refusal> {
        if let Some(prev) = self.seen.get(&c.publisher) {
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
        }
        self.seen.insert(c.publisher, *c);
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
    /// Keyed by verifying key, because an address is its hash and verifies nothing.
    signatures: BTreeMap<[u8; 32], Signature>,
}

impl Cosigned {
    pub fn new(checkpoint: Checkpoint) -> Self {
        Cosigned {
            checkpoint,
            signatures: BTreeMap::new(),
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
        chosen.iter().filter(|w| present.contains(*w)).count()
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
}

impl WitnessPolicy {
    pub fn new(chosen: Vec<Address>, threshold: usize) -> Self {
        WitnessPolicy { chosen, threshold }
    }

    /// Decide whether to accept a cosigned checkpoint over one already held.
    pub fn accept(&self, held: Option<&Checkpoint>, offered: &Cosigned) -> Acceptance {
        if let Some(h) = held {
            let c = &offered.checkpoint;
            if c.publisher != h.publisher
                || c.sequence < h.sequence
                || (c.sequence == h.sequence && c.digest != h.digest)
            {
                return Acceptance::NotForward;
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

    fn cp(pubr: &Identity, seq: u64, d: u8) -> Checkpoint {
        Checkpoint {
            publisher: pubr.address(),
            sequence: seq,
            digest: Cid::of(&[d]),
        }
    }

    /// A witness countersigns something that moves forward.
    #[test]
    fn a_witness_countersigns_a_forward_checkpoint() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));
        assert!(w.cosign(&cp(&pubr, 1, 1)).is_ok());
        assert!(w.cosign(&cp(&pubr, 2, 2)).is_ok());
        assert_eq!(w.latest(&pubr.address()).unwrap().sequence, 2);
    }

    /// And refuses one that goes backwards, which is the whole job.
    #[test]
    fn a_witness_refuses_a_regression() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));
        w.cosign(&cp(&pubr, 5, 1)).unwrap();
        assert_eq!(
            w.cosign(&cp(&pubr, 3, 2)),
            Err(Refusal::NotForward {
                seen: 5,
                offered: 3
            })
        );
        assert_eq!(w.latest(&pubr.address()).unwrap().sequence, 5);
    }

    /// A publisher showing two histories at one sequence is caught by the witness.
    ///
    /// This is the split view the whole layer exists for. Without a witness, two readers each
    /// see a signed, current, internally consistent history and neither can tell.
    #[test]
    fn a_witness_catches_a_publisher_equivocating() {
        let pubr = ident(1);
        let mut w = Witness::new(ident(100));
        w.cosign(&cp(&pubr, 7, 1)).unwrap();
        assert_eq!(
            w.cosign(&cp(&pubr, 7, 2)),
            Err(Refusal::Equivocation {
                seen: Cid::of(&[1]),
                offered: Cid::of(&[2])
            })
        );
    }

    /// Publishers are tracked separately, or one publisher would block another.
    #[test]
    fn publishers_do_not_share_a_sequence_space() {
        let a = ident(1);
        let b = ident(2);
        let mut w = Witness::new(ident(100));
        w.cosign(&cp(&a, 9, 1)).unwrap();
        assert!(w.cosign(&cp(&b, 1, 1)).is_ok(), "one publisher blocked another");
    }

    /// A countersignature for one publisher must not be replayable for another.
    #[test]
    fn a_countersignature_names_its_publisher() {
        let a = ident(1);
        let b = ident(2);
        let mut w = Witness::new(ident(100));
        let sig = w.cosign(&cp(&a, 1, 5)).unwrap();

        // Same sequence and digest, different publisher.
        let mut lifted = Cosigned::new(cp(&b, 1, 5));
        assert!(
            !lifted.attach(w.key(), sig),
            "a countersignature was lifted onto another publisher"
        );
    }

    /// An invalid signature must never enter the structure.
    #[test]
    fn a_forged_countersignature_is_refused_on_attachment() {
        let pubr = ident(1);
        let honest = ident(100);
        let forger = ident(101);
        let c = cp(&pubr, 1, 1);

        let mut cos = Cosigned::new(c);
        // The forger signs, and claims to be the honest witness.
        let sig = forger.sign(&c.signing_bytes());
        assert!(!cos.attach(honest.key_bytes(), sig));
        assert_eq!(cos.witnesses().count(), 0);
    }

    /// A reader counts only the witnesses they chose.
    ///
    /// Otherwise a thousand countersignatures is a thousand identities somebody minted, which
    /// is the whole Sybil problem arriving through the mechanism meant to resist it.
    #[test]
    fn signatures_from_unchosen_witnesses_do_not_count() {
        let pubr = ident(1);
        let c = cp(&pubr, 1, 1);
        let mut cos = Cosigned::new(c);

        let mine: Vec<Address> = (200..203u32).map(|i| ident(i).address()).collect();
        // Ten thousand strangers countersign.
        for i in 1_000..11_000u32 {
            let mut w = Witness::new(ident(i));
            let sig = w.cosign(&c).unwrap();
            assert!(cos.attach(w.key(), sig));
        }
        assert_eq!(cos.witnesses().count(), 10_000);

        let policy = WitnessPolicy::new(mine, 2);
        assert_eq!(
            policy.accept(None, &cos),
            Acceptance::Undersigned {
                support: 0,
                threshold: 2
            },
            "strangers satisfied a reader's threshold"
        );
    }

    /// The threshold is met only by chosen witnesses.
    #[test]
    fn a_threshold_is_met_by_chosen_witnesses() {
        let pubr = ident(1);
        let c = cp(&pubr, 1, 1);
        let mut cos = Cosigned::new(c);
        let chosen: Vec<Address> = (200..204u32).map(|i| ident(i).address()).collect();

        for i in 200..202u32 {
            let mut w = Witness::new(ident(i));
            cos.attach(w.key(), w.cosign(&c).unwrap());
        }
        let policy = WitnessPolicy::new(chosen.clone(), 3);
        assert!(matches!(
            policy.accept(None, &cos),
            Acceptance::Undersigned { support: 2, .. }
        ));

        let mut w = Witness::new(ident(202));
        cos.attach(w.key(), w.cosign(&c).unwrap());
        assert_eq!(policy.accept(None, &cos), Acceptance::Accepted);
    }

    /// A reader refuses a checkpoint that does not advance on what they hold.
    ///
    /// This is what stops a jointly stale replica set: the replicas agree with each other, and
    /// the reader has already seen further.
    #[test]
    fn a_reader_refuses_a_rollback_even_when_fully_countersigned() {
        let pubr = ident(1);
        let chosen: Vec<Address> = (200..203u32).map(|i| ident(i).address()).collect();
        let policy = WitnessPolicy::new(chosen, 3);

        let newer = cp(&pubr, 10, 9);
        let older = cp(&pubr, 4, 4);
        let mut cos = Cosigned::new(older);
        // Fresh witnesses, so they have no memory that would refuse it, and all three sign.
        for i in 200..203u32 {
            let mut w = Witness::new(ident(i));
            cos.attach(w.key(), w.cosign(&older).unwrap());
        }
        assert_eq!(cos.support(&policy.chosen), 3);
        assert_eq!(policy.accept(Some(&newer), &cos), Acceptance::NotForward);
    }

    /// A witness that equivocates leaves portable evidence.
    ///
    /// Anyone can check it and it names the witness, so equivocation is expensive rather than
    /// deniable. A witness that never equivocates is never accused, because the evidence
    /// cannot be manufactured without its key.
    #[test]
    fn equivocation_by_a_witness_is_provable_by_anyone() {
        let pubr = ident(1);
        let bad = ident(100);
        let a = cp(&pubr, 3, 1);
        let b = cp(&pubr, 3, 2);

        let proof = Equivocation {
            witness: bad.key_bytes(),
            a,
            sig_a: bad.sign(&a.signing_bytes()),
            b,
            sig_b: bad.sign(&b.signing_bytes()),
        };
        assert!(proof.is_valid());

        // The same shape against an honest witness cannot be assembled without its key.
        let honest = ident(101);
        let forged = Equivocation {
            witness: honest.key_bytes(),
            a,
            sig_a: bad.sign(&a.signing_bytes()),
            b,
            sig_b: bad.sign(&b.signing_bytes()),
        };
        assert!(!forged.is_valid(), "an honest witness was framed");
    }

    /// Evidence that is not actually a conflict must be rejected.
    #[test]
    fn a_non_conflict_is_not_evidence() {
        let pubr = ident(1);
        let w = ident(100);
        let a = cp(&pubr, 3, 1);
        let b = cp(&pubr, 4, 2);

        // Different sequences: advancing, not equivocating.
        let advancing = Equivocation {
            witness: w.key_bytes(),
            a,
            sig_a: w.sign(&a.signing_bytes()),
            b,
            sig_b: w.sign(&b.signing_bytes()),
        };
        assert!(!advancing.is_valid());

        // Same checkpoint twice.
        let same = Equivocation {
            witness: w.key_bytes(),
            a,
            sig_a: w.sign(&a.signing_bytes()),
            b: a,
            sig_b: w.sign(&a.signing_bytes()),
        };
        assert!(!same.is_valid());
    }

    /// Witnesses add parties who can withhold and none who can substitute.
    ///
    /// A witness never originates a statement, so the worst a captured set can do is refuse to
    /// countersign, which is visible as an undersigned checkpoint rather than as a wrong one.
    #[test]
    fn a_captured_witness_set_can_only_stall() {
        let pubr = ident(1);
        let chosen: Vec<Address> = (200..203u32).map(|i| ident(i).address()).collect();
        let policy = WitnessPolicy::new(chosen, 2);

        // Every witness refuses. Nothing they can do produces a checkpoint the publisher did
        // not sign, because they do not sign checkpoints, they sign about them.
        let c = cp(&pubr, 1, 1);
        let cos = Cosigned::new(c);
        assert!(matches!(
            policy.accept(None, &cos),
            Acceptance::Undersigned { support: 0, .. }
        ));
        assert_eq!(cos.witnesses().count(), 0);
    }
}
