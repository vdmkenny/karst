//! Somewhere for mail to wait.
//!
//! A recipient who must be reachable when a message is sent is a recipient whose presence is
//! the network's business. Providers exist so that receiving is a pull: mail is left in a box,
//! the box is collected later, and being offline is not observable to the sender or to anyone
//! watching the sender. Loopix uses the same arrangement.
//!
//! # What a provider learns, stated plainly
//!
//! It sees a mailbox tag and a sealed blob of fixed size. It does not see the content, the
//! sender, the message length, or the number of messages in the underlying conversation. It
//! does see how much traffic a tag receives and when it is collected, and it can withhold or
//! discard. **A provider is trusted for availability and not for confidentiality.**
//!
//! # Tags are secret
//!
//! A mailbox tag is 32 random bytes given out with a contact's sealing key, not derived from
//! an identity. Anyone who has been given a tag can deposit into it, and nobody else can find
//! it. This is what keeps a stranger from flooding a box they were never told about.
//!
//! It leaves a known gap: a **correspondent** can flood a box they legitimately know. The
//! answer is to gate deposit on a capability the recipient issues, spendable anonymously so
//! that presenting one does not identify the sender. L9 and L14 already hold both halves and
//! they are not wired together.
//!
//! # A full box is reported, not hidden
//!
//! When a box is full, new mail is refused and the refusal is counted. The alternative is to
//! evict what is already there, which loses mail nobody has read yet and loses it silently.
//! A recipient collecting from a box that refused deposits is told so, and can act on it. This
//! is the same choice made everywhere else in this design: an adversary who causes loss should
//! cause a loss that is **visible** rather than one that is deniable.
//!
//! # An empty box is not remembered forever
//!
//! `DEFAULT_TOTAL` bounds stored items and bounds nothing about the number of tags. A box
//! emptied by its owner used to stay in the map at zero items, so `{deposit to a fresh tag,
//! drain it}` grew the map permanently at two packets an iteration while `held` never rose
//! above one. Empty boxes are therefore dropped.
//!
//! A box emptied but carrying a refusal count is the awkward case, because that count is the
//! only record that mail was lost and the tag owner has not seen it yet. Those are kept, up to
//! `MAX_REFUSAL_MEMORY`, oldest forgotten first. Forgetting is counted in
//! [`Provider::forgotten`] rather than done quietly, since a provider that silently loses the
//! evidence of loss is worse than one that admits it.

use std::collections::{BTreeMap, VecDeque};

use crate::frame::{ENVELOPE_BYTES, MAILBOX_BYTES};

pub type Tag = [u8; MAILBOX_BYTES];

/// Why a drain was refused. Never sent on the wire: a provider that answered would say
/// whether the tag exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainError {
    /// The tag is not the hash of the key presented, or the signature does not verify.
    NotYours,
    /// That counter has already been used for this box.
    Replayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositError {
    /// Not the size everything on this network is.
    WrongSize,
    /// The box is full. Counted against the box so the owner learns of it.
    BoxFull,
    /// The provider as a whole is full.
    ProviderFull,
}

/// What a collector is handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collected {
    pub items: Vec<Vec<u8>>,
    /// Deposits refused since the last collection. Non-zero means mail was lost.
    pub refused: u64,
}

#[derive(Debug, Default)]
struct Box_ {
    items: VecDeque<Vec<u8>>,
    refused: u64,
    /// Creation order, for age-ordered eviction. Never the tag, which the adversary picks.
    seq: u64,
    /// Highest drain counter accepted for this box, so a captured request cannot be replayed.
    drained_to: u64,
}

#[derive(Debug)]
pub struct Provider {
    boxes: BTreeMap<Tag, Box_>,
    per_box: usize,
    total: usize,
    held: usize,
    next_seq: u64,
    forgotten: u64,
}

impl Provider {
    pub const DEFAULT_PER_BOX: usize = 1024;
    pub const DEFAULT_TOTAL: usize = 1 << 20;
    /// How many emptied boxes may be kept solely to report a refusal count.
    ///
    /// Producing one costs an adversary `per_box + 1` deposits and a drain, so this is not a
    /// cheap structure to grind, but it is not a free one either and it needs a bound.
    pub const MAX_REFUSAL_MEMORY: usize = 1 << 14;

    pub fn new() -> Self {
        Provider {
            boxes: BTreeMap::new(),
            per_box: Self::DEFAULT_PER_BOX,
            total: Self::DEFAULT_TOTAL,
            held: 0,
            next_seq: 0,
            forgotten: 0,
        }
    }

    pub fn with_limits(per_box: usize, total: usize) -> Self {
        Provider {
            per_box,
            total,
            ..Provider::new()
        }
    }

    pub fn held(&self) -> usize {
        self.held
    }

    /// Boxes currently tracked. Bounded, which is the point.
    pub fn boxes(&self) -> usize {
        self.boxes.len()
    }

    /// Refusal counts dropped to stay inside [`Provider::MAX_REFUSAL_MEMORY`].
    ///
    /// Non-zero means some owner will collect an under-reported refusal count. It is a worse
    /// outcome than remembering and a better one than running out of memory, and it is
    /// readable rather than silent.
    pub fn forgotten(&self) -> u64 {
        self.forgotten
    }

    /// Drop what carries no information, then bound what does.
    fn prune(&mut self) {
        // A box that remembers a drain counter is kept even when empty: forgetting it would
        // make an already-used request work again.
        self.boxes
            .retain(|_, b| !b.items.is_empty() || b.refused > 0 || b.drained_to > 0);

        let empties = self.boxes.values().filter(|b| b.items.is_empty()).count();
        if empties <= Self::MAX_REFUSAL_MEMORY {
            return;
        }
        // Oldest first, by creation order rather than by tag: a tag is chosen by whoever
        // deposits, so evicting on it hands the adversary the choice of victim.
        let mut ages: Vec<(u64, Tag)> = self
            .boxes
            .iter()
            .filter(|(_, b)| b.items.is_empty())
            .map(|(t, b)| (b.seq, *t))
            .collect();
        ages.sort_unstable();
        for (_, tag) in ages.into_iter().take(empties - Self::MAX_REFUSAL_MEMORY) {
            self.boxes.remove(&tag);
            self.forgotten += 1;
        }
    }

    /// File a delivered payload.
    ///
    /// The payload is `[tag][sealed]` and the provider reads only the tag.
    pub fn deposit(&mut self, payload: &[u8]) -> Result<(), DepositError> {
        if payload.len() != MAILBOX_BYTES + ENVELOPE_BYTES {
            return Err(DepositError::WrongSize);
        }
        let mut tag: Tag = [0u8; MAILBOX_BYTES];
        tag.copy_from_slice(&payload[..MAILBOX_BYTES]);
        let sealed = payload[MAILBOX_BYTES..].to_vec();

        if self.held >= self.total {
            return Err(DepositError::ProviderFull);
        }
        let seq = self.next_seq;
        let b = self.boxes.entry(tag).or_insert_with(|| Box_ {
            seq,
            ..Box_::default()
        });
        if b.seq == seq {
            self.next_seq += 1;
        }
        if b.items.len() >= self.per_box {
            b.refused += 1;
            return Err(DepositError::BoxFull);
        }
        b.items.push_back(sealed);
        self.held += 1;
        Ok(())
    }

    /// Empty a box, for a party entitled to drain it.
    ///
    /// Collecting a box that does not exist returns an empty collection rather than an error,
    /// because an error would tell whoever asked that the tag is unused, and that turns
    /// collection into a way to probe which tags are live.
    pub fn collect(&mut self, tag: &Tag) -> Collected {
        match self.boxes.remove(tag) {
            None => Collected {
                items: Vec::new(),
                refused: 0,
            },
            Some(b) => {
                self.held -= b.items.len();
                Collected {
                    items: b.items.into(),
                    refused: b.refused,
                }
            }
        }
    }

    /// Take one item on proof that the asker holds the drain key.
    ///
    /// The credential is the drain key's **public** half; the proof is a signature over a
    /// counter. Nothing secret crosses the wire, which is the difference from the earlier
    /// arrangement: that one sent the drain secret itself on every poll, as its own proof, so
    /// a single captured datagram took the mailbox for good.
    ///
    /// The counter must exceed every counter already accepted for this tag, which is what
    /// makes a captured request useless when replayed.
    ///
    /// A box is kept while it remembers a counter even when it holds nothing, because
    /// forgetting the counter would let an old request work again. That state is bounded like
    /// everything else here, so a tag evicted under pressure does become replayable; the cap
    /// is high and the alternative is unbounded memory.
    pub fn drain_once(
        &mut self,
        tag: &Tag,
        drain_public: &[u8; 32],
        counter: u64,
        signature: &[u8; 64],
    ) -> Result<(Option<Vec<u8>>, u64), DrainError> {
        // The tag must be the hash of the key presented, or anyone could drain any box by
        // presenting a key of their own.
        if *tag != crate::client::mailbox_tag(drain_public) {
            return Err(DrainError::NotYours);
        }
        let peer =
            karst_id::Peer::from_key_bytes(drain_public).map_err(|_| DrainError::NotYours)?;
        let sig = karst_id::Signature::from_bytes(signature);
        if peer
            .verify(&crate::client::drain_challenge(counter), &sig)
            .is_err()
        {
            return Err(DrainError::NotYours);
        }

        let seq = self.next_seq;
        let b = self.boxes.entry(*tag).or_insert_with(|| Box_ {
            seq,
            ..Box_::default()
        });
        if b.seq == seq {
            self.next_seq += 1;
        }
        if counter <= b.drained_to {
            return Err(DrainError::Replayed);
        }
        b.drained_to = counter;

        let item = b.items.pop_front();
        if item.is_some() {
            self.held -= 1;
        }
        let refused = b.refused;
        self.prune();
        Ok((item, refused))
    }

    /// Take one item, leaving the box and its refusal count intact.
    ///
    /// The refusal count is what tells an owner that mail was lost, so handing back one item
    /// must not destroy it. The earlier arrangement emptied the box and re-deposited the
    /// remainder, which recreated the entry through `or_default()` and zeroed the count.
    pub fn take_one(&mut self, tag: &Tag) -> (Option<Vec<u8>>, u64) {
        match self.boxes.get_mut(tag) {
            None => (None, 0),
            Some(b) => {
                let item = b.items.pop_front();
                if item.is_some() {
                    self.held -= 1;
                }
                let refused = b.refused;
                self.prune();
                (item, refused)
            }
        }
    }

    /// Read one item without removing it.
    ///
    /// For feeds, where the tag is public and anyone may read. Draining on read would let any
    /// stranger delete a publisher's output one datagram at a time.
    pub fn peek(&self, tag: &Tag, index: usize) -> (Option<Vec<u8>>, u64) {
        match self.boxes.get(tag) {
            None => (None, 0),
            Some(b) => (b.items.get(index).cloned(), b.refused),
        }
    }

    /// How many items a box holds. Used by a feed reader to know when it has caught up.
    pub fn depth(&self, tag: &Tag) -> usize {
        self.boxes.get(tag).map_or(0, |b| b.items.len())
    }
}

impl Default for Provider {
    fn default() -> Self {
        Provider::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(tag: u8, body: u8) -> Vec<u8> {
        let mut v = vec![tag; MAILBOX_BYTES];
        v.extend(std::iter::repeat(body).take(ENVELOPE_BYTES));
        v
    }

    fn tagged(tag: &[u8; MAILBOX_BYTES], body: u8) -> Vec<u8> {
        let mut v = tag.to_vec();
        v.extend(std::iter::repeat(body).take(ENVELOPE_BYTES));
        v
    }

    /// The bound that `DEFAULT_TOTAL` does not provide.
    ///
    /// `{deposit to a fresh tag, drain it}` keeps `held` at one forever, so the item bound
    /// never engages, while each iteration used to leave an entry in the map permanently. Two
    /// packets bought a permanent allocation, which is a memory exhaustion at line rate.
    #[test]
    fn draining_a_box_does_not_leave_it_behind() {
        let mut p = Provider::new();
        for i in 0..5_000u32 {
            let mut tag = [0u8; MAILBOX_BYTES];
            tag[..4].copy_from_slice(&i.to_le_bytes());
            p.deposit(&tagged(&tag, 7)).unwrap();
            assert!(p.take_one(&tag).0.is_some());
        }
        assert_eq!(p.held(), 0);
        assert_eq!(p.boxes(), 0, "an emptied box with nothing to report was kept");
    }

    /// Refusal counts survive an emptied box, up to a bound, and forgetting is visible.
    ///
    /// A box emptied while carrying refusals is the one empty box worth keeping: the count is
    /// the only record that mail was lost. It is still not worth keeping without limit, and an
    /// owner handed an under-reported count should be able to find out that happened.
    #[test]
    fn a_refusal_count_outlives_the_box_but_not_without_limit() {
        let mut p = Provider::with_limits(1, 1 << 20);
        let mut tag = [9u8; MAILBOX_BYTES];
        p.deposit(&tagged(&tag, 1)).unwrap();
        assert_eq!(p.deposit(&tagged(&tag, 2)), Err(DepositError::BoxFull));
        assert_eq!(p.take_one(&tag), (Some(vec![1u8; ENVELOPE_BYTES]), 1));
        assert_eq!(p.boxes(), 1, "the refusal count was dropped with the box");

        for i in 0..(Provider::MAX_REFUSAL_MEMORY as u32 + 64) {
            tag = [0u8; MAILBOX_BYTES];
            tag[..4].copy_from_slice(&i.to_le_bytes());
            p.deposit(&tagged(&tag, 1)).unwrap();
            p.deposit(&tagged(&tag, 2)).ok();
            p.take_one(&tag);
        }
        assert!(p.boxes() <= Provider::MAX_REFUSAL_MEMORY + 1);
        assert!(p.forgotten() > 0, "eviction must be countable, not silent");
    }

    /// A captured drain request must not work twice, and must not work for anyone else.
    ///
    /// The credential used to be the drain secret, sent in the clear on every poll over an
    /// unencrypted UDP link the design already documents as non-anonymous. One passive capture
    /// yielded the credential permanently: replay `REQ_DRAIN` from any address and the provider
    /// pops the victim's mail and hands it over, deleting it from the box the recipient polls.
    #[test]
    fn a_drain_request_authorises_exactly_one_drain() {
        let owner = karst_id::Identity::from_seed([3u8; 32]);
        let pk = owner.key_bytes();
        let tag = crate::client::mailbox_tag(&pk);

        let mut p = Provider::new();
        p.deposit(&tagged(&tag, 1)).unwrap();
        p.deposit(&tagged(&tag, 2)).unwrap();

        let sign = |c: u64| owner.sign(&crate::client::drain_challenge(c)).to_bytes();

        // The honest drain works.
        let s1 = sign(1);
        assert_eq!(p.drain_once(&tag, &pk, 1, &s1).unwrap().0, Some(vec![1u8; ENVELOPE_BYTES]));

        // The identical request, captured off the wire and replayed, does not.
        assert_eq!(p.drain_once(&tag, &pk, 1, &s1), Err(DrainError::Replayed));
        assert_eq!(p.held(), 1, "a replay took a second item");

        // A stranger presenting their own key cannot drain this box, because the tag is the
        // hash of the owner's key and will not match theirs.
        let thief = karst_id::Identity::from_seed([4u8; 32]);
        let ts = thief.sign(&crate::client::drain_challenge(9)).to_bytes();
        assert_eq!(
            p.drain_once(&tag, &thief.key_bytes(), 9, &ts),
            Err(DrainError::NotYours)
        );

        // Nor by claiming the owner's key without the signature to match.
        assert_eq!(p.drain_once(&tag, &pk, 2, &ts), Err(DrainError::NotYours));
        assert_eq!(p.held(), 1);

        // The owner's next counter still works.
        assert!(p.drain_once(&tag, &pk, 2, &sign(2)).unwrap().0.is_some());
    }

    /// Forgetting a counter would make an old request work again, so an emptied box that
    /// remembers one is kept.
    #[test]
    fn an_emptied_box_remembers_what_has_already_been_spent() {
        let owner = karst_id::Identity::from_seed([5u8; 32]);
        let pk = owner.key_bytes();
        let tag = crate::client::mailbox_tag(&pk);
        let sign = |c: u64| owner.sign(&crate::client::drain_challenge(c)).to_bytes();

        let mut p = Provider::new();
        p.deposit(&tagged(&tag, 1)).unwrap();
        assert!(p.drain_once(&tag, &pk, 7, &sign(7)).unwrap().0.is_some());
        assert_eq!(p.held(), 0);

        // New mail arrives at the same tag. The old request must still be dead.
        p.deposit(&tagged(&tag, 2)).unwrap();
        assert_eq!(p.drain_once(&tag, &pk, 7, &sign(7)), Err(DrainError::Replayed));
        assert_eq!(p.held(), 1, "a replayed request stole newly arrived mail");
    }

    #[test]
    fn mail_left_in_a_box_is_there_when_collected() {
        let mut p = Provider::new();
        p.deposit(&payload(1, 10)).unwrap();
        p.deposit(&payload(1, 11)).unwrap();
        p.deposit(&payload(2, 20)).unwrap();

        let c = p.collect(&[1u8; 32]);
        assert_eq!(c.items.len(), 2);
        assert_eq!(c.refused, 0);
        assert_eq!(p.collect(&[2u8; 32]).items.len(), 1);
    }

    /// Collecting empties, so a second collection returns nothing.
    #[test]
    fn collection_empties_the_box() {
        let mut p = Provider::new();
        p.deposit(&payload(1, 10)).unwrap();
        assert_eq!(p.collect(&[1u8; 32]).items.len(), 1);
        assert_eq!(p.collect(&[1u8; 32]).items.len(), 0);
        assert_eq!(p.held(), 0);
    }

    /// An unknown tag must look exactly like an empty box.
    ///
    /// Distinguishing them would let anyone test whether a tag is in use, which is an
    /// enumeration oracle over the provider's users.
    #[test]
    fn an_unknown_tag_is_indistinguishable_from_an_empty_box() {
        let mut p = Provider::new();
        p.deposit(&payload(1, 10)).unwrap();
        let emptied = p.collect(&[1u8; 32]);
        let never_used = p.collect(&[99u8; 32]);
        assert_eq!(p.collect(&[1u8; 32]), never_used);
        assert_eq!(emptied.refused, never_used.refused);
    }

    /// A full box refuses rather than discarding what is already there.
    #[test]
    fn a_full_box_preserves_what_it_holds() {
        let mut p = Provider::with_limits(4, 100);
        for i in 0..4 {
            p.deposit(&payload(1, i)).unwrap();
        }
        assert_eq!(p.deposit(&payload(1, 99)), Err(DepositError::BoxFull));

        let c = p.collect(&[1u8; 32]);
        assert_eq!(c.items.len(), 4);
        // The original four, none replaced.
        for (i, item) in c.items.iter().enumerate() {
            assert_eq!(item[0], i as u8);
        }
    }

    /// Loss must be reported to the owner, not absorbed.
    #[test]
    fn refused_deposits_are_reported_on_collection() {
        let mut p = Provider::with_limits(2, 100);
        p.deposit(&payload(1, 0)).unwrap();
        p.deposit(&payload(1, 1)).unwrap();
        for _ in 0..17 {
            let _ = p.deposit(&payload(1, 2));
        }
        let c = p.collect(&[1u8; 32]);
        assert_eq!(c.items.len(), 2);
        assert_eq!(c.refused, 17, "the owner was not told mail was lost");
    }

    /// One box must not be able to consume the whole provider.
    #[test]
    fn one_box_cannot_exhaust_the_provider() {
        let mut p = Provider::with_limits(8, 32);
        for i in 0..100u8 {
            let _ = p.deposit(&payload(1, i));
        }
        assert_eq!(p.held(), 8);
        // Other boxes still work.
        assert!(p.deposit(&payload(2, 0)).is_ok());
    }

    /// Anything that is not the one size on this network is refused.
    #[test]
    fn wrong_sized_payloads_are_refused() {
        let mut p = Provider::new();
        for n in [0usize, 31, MAILBOX_BYTES, MAILBOX_BYTES + ENVELOPE_BYTES - 1, 4096] {
            assert_eq!(p.deposit(&vec![0u8; n]), Err(DepositError::WrongSize));
        }
        assert_eq!(p.held(), 0);
    }
    /// Reading one item must not destroy the record that mail was lost.
    ///
    /// The design justifies a world-writable feed box on the grounds that denial is visible.
    /// Emptying the box to hand back one item rebuilt it from nothing and zeroed the counter,
    /// so the thing the justification rested on did not survive a single read.
    #[test]
    fn taking_one_item_preserves_the_refusal_count() {
        let mut p = Provider::with_limits(2, 100);
        p.deposit(&payload(1, 0)).unwrap();
        p.deposit(&payload(1, 1)).unwrap();
        for _ in 0..9 {
            let _ = p.deposit(&payload(1, 2));
        }

        let (item, refused) = p.take_one(&[1u8; 32]);
        assert!(item.is_some());
        assert_eq!(refused, 9);
        // And again, still reported.
        let (item, refused) = p.take_one(&[1u8; 32]);
        assert!(item.is_some());
        assert_eq!(refused, 9, "the count was destroyed by reading");
        assert_eq!(p.take_one(&[1u8; 32]).0, None);
    }

    /// Reading a feed must not delete it.
    ///
    /// A feed tag is computable from a public address, so if reading drained the box any
    /// stranger could delete any publication one datagram at a time.
    #[test]
    fn peeking_does_not_drain_a_feed() {
        let mut p = Provider::new();
        for i in 0..5 {
            p.deposit(&payload(9, i)).unwrap();
        }
        let tag = [9u8; 32];
        for _ in 0..100 {
            for i in 0..5 {
                assert!(p.peek(&tag, i).0.is_some(), "an item vanished on read");
            }
        }
        assert_eq!(p.depth(&tag), 5);
        assert_eq!(p.peek(&tag, 5).0, None);
    }

    /// Reading past the end of an unknown box must look like reading an empty one.
    #[test]
    fn peeking_an_unknown_tag_is_indistinguishable_from_an_empty_box() {
        let mut p = Provider::new();
        p.deposit(&payload(1, 0)).unwrap();
        let _ = p.take_one(&[1u8; 32]);
        assert_eq!(p.peek(&[1u8; 32], 0), p.peek(&[123u8; 32], 0));
    }

}
