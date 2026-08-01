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

use std::collections::{BTreeMap, VecDeque};

use crate::frame::{ENVELOPE_BYTES, MAILBOX_BYTES};

pub type Tag = [u8; MAILBOX_BYTES];

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
}

#[derive(Debug)]
pub struct Provider {
    boxes: BTreeMap<Tag, Box_>,
    per_box: usize,
    total: usize,
    held: usize,
}

impl Provider {
    pub const DEFAULT_PER_BOX: usize = 1024;
    pub const DEFAULT_TOTAL: usize = 1 << 20;

    pub fn new() -> Self {
        Provider {
            boxes: BTreeMap::new(),
            per_box: Self::DEFAULT_PER_BOX,
            total: Self::DEFAULT_TOTAL,
            held: 0,
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
        let b = self.boxes.entry(tag).or_default();
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
                (item, b.refused)
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
