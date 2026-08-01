//! Messages, cut to fit a packet.
//!
//! # Everything is the same size
//!
//! A Sphinx payload carries a length prefix, so the hop where a packet terminates learns how
//! many bytes the sender meant. For a provider holding mail on someone's behalf that is a
//! sizeable leak: message length is a strong fingerprint, and lengths across a conversation
//! are stronger still.
//!
//! So a fragment always fills the payload. Padding lives **inside** the sealed blob, where the
//! provider cannot see it and cannot strip it. Every fragment on the wire, in a provider's
//! store, and in transit is exactly `FRAGMENT_BYTES`, and a one byte message costs the same as
//! a full one.
//!
//! What this does not hide is the **number** of fragments, which is message length rounded up
//! to the fragment size. A sender wanting that concealed pads to a fixed fragment count, and
//! that is a choice at a higher layer because only the sender knows what it is worth.

use karst_mix::packet::PAYLOAD_BYTES;

/// Bytes usable in a delivered payload, once Sphinx has taken its length prefix.
pub const FRAGMENT_BYTES: usize = PAYLOAD_BYTES - 4;

/// The mailbox a fragment is filed under, in clear, because a provider must read it to file it.
pub const MAILBOX_BYTES: usize = 32;

/// Space for the sealed blob.
pub const SEALED_BYTES: usize = FRAGMENT_BYTES - MAILBOX_BYTES;

/// Space for the fragment once sealing has taken its overhead.
pub const INNER_BYTES: usize = SEALED_BYTES - karst_seal::OVERHEAD;

/// Header inside the sealed blob: message id, index, total, and the used length.
pub const INNER_HEADER: usize = 16 + 2 + 2 + 2;

/// Message bytes carried by one fragment.
pub const DATA_BYTES: usize = INNER_BYTES - INNER_HEADER;

/// The most fragments one message may have.
///
/// Bounded so that a reassembly buffer cannot be inflated by a claim. A sender with more to say
/// than this uses L6, where large content belongs.
pub const MAX_FRAGMENTS: u16 = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    Malformed,
    /// Fragments claiming to belong to the same message disagree about it.
    Inconsistent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub msg_id: [u8; 16],
    pub index: u16,
    pub total: u16,
    pub data: Vec<u8>,
}

impl Fragment {
    /// Serialise to exactly `INNER_BYTES`, padded.
    pub fn encode(&self) -> [u8; INNER_BYTES] {
        let mut out = [0u8; INNER_BYTES];
        out[..16].copy_from_slice(&self.msg_id);
        out[16..18].copy_from_slice(&self.index.to_le_bytes());
        out[18..20].copy_from_slice(&self.total.to_le_bytes());
        out[20..22].copy_from_slice(&(self.data.len() as u16).to_le_bytes());
        out[INNER_HEADER..INNER_HEADER + self.data.len()].copy_from_slice(&self.data);
        // The remainder stays zero. It is inside the sealed blob, so it is not visible to
        // anyone who could learn anything from it.
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Fragment, FrameError> {
        if bytes.len() != INNER_BYTES {
            return Err(FrameError::Malformed);
        }
        let mut msg_id = [0u8; 16];
        msg_id.copy_from_slice(&bytes[..16]);
        let index = u16::from_le_bytes([bytes[16], bytes[17]]);
        let total = u16::from_le_bytes([bytes[18], bytes[19]]);
        let len = u16::from_le_bytes([bytes[20], bytes[21]]) as usize;
        if total == 0 || total > MAX_FRAGMENTS || index >= total || len > DATA_BYTES {
            return Err(FrameError::Malformed);
        }
        Ok(Fragment {
            msg_id,
            index,
            total,
            data: bytes[INNER_HEADER..INNER_HEADER + len].to_vec(),
        })
    }
}

/// Cut a message into fragments.
pub fn split(msg_id: [u8; 16], message: &[u8]) -> Result<Vec<Fragment>, FrameError> {
    let total = message.len().div_ceil(DATA_BYTES).max(1);
    if total > MAX_FRAGMENTS as usize {
        return Err(FrameError::TooLarge);
    }
    Ok(message
        .chunks(DATA_BYTES)
        .chain(if message.is_empty() {
            Some(&[][..])
        } else {
            None
        })
        .enumerate()
        .map(|(i, c)| Fragment {
            msg_id,
            index: i as u16,
            total: total as u16,
            data: c.to_vec(),
        })
        .collect())
}

/// Collect fragments until a message is whole.
#[derive(Debug, Default)]
pub struct Reassembler {
    partial: std::collections::BTreeMap<[u8; 16], Partial>,
    capacity: usize,
}

#[derive(Debug)]
struct Partial {
    total: u16,
    parts: std::collections::BTreeMap<u16, Vec<u8>>,
}

impl Reassembler {
    /// How many part-built messages to track at once.
    ///
    /// An adversary who can reach this buffer creates one entry per message id they invent, so
    /// the bound is what stops a stranger's first fragments from exhausting memory. Oldest
    /// goes first, because a message that has been incomplete longest is the one least likely
    /// to complete.
    pub const DEFAULT_CAPACITY: usize = 256;

    pub fn new() -> Self {
        Reassembler {
            partial: Default::default(),
            capacity: Self::DEFAULT_CAPACITY,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Reassembler {
            partial: Default::default(),
            capacity,
        }
    }

    pub fn tracking(&self) -> usize {
        self.partial.len()
    }

    /// Take a fragment. Returns the message if that was the last one missing.
    pub fn accept(&mut self, f: Fragment) -> Result<Option<Vec<u8>>, FrameError> {
        if f.total == 0 || f.total > MAX_FRAGMENTS || f.index >= f.total {
            return Err(FrameError::Malformed);
        }
        if !self.partial.contains_key(&f.msg_id) && self.partial.len() >= self.capacity {
            let oldest = *self.partial.keys().next().expect("non-empty");
            self.partial.remove(&oldest);
        }

        let e = self.partial.entry(f.msg_id).or_insert_with(|| Partial {
            total: f.total,
            parts: Default::default(),
        });
        if e.total != f.total {
            // Two fragments under one id disagreeing about the message is either corruption
            // or an attempt to confuse reassembly. Neither is worth keeping.
            self.partial.remove(&f.msg_id);
            return Err(FrameError::Inconsistent);
        }
        // First writer wins. A later fragment must not overwrite an earlier one, or anybody
        // who learns a message id can rewrite a message already in flight.
        e.parts.entry(f.index).or_insert(f.data);

        if e.parts.len() == e.total as usize {
            let done = self.partial.remove(&f.msg_id).expect("just checked");
            let mut out = Vec::new();
            for (_, part) in done.parts {
                out.extend_from_slice(&part);
            }
            return Ok(Some(out));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: &[u8]) -> Vec<u8> {
        let frags = split([1u8; 16], msg).unwrap();
        let mut r = Reassembler::new();
        let mut out = None;
        for f in frags {
            let wire = f.encode();
            assert_eq!(wire.len(), INNER_BYTES, "a fragment was not full size");
            let back = Fragment::decode(&wire).unwrap();
            if let Some(m) = r.accept(back).unwrap() {
                out = Some(m);
            }
        }
        out.expect("never completed")
    }

    #[test]
    fn messages_of_every_shape_round_trip() {
        assert_eq!(round_trip(b""), b"");
        assert_eq!(round_trip(b"hello"), b"hello");
        let big: Vec<u8> = (0..DATA_BYTES * 7 + 13).map(|i| (i % 251) as u8).collect();
        assert_eq!(round_trip(&big), big);
        let exact: Vec<u8> = vec![9u8; DATA_BYTES * 3];
        assert_eq!(round_trip(&exact), exact);
    }

    /// Every fragment on the wire is the same size regardless of the message.
    #[test]
    fn a_one_byte_message_looks_exactly_like_a_full_one() {
        let a = split([1u8; 16], b"x").unwrap()[0].encode();
        let b = split([2u8; 16], &vec![7u8; DATA_BYTES]).unwrap()[0].encode();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), INNER_BYTES);
    }

    /// Fragments arriving in any order must reassemble the same.
    #[test]
    fn order_does_not_matter() {
        let big: Vec<u8> = (0..DATA_BYTES * 5).map(|i| (i % 251) as u8).collect();
        let mut frags = split([3u8; 16], &big).unwrap();
        frags.reverse();
        let mut r = Reassembler::new();
        let mut out = None;
        for f in frags {
            if let Some(m) = r.accept(f).unwrap() {
                out = Some(m);
            }
        }
        assert_eq!(out.unwrap(), big);
    }

    /// A duplicate fragment must not be able to rewrite one already held.
    ///
    /// Anyone who learns a message id would otherwise be able to substitute content into a
    /// message in flight, and the recipient would reassemble it without noticing.
    #[test]
    fn a_later_fragment_cannot_overwrite_an_earlier_one() {
        let big: Vec<u8> = vec![1u8; DATA_BYTES * 2];
        let frags = split([4u8; 16], &big).unwrap();
        let mut r = Reassembler::new();
        r.accept(frags[0].clone()).unwrap();

        let mut forged = frags[0].clone();
        forged.data = vec![0xFF; DATA_BYTES];
        r.accept(forged).unwrap();

        let out = r.accept(frags[1].clone()).unwrap().unwrap();
        assert_eq!(out, big, "a forged duplicate replaced genuine content");
    }

    /// Fragments disagreeing about the message they belong to must be rejected.
    #[test]
    fn inconsistent_totals_are_refused() {
        let mut r = Reassembler::new();
        let base = Fragment {
            msg_id: [5u8; 16],
            index: 0,
            total: 4,
            data: vec![1],
        };
        r.accept(base.clone()).unwrap();
        let mut lying = base.clone();
        lying.total = 9;
        lying.index = 1;
        assert_eq!(r.accept(lying), Err(FrameError::Inconsistent));
    }

    /// A claimed fragment count must not be able to reserve memory.
    #[test]
    fn an_absurd_fragment_count_is_refused() {
        let mut r = Reassembler::new();
        assert_eq!(
            r.accept(Fragment {
                msg_id: [6u8; 16],
                index: 0,
                total: u16::MAX,
                data: vec![],
            }),
            Err(FrameError::Malformed)
        );
        assert_eq!(r.tracking(), 0);
    }

    /// Half-built messages from strangers must not accumulate without bound.
    #[test]
    fn incomplete_messages_do_not_accumulate_without_bound() {
        let mut r = Reassembler::with_capacity(16);
        for i in 0..10_000u32 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_le_bytes());
            r.accept(Fragment {
                msg_id: id,
                index: 0,
                total: 8,
                data: vec![1],
            })
            .unwrap();
        }
        assert_eq!(r.tracking(), 16);
    }

    /// A decoder must reject anything that is not exactly a fragment.
    #[test]
    fn short_and_long_encodings_are_refused() {
        let good = Fragment {
            msg_id: [7u8; 16],
            index: 0,
            total: 1,
            data: vec![1, 2, 3],
        }
        .encode();
        for n in [0usize, 1, INNER_HEADER, INNER_BYTES - 1] {
            assert_eq!(Fragment::decode(&good[..n]), Err(FrameError::Malformed));
        }
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(Fragment::decode(&long), Err(FrameError::Malformed));
    }

    /// A length field claiming more than the fragment holds must be refused.
    #[test]
    fn an_overlong_length_field_is_refused() {
        let mut bytes = Fragment {
            msg_id: [8u8; 16],
            index: 0,
            total: 1,
            data: vec![1],
        }
        .encode();
        bytes[20..22].copy_from_slice(&(DATA_BYTES as u16 + 1).to_le_bytes());
        assert_eq!(Fragment::decode(&bytes), Err(FrameError::Malformed));
    }
}
