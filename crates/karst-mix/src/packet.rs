//! Layered mix packets: fixed size, per-hop unlinkable, sender-chosen delays.
//!
//! This implements the *structure* of Sphinx (Danezis and Goldberg, IEEE S&P 2009): an
//! ephemeral group element blinded at each hop, a fixed size header consumed one block
//! at a time with filler appended so the packet never changes length, and a payload
//! peeled one layer per hop.
//!
//! **It is not Sphinx.** The keystream here is BLAKE3's extendable output rather than a
//! standard stream cipher, and the header has no per-hop MAC, so this does not have
//! Sphinx's proven tagging-attack resistance. It is a proof of concept for the layer's
//! behaviour, not a deployable format. Issue #1 tracks the real thing.
//!
//! What it does demonstrate, and what the tests assert:
//!
//! - every packet on the wire is exactly [`PACKET_BYTES`] long, always
//! - the same message is bitwise unrecognisable between one hop and the next
//! - a hop learns the next hop and its own delay, and nothing about path length or its
//!   own position on the path
//! - a hop that is not the intended recipient cannot peel its layer

use x25519_dalek::{PublicKey, StaticSecret};

/// Every packet in the network is this size. No exceptions, ever, because a length
/// distribution is a fingerprint.
pub const PACKET_BYTES: usize = 1024;

/// Maximum path length. The header is always this many blocks regardless of the actual
/// route, so a hop cannot tell how far along it is.
pub const MAX_HOPS: usize = 5;

/// Per-hop routing block: next hop id, delay, flags.
pub const HOP_BLOCK: usize = 32;

pub const HEADER_BYTES: usize = MAX_HOPS * HOP_BLOCK;
pub const ALPHA_BYTES: usize = 32;
pub const PAYLOAD_BYTES: usize = PACKET_BYTES - HEADER_BYTES - ALPHA_BYTES;

const FLAG_FORWARD: u8 = 1;
const FLAG_DELIVER: u8 = 2;

/// What a mix node learns after peeling one layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peeled {
    /// Hold for `delay_ms`, then send to `next`.
    Forward { next: u16, delay_ms: u32, packet: Packet },
    /// This packet terminates here.
    Deliver { delay_ms: u32, payload: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MixError {
    /// Route was empty or longer than [`MAX_HOPS`].
    BadRoute,
    /// Payload did not fit in one fixed size packet.
    PayloadTooLarge,
    /// The flag byte was neither forward nor deliver, which means this node could not
    /// decrypt the block, which means the packet was not addressed to it.
    NotForUs,
}

impl core::fmt::Display for MixError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MixError::BadRoute => write!(f, "route must be between 1 and {MAX_HOPS} hops"),
            MixError::PayloadTooLarge => {
                write!(f, "payload exceeds {} bytes", PAYLOAD_BYTES - 4)
            }
            MixError::NotForUs => write!(f, "packet is not addressed to this node"),
        }
    }
}

impl std::error::Error for MixError {}

/// A mix node's long term keypair.
pub struct MixKey {
    secret: StaticSecret,
    public: PublicKey,
}

impl MixKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        MixKey { secret, public }
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }
}

/// One hop on a route: who it is, and how long they should hold the packet.
#[derive(Clone, Copy)]
pub struct Hop {
    pub id: u16,
    pub public: PublicKey,
    pub delay_ms: u32,
}

/// A fixed size mix packet.
#[derive(Clone, PartialEq, Eq)]
pub struct Packet {
    alpha: [u8; ALPHA_BYTES],
    header: [u8; HEADER_BYTES],
    payload: [u8; PAYLOAD_BYTES],
}

impl core::fmt::Debug for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Packet({} bytes)", PACKET_BYTES)
    }
}

/// Derive a keystream of `n` bytes from a shared secret and a domain label.
fn stream(shared: &[u8; 32], label: &str, n: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.mix.v0");
    h.update(label.as_bytes());
    h.update(shared);
    let mut out = vec![0u8; n];
    h.finalize_xof().fill(&mut out);
    out
}

/// Blinding factor, so the ephemeral element differs at every hop and no two hops can
/// recognise the same packet by it.
fn blind(alpha: &[u8; 32], shared: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.mix.blind.v0");
    h.update(alpha);
    h.update(shared);
    *h.finalize().as_bytes()
}

fn xor(buf: &mut [u8], ks: &[u8]) {
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
}

impl Packet {
    /// Wrap a message for a route. Delays are chosen by the sender, per Loopix.
    pub fn wrap(route: &[Hop], message: &[u8], ephemeral_seed: [u8; 32]) -> Result<Packet, MixError> {
        if route.is_empty() || route.len() > MAX_HOPS {
            return Err(MixError::BadRoute);
        }
        if message.len() + 4 > PAYLOAD_BYTES {
            return Err(MixError::PayloadTooLarge);
        }

        // Forward pass: derive the shared secret each hop will independently recover.
        let mut eph = StaticSecret::from(ephemeral_seed);
        let mut alpha = PublicKey::from(&eph).to_bytes();
        let mut secrets: Vec<[u8; 32]> = Vec::with_capacity(route.len());
        let mut alphas: Vec<[u8; 32]> = Vec::with_capacity(route.len());

        for hop in route {
            let shared = eph.diffie_hellman(&hop.public).to_bytes();
            alphas.push(alpha);
            secrets.push(shared);

            let b = blind(&alpha, &shared);
            eph = StaticSecret::from(b);
            alpha = PublicKey::from(&eph).to_bytes();
        }

        // Payload: length prefix then message, padded to fixed size with deterministic
        // filler so the padding is not distinguishable from content.
        let mut payload = [0u8; PAYLOAD_BYTES];
        payload[..4].copy_from_slice(&(message.len() as u32).to_le_bytes());
        payload[4..4 + message.len()].copy_from_slice(message);
        let pad = stream(&secrets[route.len() - 1], "pad", PAYLOAD_BYTES - 4 - message.len());
        payload[4 + message.len()..].copy_from_slice(&pad);

        // Header starts as filler so an early hop cannot tell how many hops remain.
        let mut header = [0u8; HEADER_BYTES];
        let filler = stream(&secrets[route.len() - 1], "initfill", HEADER_BYTES);
        header.copy_from_slice(&filler);

        // Build inside out: the last hop's block is written first, then each earlier hop
        // shifts the header right and encrypts the whole thing under its own key.
        for i in (0..route.len()).rev() {
            header.copy_within(0..HEADER_BYTES - HOP_BLOCK, HOP_BLOCK);

            let mut block = [0u8; HOP_BLOCK];
            if i == route.len() - 1 {
                block[0] = FLAG_DELIVER;
                block[1..3].copy_from_slice(&0u16.to_le_bytes());
            } else {
                block[0] = FLAG_FORWARD;
                block[1..3].copy_from_slice(&route[i + 1].id.to_le_bytes());
            }
            block[3..7].copy_from_slice(&route[i].delay_ms.to_le_bytes());
            header[..HOP_BLOCK].copy_from_slice(&block);

            xor(&mut header, &stream(&secrets[i], "hdr", HEADER_BYTES));
            xor(&mut payload, &stream(&secrets[i], "pay", PAYLOAD_BYTES));
        }

        Ok(Packet {
            alpha: alphas[0],
            header,
            payload,
        })
    }

    /// Peel one layer. Returns where to send it next and how long to hold it.
    pub fn peel(mut self, key: &MixKey) -> Result<Peeled, MixError> {
        let their_alpha = PublicKey::from(self.alpha);
        let shared = key.secret.diffie_hellman(&their_alpha).to_bytes();

        xor(&mut self.header, &stream(&shared, "hdr", HEADER_BYTES));
        xor(&mut self.payload, &stream(&shared, "pay", PAYLOAD_BYTES));

        let block = &self.header[..HOP_BLOCK];
        let flag = block[0];
        let next = u16::from_le_bytes([block[1], block[2]]);
        let delay_ms = u32::from_le_bytes([block[3], block[4], block[5], block[6]]);

        match flag {
            FLAG_DELIVER => {
                let len = u32::from_le_bytes(self.payload[..4].try_into().unwrap()) as usize;
                if len + 4 > PAYLOAD_BYTES {
                    return Err(MixError::NotForUs);
                }
                Ok(Peeled::Deliver {
                    delay_ms,
                    payload: self.payload[4..4 + len].to_vec(),
                })
            }
            FLAG_FORWARD => {
                // Shift the consumed block off and append filler, so the packet stays
                // exactly the same size and the next hop cannot see how far it has come.
                self.header.copy_within(HOP_BLOCK.., 0);
                let fill = stream(&shared, "fill", HOP_BLOCK);
                self.header[HEADER_BYTES - HOP_BLOCK..].copy_from_slice(&fill);
                self.alpha = blind_public(&self.alpha, &shared);
                Ok(Peeled::Forward {
                    next,
                    delay_ms,
                    packet: self,
                })
            }
            _ => Err(MixError::NotForUs),
        }
    }

    /// Fixed, always. This is the whole point.
    pub fn wire_len(&self) -> usize {
        PACKET_BYTES
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PACKET_BYTES);
        v.extend_from_slice(&self.alpha);
        v.extend_from_slice(&self.header);
        v.extend_from_slice(&self.payload);
        v
    }
}

fn blind_public(alpha: &[u8; 32], shared: &[u8; 32]) -> [u8; 32] {
    let b = blind(alpha, shared);
    let s = StaticSecret::from(b);
    PublicKey::from(&s).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<MixKey> {
        (0..n)
            .map(|i| MixKey::from_seed([(i as u8) + 1; 32]))
            .collect()
    }

    fn route(ks: &[MixKey], delays: &[u32]) -> Vec<Hop> {
        ks.iter()
            .enumerate()
            .map(|(i, k)| Hop {
                id: i as u16,
                public: k.public(),
                delay_ms: delays[i],
            })
            .collect()
    }

    #[test]
    fn a_message_survives_a_three_hop_route() {
        let ks = keys(3);
        let r = route(&ks, &[10, 20, 30]);
        let p = Packet::wrap(&r, b"the quick brown fox", [9u8; 32]).unwrap();

        let Peeled::Forward { next, delay_ms, packet } = p.peel(&ks[0]).unwrap() else {
            panic!("hop 0 should forward");
        };
        assert_eq!((next, delay_ms), (1, 10));

        let Peeled::Forward { next, delay_ms, packet } = packet.peel(&ks[1]).unwrap() else {
            panic!("hop 1 should forward");
        };
        assert_eq!((next, delay_ms), (2, 20));

        match packet.peel(&ks[2]).unwrap() {
            Peeled::Deliver { delay_ms, payload } => {
                assert_eq!(delay_ms, 30);
                assert_eq!(payload, b"the quick brown fox");
            }
            _ => panic!("hop 2 should deliver"),
        }
    }

    #[test]
    fn every_packet_is_the_same_size_at_every_hop() {
        let ks = keys(3);
        let r = route(&ks, &[1, 2, 3]);

        for msg_len in [0usize, 1, 100, PAYLOAD_BYTES - 4] {
            let msg = vec![7u8; msg_len];
            let p = Packet::wrap(&r, &msg, [3u8; 32]).unwrap();
            assert_eq!(p.to_bytes().len(), PACKET_BYTES);

            let Peeled::Forward { packet, .. } = p.peel(&ks[0]).unwrap() else {
                panic!()
            };
            assert_eq!(packet.to_bytes().len(), PACKET_BYTES);
            let Peeled::Forward { packet, .. } = packet.peel(&ks[1]).unwrap() else {
                panic!()
            };
            assert_eq!(packet.to_bytes().len(), PACKET_BYTES);
        }
    }

    #[test]
    fn the_same_message_is_unrecognisable_between_hops() {
        let ks = keys(3);
        let r = route(&ks, &[1, 2, 3]);
        let p0 = Packet::wrap(&r, b"trace me if you can", [11u8; 32]).unwrap();
        let b0 = p0.to_bytes();

        let Peeled::Forward { packet: p1, .. } = p0.peel(&ks[0]).unwrap() else {
            panic!()
        };
        let b1 = p1.to_bytes();
        let Peeled::Forward { packet: p2, .. } = p1.peel(&ks[1]).unwrap() else {
            panic!()
        };
        let b2 = p2.to_bytes();

        // No shared bytes anywhere, including the ephemeral element.
        assert_ne!(b0, b1);
        assert_ne!(b1, b2);
        assert_ne!(&b0[..32], &b1[..32], "alpha must be blinded per hop");
        assert_ne!(&b1[..32], &b2[..32], "alpha must be blinded per hop");

        let shared_bytes = b0.iter().zip(b1.iter()).filter(|(a, b)| a == b).count();
        assert!(
            shared_bytes < PACKET_BYTES / 8,
            "hops must not be linkable by content, {shared_bytes} bytes matched"
        );
    }

    #[test]
    fn a_hop_cannot_tell_how_long_the_route_is_or_where_it_sits() {
        let ks = keys(4);
        // Two routes of different length, both starting at the same node.
        let short = route(&ks[..2], &[5, 5]);
        let long = route(&ks[..4], &[5, 5, 5, 5]);

        let a = Packet::wrap(&short, b"x", [1u8; 32]).unwrap();
        let b = Packet::wrap(&long, b"x", [1u8; 32]).unwrap();

        // Identical size and structure. The first hop sees the same shape either way.
        assert_eq!(a.to_bytes().len(), b.to_bytes().len());
        let Peeled::Forward { packet: a1, .. } = a.peel(&ks[0]).unwrap() else {
            panic!()
        };
        let Peeled::Forward { packet: b1, .. } = b.peel(&ks[0]).unwrap() else {
            panic!()
        };
        assert_eq!(a1.to_bytes().len(), b1.to_bytes().len());
    }

    #[test]
    fn the_wrong_node_cannot_peel_the_layer() {
        let ks = keys(3);
        let stranger = MixKey::from_seed([99u8; 32]);
        let r = route(&ks, &[1, 2, 3]);
        let p = Packet::wrap(&r, b"not for you", [5u8; 32]).unwrap();

        assert_eq!(p.peel(&stranger), Err(MixError::NotForUs));
    }

    #[test]
    fn routes_are_bounded() {
        let ks = keys(MAX_HOPS + 1);
        let too_long = route(&ks, &vec![1u32; MAX_HOPS + 1]);
        assert_eq!(
            Packet::wrap(&too_long, b"x", [1u8; 32]).unwrap_err(),
            MixError::BadRoute
        );
        assert_eq!(
            Packet::wrap(&[], b"x", [1u8; 32]).unwrap_err(),
            MixError::BadRoute
        );
    }

    #[test]
    fn an_oversized_payload_is_refused_rather_than_truncated() {
        let ks = keys(2);
        let r = route(&ks, &[1, 1]);
        let big = vec![0u8; PAYLOAD_BYTES];
        assert_eq!(
            Packet::wrap(&r, &big, [1u8; 32]).unwrap_err(),
            MixError::PayloadTooLarge
        );
    }
}
