//! Sphinx-format mix packets.
//!
//! This implements the construction of *Sphinx: A Compact and Provably Secure Mix Format*
//! (Danezis and Goldberg, IEEE S&P 2009), which is the format L4 requires rather than one
//! shaped like it.
//!
//! # Why the format matters, concretely
//!
//! In 2014 a Sybil fleet of Tor relays ran a **tagging attack**: they modified protocol
//! headers so that a colluding relay downstream could recognise traffic that had passed a
//! confederate upstream. It worked, and evidence indicates the results reached the FBI.
//!
//! A tagging attack needs two things. The attacker must be able to modify a packet, and the
//! modification must survive to somewhere it can be recognised. Sphinx removes both:
//!
//! - **The header carries a per-hop MAC (γ).** A hop verifies it *before* processing
//!   anything, so a modified header is dropped at the first honest relay rather than
//!   forwarded with a signal in it.
//! - **The payload is encrypted with a wide-block cipher**, not a stream cipher. Under a
//!   stream cipher, flipping bit *k* of the ciphertext flips bit *k* of the plaintext, which
//!   is a perfectly predictable, perfectly recognisable mark. Under a wide-block cipher any
//!   change randomises the entire block, so there is nothing to recognise.
//!
//! The second is the one that is easy to get wrong and easy to miss, because a stream cipher
//! looks like encryption and passes every functional test.
//!
//! # Structure
//!
//! ```text
//!   α (32)  ephemeral group element, re-derived per hop
//!   γ (16)  MAC over β under this hop's key
//!   β (160) routing information, one BLOCK consumed per hop, refilled to constant length
//!   δ (816) payload, wide-block encrypted, one layer peeled per hop
//! ```
//!
//! Each β block is `[routing (16) | γ for the next hop (16)]`, so the MAC chain is carried
//! inside the header the MAC protects.
//!
//! # What this is not
//!
//! Two deviations from the paper, both deliberate and both stated rather than buried:
//!
//! 1. **The group element is re-derived rather than blinded.** Sphinx computes
//!    `α_{i+1} = α_i^{b_i}` in a prime-order group. X25519 clamps scalars, so composing
//!    blindings that way does not behave as the proof assumes. Here each hop derives a fresh
//!    element from the shared secret instead, which preserves per-hop unlinkability and is
//!    not the construction the security proof covers.
//! 2. **Primitives are BLAKE3-based** rather than the paper's. The MAC is a keyed BLAKE3, the
//!    stream is its XOF, and the wide-block cipher is a four-round unbalanced Feistel in the
//!    LIONESS shape rather than LIONESS itself.
//!
//! This is not a reviewed implementation and should not be deployed as one.

use x25519_dalek::{PublicKey, StaticSecret};

/// Every packet in the network is this size. No exceptions, because a length distribution is
/// a fingerprint.
pub const PACKET_BYTES: usize = 1024;

/// Maximum path length. The header is always this many blocks regardless of the actual route,
/// so a hop cannot tell how far along it is.
pub const MAX_HOPS: usize = 5;

/// Routing information per hop.
pub const ROUTING_BYTES: usize = 16;
/// MAC length.
pub const MAC_BYTES: usize = 16;
/// One header slot: routing plus the next hop's MAC.
pub const BLOCK: usize = ROUTING_BYTES + MAC_BYTES;

pub const ALPHA_BYTES: usize = 32;
pub const HEADER_BYTES: usize = MAX_HOPS * BLOCK;
pub const PAYLOAD_BYTES: usize = PACKET_BYTES - ALPHA_BYTES - MAC_BYTES - HEADER_BYTES;

const FLAG_FORWARD: u8 = 1;
const FLAG_DELIVER: u8 = 2;

// ---------------------------------------------------------------- primitives

fn stream(shared: &[u8; 32], label: &str, n: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.sphinx.v1.stream");
    h.update(label.as_bytes());
    h.update(shared);
    let mut out = vec![0u8; n];
    h.finalize_xof().fill(&mut out);
    out
}

fn subkey(shared: &[u8; 32], label: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.sphinx.v1.key");
    h.update(label.as_bytes());
    h.update(shared);
    *h.finalize().as_bytes()
}

/// Keyed MAC over the header. This is the tagging defence: a hop that cannot reproduce it
/// drops the packet instead of forwarding a modified one.
fn mac(key: &[u8; 32], data: &[u8]) -> [u8; MAC_BYTES] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"karst.sphinx.v1.mac");
    h.update(data);
    let full = h.finalize();
    let mut out = [0u8; MAC_BYTES];
    out.copy_from_slice(&full.as_bytes()[..MAC_BYTES]);
    out
}

fn xor(buf: &mut [u8], ks: &[u8]) {
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
}

/// Constant-time comparison, so a hop does not leak where a forged MAC first diverged.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------- wide-block cipher

/// Split point for the unbalanced Feistel. `L` is one hash block, `R` is the rest.
const FEISTEL_L: usize = 32;

/// Four-round unbalanced Feistel in the LIONESS shape, giving a wide-block pseudorandom
/// permutation over the whole payload.
///
/// **This is the property that defeats payload tagging.** A stream cipher would let an
/// attacker flip a chosen plaintext bit by flipping the corresponding ciphertext bit, which
/// is exactly the mark a confederate downstream looks for. Here any single-bit change
/// randomises the entire payload, so a modification produces noise rather than a signal.
fn wide_encrypt(key: &[u8; 32], data: &mut [u8]) {
    if data.len() <= FEISTEL_L {
        // Degenerate width: fall back to a keyed stream over the whole thing. Not reachable
        // with the sizes above, and defined rather than left to panic.
        let ks = stream(key, "narrow", data.len());
        xor(data, &ks);
        return;
    }
    let (l, r) = data.split_at_mut(FEISTEL_L);

    // R ^= S(k1, L)
    let ks = stream(&subkey(key, "f1"), &hex(l), r.len());
    xor(r, &ks);
    // L ^= H(k2, R)
    xor(l, &hash_to(&subkey(key, "f2"), r, FEISTEL_L));
    // R ^= S(k3, L)
    let ks = stream(&subkey(key, "f3"), &hex(l), r.len());
    xor(r, &ks);
    // L ^= H(k4, R)
    xor(l, &hash_to(&subkey(key, "f4"), r, FEISTEL_L));
}

fn wide_decrypt(key: &[u8; 32], data: &mut [u8]) {
    if data.len() <= FEISTEL_L {
        let ks = stream(key, "narrow", data.len());
        xor(data, &ks);
        return;
    }
    let (l, r) = data.split_at_mut(FEISTEL_L);

    xor(l, &hash_to(&subkey(key, "f4"), r, FEISTEL_L));
    let ks = stream(&subkey(key, "f3"), &hex(l), r.len());
    xor(r, &ks);
    xor(l, &hash_to(&subkey(key, "f2"), r, FEISTEL_L));
    let ks = stream(&subkey(key, "f1"), &hex(l), r.len());
    xor(r, &ks);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hash_to(key: &[u8; 32], data: &[u8], n: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(data);
    let mut out = vec![0u8; n];
    h.finalize_xof().fill(&mut out);
    out
}

// ---------------------------------------------------------------- types

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peeled {
    Forward {
        next: u16,
        delay_ms: u32,
        packet: Packet,
    },
    Deliver {
        delay_ms: u32,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MixError {
    BadRoute,
    PayloadTooLarge,
    /// The header MAC did not verify. Either the packet was not addressed to this node, or it
    /// was modified in flight. **A hop cannot tell which, and must not try**: distinguishing
    /// them would itself be an oracle.
    BadMac,
    /// This packet has been seen before.
    Replay,
    /// The routing block did not decode.
    Malformed,
}

impl core::fmt::Display for MixError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MixError::BadRoute => write!(f, "route must be between 1 and {MAX_HOPS} hops"),
            MixError::PayloadTooLarge => {
                write!(f, "payload exceeds {} bytes", PAYLOAD_BYTES - 4)
            }
            MixError::BadMac => write!(f, "header MAC did not verify"),
            MixError::Replay => write!(f, "packet already seen"),
            MixError::Malformed => write!(f, "malformed routing block"),
        }
    }
}

impl std::error::Error for MixError {}

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

#[derive(Clone, Copy)]
pub struct Hop {
    pub id: u16,
    pub public: PublicKey,
    pub delay_ms: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Packet {
    alpha: [u8; ALPHA_BYTES],
    gamma: [u8; MAC_BYTES],
    beta: [u8; HEADER_BYTES],
    delta: Vec<u8>,
}

impl core::fmt::Debug for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Packet({PACKET_BYTES} bytes)")
    }
}

/// Replay detection. Sphinx provides the tag; storing it is the node's job.
#[derive(Default)]
pub struct SeenTags {
    tags: std::collections::BTreeSet<[u8; 16]>,
}

impl SeenTags {
    pub fn new() -> Self {
        SeenTags::default()
    }
    pub fn len(&self) -> usize {
        self.tags.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
    fn check_and_insert(&mut self, tag: [u8; 16]) -> bool {
        self.tags.insert(tag)
    }
}

fn routing_block(flag: u8, next: u16, delay_ms: u32) -> [u8; ROUTING_BYTES] {
    let mut b = [0u8; ROUTING_BYTES];
    b[0] = flag;
    b[1..3].copy_from_slice(&next.to_le_bytes());
    b[3..7].copy_from_slice(&delay_ms.to_le_bytes());
    b
}

impl Packet {
    /// Derive the per-hop shared secrets the sender needs, and the element each hop sees.
    fn derive_path(route: &[Hop], seed: [u8; 32]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let mut eph = StaticSecret::from(seed);
        let mut alpha = PublicKey::from(&eph).to_bytes();
        let mut secrets = Vec::with_capacity(route.len());
        let mut alphas = Vec::with_capacity(route.len());

        for hop in route {
            let shared = eph.diffie_hellman(&hop.public).to_bytes();
            alphas.push(alpha);
            secrets.push(shared);

            eph = StaticSecret::from(subkey(&shared, "next"));
            alpha = PublicKey::from(&eph).to_bytes();
        }
        (secrets, alphas)
    }

    /// The filler that keeps β at constant length while hiding path length and position.
    ///
    /// Each hop shifts a block off the front and appends keystream to the back. The sender
    /// must precompute exactly the keystream those hops will append, so that the header a hop
    /// reconstructs is the one the sender encrypted for the next hop.
    fn filler(secrets: &[[u8; 32]]) -> Vec<u8> {
        let mut phi: Vec<u8> = Vec::new();
        for s in secrets.iter().take(secrets.len().saturating_sub(1)) {
            phi.extend_from_slice(&[0u8; BLOCK]);
            let rho = stream(s, "rho", HEADER_BYTES + BLOCK);
            let start = HEADER_BYTES + BLOCK - phi.len();
            let tail: Vec<u8> = rho[start..].to_vec();
            xor(&mut phi, &tail);
        }
        phi
    }

    /// Wrap a message for a route. Delays are chosen by the sender, per Loopix.
    pub fn wrap(route: &[Hop], message: &[u8], seed: [u8; 32]) -> Result<Packet, MixError> {
        let n = route.len();
        if n == 0 || n > MAX_HOPS {
            return Err(MixError::BadRoute);
        }
        if message.len() + 4 > PAYLOAD_BYTES {
            return Err(MixError::PayloadTooLarge);
        }

        let (secrets, alphas) = Self::derive_path(route, seed);

        // Payload: length prefix, message, deterministic padding. Encrypted from the inside
        // out so each hop peels exactly one layer.
        let mut delta = vec![0u8; PAYLOAD_BYTES];
        delta[..4].copy_from_slice(&(message.len() as u32).to_le_bytes());
        delta[4..4 + message.len()].copy_from_slice(message);
        let pad = stream(&secrets[n - 1], "pad", PAYLOAD_BYTES - 4 - message.len());
        delta[4 + message.len()..].copy_from_slice(&pad);
        for s in secrets.iter().take(n).rev() {
            wide_encrypt(&subkey(s, "pi"), &mut delta);
        }

        // Header, built from the last hop backwards.
        let phi = Self::filler(&secrets);
        let last_len = HEADER_BYTES - phi.len();

        let mut beta = vec![0u8; last_len];
        beta[..ROUTING_BYTES].copy_from_slice(&routing_block(FLAG_DELIVER, 0, route[n - 1].delay_ms));
        // The next-MAC slot is zero at the final hop, and the remainder is deterministic
        // padding so the header carries no structure a hop could read.
        let tail_pad = stream(&secrets[n - 1], "hpad", last_len - BLOCK);
        beta[BLOCK..].copy_from_slice(&tail_pad);
        xor(&mut beta, &stream(&secrets[n - 1], "rho", last_len));
        beta.extend_from_slice(&phi);

        let mut gamma = mac(&subkey(&secrets[n - 1], "mu"), &beta);

        for i in (0..n - 1).rev() {
            let mut nb = vec![0u8; HEADER_BYTES];
            nb[..ROUTING_BYTES]
                .copy_from_slice(&routing_block(FLAG_FORWARD, route[i + 1].id, route[i].delay_ms));
            nb[ROUTING_BYTES..BLOCK].copy_from_slice(&gamma);
            nb[BLOCK..].copy_from_slice(&beta[..HEADER_BYTES - BLOCK]);
            xor(&mut nb, &stream(&secrets[i], "rho", HEADER_BYTES));
            beta = nb;
            gamma = mac(&subkey(&secrets[i], "mu"), &beta);
        }

        let mut beta_arr = [0u8; HEADER_BYTES];
        beta_arr.copy_from_slice(&beta);

        Ok(Packet {
            alpha: alphas[0],
            gamma,
            beta: beta_arr,
            delta,
        })
    }

    /// Peel one layer.
    ///
    /// The MAC is verified **before** anything else is trusted. A packet that fails is
    /// dropped, which is what stops a tagging attack: a modified header never reaches a
    /// confederate downstream to be recognised.
    pub fn peel(mut self, key: &MixKey, seen: &mut SeenTags) -> Result<Peeled, MixError> {
        let shared = key
            .secret
            .diffie_hellman(&PublicKey::from(self.alpha))
            .to_bytes();

        // 1. Integrity, first.
        let expected = mac(&subkey(&shared, "mu"), &self.beta);
        if !ct_eq(&expected, &self.gamma) {
            return Err(MixError::BadMac);
        }

        // 2. Replay, second. Both must precede any processing.
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&subkey(&shared, "tag")[..16]);
        if !seen.check_and_insert(tag) {
            return Err(MixError::Replay);
        }

        // 3. Peel the payload. Any modification randomises it rather than marking it.
        wide_decrypt(&subkey(&shared, "pi"), &mut self.delta);

        // 4. Shift the header, refilling to constant length.
        let mut padded = vec![0u8; HEADER_BYTES + BLOCK];
        padded[..HEADER_BYTES].copy_from_slice(&self.beta);
        xor(&mut padded, &stream(&shared, "rho", HEADER_BYTES + BLOCK));

        let flag = padded[0];
        let next = u16::from_le_bytes([padded[1], padded[2]]);
        let delay_ms = u32::from_le_bytes([padded[3], padded[4], padded[5], padded[6]]);

        match flag {
            FLAG_DELIVER => {
                let len = u32::from_le_bytes(self.delta[..4].try_into().unwrap()) as usize;
                if len + 4 > PAYLOAD_BYTES {
                    return Err(MixError::Malformed);
                }
                Ok(Peeled::Deliver {
                    delay_ms,
                    payload: self.delta[4..4 + len].to_vec(),
                })
            }
            FLAG_FORWARD => {
                let mut next_gamma = [0u8; MAC_BYTES];
                next_gamma.copy_from_slice(&padded[ROUTING_BYTES..BLOCK]);
                let mut next_beta = [0u8; HEADER_BYTES];
                next_beta.copy_from_slice(&padded[BLOCK..BLOCK + HEADER_BYTES]);

                Ok(Peeled::Forward {
                    next,
                    delay_ms,
                    packet: Packet {
                        alpha: PublicKey::from(&StaticSecret::from(subkey(&shared, "next")))
                            .to_bytes(),
                        gamma: next_gamma,
                        beta: next_beta,
                        delta: self.delta,
                    },
                })
            }
            _ => Err(MixError::Malformed),
        }
    }

    pub fn wire_len(&self) -> usize {
        PACKET_BYTES
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PACKET_BYTES);
        v.extend_from_slice(&self.alpha);
        v.extend_from_slice(&self.gamma);
        v.extend_from_slice(&self.beta);
        v.extend_from_slice(&self.delta);
        v
    }

    /// Flip one bit of the payload, as an attacker on the wire would.
    #[doc(hidden)]
    pub fn tamper_payload(&self, bit: usize) -> Packet {
        let mut c = self.clone();
        c.delta[(bit / 8) % PAYLOAD_BYTES] ^= 1 << (bit % 8);
        c
    }

    /// Flip one bit of the header.
    #[doc(hidden)]
    pub fn tamper_header(&self, bit: usize) -> Packet {
        let mut c = self.clone();
        c.beta[(bit / 8) % HEADER_BYTES] ^= 1 << (bit % 8);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<MixKey> {
        (0..n).map(|i| MixKey::from_seed([(i as u8) + 1; 32])).collect()
    }

    fn route(ks: &[MixKey]) -> Vec<Hop> {
        ks.iter()
            .enumerate()
            .map(|(i, k)| Hop {
                id: i as u16,
                public: k.public(),
                delay_ms: 10 * (i as u32 + 1),
            })
            .collect()
    }

    /// Walk a packet to its destination, returning the delivered payload.
    fn deliver(ks: &[MixKey], p: Packet) -> Result<Vec<u8>, MixError> {
        let mut seen: Vec<SeenTags> = (0..ks.len()).map(|_| SeenTags::new()).collect();
        let mut cur = p;
        for i in 0..ks.len() {
            match cur.peel(&ks[i], &mut seen[i])? {
                Peeled::Forward { next, packet, .. } => {
                    assert_eq!(next as usize, i + 1, "routed to the wrong hop");
                    cur = packet;
                }
                Peeled::Deliver { payload, .. } => return Ok(payload),
            }
        }
        Err(MixError::Malformed)
    }

    #[test]
    fn routes_of_every_length_deliver() {
        for n in 1..=MAX_HOPS {
            let ks = keys(n);
            let r = route(&ks);
            let msg = format!("message over {n} hops");
            let p = Packet::wrap(&r, msg.as_bytes(), [9u8; 32]).unwrap();
            assert_eq!(
                deliver(&ks, p).unwrap(),
                msg.as_bytes(),
                "{n} hop route failed"
            );
        }
    }

    #[test]
    fn delays_arrive_at_the_right_hops() {
        let ks = keys(3);
        let r = route(&ks);
        let p = Packet::wrap(&r, b"x", [1u8; 32]).unwrap();
        let mut seen: Vec<SeenTags> = (0..3).map(|_| SeenTags::new()).collect();

        let Peeled::Forward { delay_ms, packet, .. } = p.peel(&ks[0], &mut seen[0]).unwrap() else {
            panic!()
        };
        assert_eq!(delay_ms, 10);
        let Peeled::Forward { delay_ms, packet, .. } =
            packet.peel(&ks[1], &mut seen[1]).unwrap()
        else {
            panic!()
        };
        assert_eq!(delay_ms, 20);
        let Peeled::Deliver { delay_ms, .. } = packet.peel(&ks[2], &mut seen[2]).unwrap() else {
            panic!()
        };
        assert_eq!(delay_ms, 30);
    }

    #[test]
    fn every_packet_is_the_same_size_at_every_hop() {
        let ks = keys(4);
        let r = route(&ks);
        for len in [0usize, 1, 100, PAYLOAD_BYTES - 4] {
            let mut cur = Packet::wrap(&r, &vec![7u8; len], [3u8; 32]).unwrap();
            assert_eq!(cur.to_bytes().len(), PACKET_BYTES);
            let mut seen: Vec<SeenTags> = (0..4).map(|_| SeenTags::new()).collect();
            for i in 0..3 {
                let Peeled::Forward { packet, .. } = cur.peel(&ks[i], &mut seen[i]).unwrap()
                else {
                    panic!()
                };
                assert_eq!(packet.to_bytes().len(), PACKET_BYTES);
                cur = packet;
            }
        }
    }

    #[test]
    fn the_same_message_is_unrecognisable_between_hops() {
        let ks = keys(3);
        let r = route(&ks);
        let p = Packet::wrap(&r, b"trace me if you can", [11u8; 32]).unwrap();
        let mut seen: Vec<SeenTags> = (0..3).map(|_| SeenTags::new()).collect();

        let b0 = p.to_bytes();
        let Peeled::Forward { packet: p1, .. } = p.peel(&ks[0], &mut seen[0]).unwrap() else {
            panic!()
        };
        let b1 = p1.to_bytes();
        let Peeled::Forward { packet: p2, .. } = p1.peel(&ks[1], &mut seen[1]).unwrap() else {
            panic!()
        };
        let b2 = p2.to_bytes();

        for (x, y) in [(&b0, &b1), (&b1, &b2)] {
            let shared = x.iter().zip(y.iter()).filter(|(a, b)| a == b).count();
            assert!(
                shared < PACKET_BYTES / 8,
                "hops linkable by content: {shared} bytes matched"
            );
        }
        assert_ne!(&b0[..32], &b1[..32], "alpha must change per hop");
    }

    /// **The tagging defence, header half.** A modified header is dropped at the first honest
    /// hop rather than forwarded carrying a mark.
    #[test]
    fn any_header_modification_is_rejected() {
        let ks = keys(3);
        let r = route(&ks);
        let p = Packet::wrap(&r, b"payload", [5u8; 32]).unwrap();

        for bit in [0usize, 1, 7, 63, 128, 511, 1023] {
            let mut seen = SeenTags::new();
            assert_eq!(
                p.tamper_header(bit).peel(&ks[0], &mut seen),
                Err(MixError::BadMac),
                "header bit {bit} was not caught"
            );
        }
    }

    /// **The tagging defence, payload half, and the one a stream cipher fails.**
    ///
    /// Under a stream cipher, flipping ciphertext bit *k* flips plaintext bit *k*: a
    /// predictable mark a confederate recognises. Under a wide-block cipher the whole payload
    /// randomises, so a modification produces noise carrying no signal.
    #[test]
    fn a_payload_modification_randomises_rather_than_marking() {
        let ks = keys(3);
        let r = route(&ks);
        let msg = vec![0xAAu8; 200];
        let clean = Packet::wrap(&r, &msg, [5u8; 32]).unwrap();

        let honest = deliver(&ks, clean.clone()).unwrap();
        assert_eq!(honest, msg);

        // Flip one bit in flight. The payload MAC-free by design, so it is not dropped, and
        // what arrives must bear no usable relationship to what was sent.
        let tampered = clean.tamper_payload(64);
        match deliver(&ks, tampered) {
            Err(_) => {} // a randomised length prefix usually fails to decode, which is fine
            Ok(out) => {
                let matching = out.iter().zip(msg.iter()).filter(|(a, b)| a == b).count();
                let expected_by_chance = out.len() / 256 + 8;
                assert!(
                    matching <= expected_by_chance,
                    "payload change was predictable: {matching} of {} bytes survived",
                    out.len()
                );
            }
        }
    }

    /// A single flipped bit must diffuse across the entire payload. This is the property a
    /// stream cipher lacks and the reason the wide-block construction is there.
    #[test]
    fn one_flipped_bit_diffuses_across_the_whole_payload() {
        let key = [7u8; 32];
        let mut a = vec![0u8; PAYLOAD_BYTES];
        let mut b = a.clone();
        b[500] ^= 1;

        wide_decrypt(&key, &mut a);
        wide_decrypt(&key, &mut b);

        let differing = a.iter().zip(b.iter()).filter(|(x, y)| x != y).count();
        assert!(
            differing > PAYLOAD_BYTES / 2,
            "only {differing} of {PAYLOAD_BYTES} bytes changed, so the change is localisable"
        );
    }

    #[test]
    fn the_wide_block_cipher_round_trips() {
        let key = [3u8; 32];
        for len in [FEISTEL_L + 1, 100, PAYLOAD_BYTES] {
            let original: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let mut buf = original.clone();
            wide_encrypt(&key, &mut buf);
            assert_ne!(buf, original, "encryption is a no-op at len {len}");
            wide_decrypt(&key, &mut buf);
            assert_eq!(buf, original, "round trip failed at len {len}");
        }
    }

    #[test]
    fn a_replayed_packet_is_rejected() {
        let ks = keys(3);
        let r = route(&ks);
        let p = Packet::wrap(&r, b"once", [5u8; 32]).unwrap();
        let mut seen = SeenTags::new();

        assert!(p.clone().peel(&ks[0], &mut seen).is_ok());
        assert_eq!(p.peel(&ks[0], &mut seen), Err(MixError::Replay));
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn the_wrong_node_cannot_peel_the_layer() {
        let ks = keys(3);
        let stranger = MixKey::from_seed([99u8; 32]);
        let r = route(&ks);
        let p = Packet::wrap(&r, b"not for you", [5u8; 32]).unwrap();
        let mut seen = SeenTags::new();
        assert_eq!(p.peel(&stranger, &mut seen), Err(MixError::BadMac));
    }

    #[test]
    fn a_hop_cannot_tell_how_long_the_route_is() {
        let ks = keys(5);
        let mut seen: Vec<SeenTags> = (0..2).map(|_| SeenTags::new()).collect();

        let short = Packet::wrap(&route(&ks[..2]), b"x", [1u8; 32]).unwrap();
        let long = Packet::wrap(&route(&ks[..5]), b"x", [1u8; 32]).unwrap();
        assert_eq!(short.to_bytes().len(), long.to_bytes().len());

        let Peeled::Forward { packet: a, .. } = short.peel(&ks[0], &mut seen[0]).unwrap() else {
            panic!()
        };
        let Peeled::Forward { packet: b, .. } = long.peel(&ks[0], &mut seen[1]).unwrap() else {
            panic!()
        };
        assert_eq!(a.to_bytes().len(), b.to_bytes().len());
    }

    #[test]
    fn routes_are_bounded() {
        let ks = keys(MAX_HOPS + 1);
        assert_eq!(
            Packet::wrap(&route(&ks), b"x", [1u8; 32]).unwrap_err(),
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
        assert_eq!(
            Packet::wrap(&route(&ks), &vec![0u8; PAYLOAD_BYTES], [1u8; 32]).unwrap_err(),
            MixError::PayloadTooLarge
        );
    }
}
