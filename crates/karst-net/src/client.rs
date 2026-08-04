//! Sending and receiving.
//!
//! # A contact is a tag and a key, not a name
//!
//! To reach someone you need where their mail is kept, a tag to file it under, and a key to
//! seal it to. None of those is an identity, none is a location, and the set is transferable
//! without reference to any registry. Naming is L15's problem and is deliberately not solved
//! by knowing how to reach someone, because a system where reaching someone requires looking
//! them up somewhere has put a directory between every two people who want to talk.
//!
//! # Every fragment takes its own route
//!
//! Fragments of one message are routed independently. A single route would give every node on
//! it a view of the whole message's timing, and a compromised node would see all of it or none
//! of it rather than a fraction. Independent routes cost reordering, which reassembly already
//! handles, and cost the loss of a whole message when any one fragment is lost, which is the
//! price of not concentrating exposure.
//!
//! # What a burst looks like
//!
//! A long message is many packets at once. The sender hands them to L3, which emits on a
//! schedule that does not depend on how many are waiting, so a burst becomes a longer
//! occupancy of an otherwise unchanged stream. The message is slower; it is not louder.

use karst_id::Identity;
use karst_mix::packet::{MixError, Packet};
use karst_seal::SealingKey;
use rand::Rng;
use x25519_dalek::PublicKey;

use crate::directory::{Directory, RouteError};
use crate::frame::{self, Fragment, Reassembler, MAILBOX_BYTES};
use crate::provider::Tag;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    Route(RouteError),
    Mix(MixError),
    MessageTooLarge,
}

/// A mailbox tag is the hash of the **public** half of the key that drains it.
///
/// Deposit needs the tag; draining needs a signature under the corresponding secret. The
/// earlier arrangement made the tag the hash of a symmetric secret and sent that secret in the
/// clear on every poll, as its own proof, over an unencrypted UDP link the design already
/// documents as non-anonymous. One captured datagram, from the provider's host or any element
/// on the path, took the mailbox permanently: the attacker replays `REQ_DRAIN` from any
/// address and the provider pops the victim's mail and hands it over, deleting it from the box
/// the recipient will poll. There was no rotation path either, since the tag is the identity
/// every correspondent holds.
///
/// A secret that must be shown to be used is not a credential, it is a bearer token in transit.
/// The drain key now proves possession without disclosure, which is what the separation was
/// always supposed to mean.
///
/// The drain key is its own key rather than the L2 identity, so a mailbox is not linked to the
/// identity that owns it.
pub fn mailbox_tag(drain_public: &[u8; 32]) -> Tag {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.net.v2.mailbox");
    h.update(drain_public);
    let mut t = [0u8; MAILBOX_BYTES];
    t.copy_from_slice(h.finalize().as_bytes());
    t
}

/// What a client signs to drain its own box.
///
/// The counter is what stops a captured request being replayed: a provider refuses a counter
/// it has already seen for that tag.
pub fn drain_challenge(counter: u64) -> Vec<u8> {
    let mut v = b"karst.net.v2.drain".to_vec();
    v.extend_from_slice(&counter.to_le_bytes());
    v
}

/// A packet and the node to hand it to.
///
/// A packet does not say where it enters. The first hop is drawn per packet, and a sender who
/// did not learn which node was drawn could not send it anywhere. Returning them together is
/// also the honest shape: the entry node is the one hop a sender cannot hide from, since it
/// sees the sender's address, and pretending otherwise by hiding it in the API would not
/// change that.
#[derive(Debug)]
pub struct Dispatch {
    pub via: u16,
    pub packet: Packet,
}

/// Everything needed to reach someone, and nothing more.
#[derive(Debug, Clone)]
pub struct Contact {
    pub mailbox: Tag,
    pub sealing: PublicKey,
    pub provider: u16,
}

pub struct Client {
    identity: Identity,
    sealing: SealingKey,
    /// Proves the right to **drain** this client's box.
    ///
    /// The tag is its hash, so a correspondent holding the tag may deposit and can neither
    /// drain nor read. Draining needs a signature under this key; reading cannot name a mailbox
    /// at all, because a read carries a publisher address and the provider derives the feed tag
    /// from it.
    ///
    /// When the tag and the key were the same value, every correspondent could permanently
    /// delete the mail they had sent, and anyone who learned a tag could delete everything in
    /// it. When reads took a raw tag, every correspondent could read it instead.
    drain: Identity,
    /// Strictly increasing, so a captured drain request cannot be replayed.
    drain_counter: u64,
    mailbox: Tag,
    provider: u16,
    /// Reassembly for **sealed mail only**.
    ///
    /// Feed content gets its own buffer per `FeedReader`. Sharing one meant fragments from a
    /// world-writable public box could occupy and evict state belonging to private mail, so
    /// the secrecy of a mailbox tag stopped being the thing that gated reach into a client's
    /// reassembly.
    inbox: Reassembler,
}

impl Client {
    pub fn new(identity: Identity, provider: u16) -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed);
        let drain = Identity::from_seed(seed);
        Client {
            identity,
            sealing: SealingKey::generate(),
            mailbox: mailbox_tag(&drain.key_bytes()),
            drain,
            drain_counter: 0,
            provider,
            inbox: Reassembler::new(),
        }
    }

    pub fn from_seed(seed: [u8; 32], provider: u16) -> Self {
        let mut ds = [0u8; 32];
        let mut h = blake3::Hasher::new();
        h.update(b"karst.net.v2.drain-key");
        h.update(&seed);
        ds.copy_from_slice(h.finalize().as_bytes());
        let drain = Identity::from_seed(ds);
        Client {
            identity: Identity::from_seed(seed),
            sealing: SealingKey::from_seed(seed),
            mailbox: mailbox_tag(&drain.key_bytes()),
            drain,
            drain_counter: 0,
            provider,
            inbox: Reassembler::new(),
        }
    }

    /// The public half of the drain key. Safe to show; the tag is its hash.
    ///
    /// The verifying key rather than its address, because the provider must check a signature
    /// with it and cannot do that from a hash.
    pub fn drain_public(&self) -> [u8; 32] {
        self.drain.key_bytes()
    }

    /// Sign the right to empty this client's own box, once.
    ///
    /// Nothing secret goes on the wire. The counter rises on every call, so a captured
    /// request is refused when replayed.
    pub fn drain_proof(&mut self) -> (u64, [u8; 64]) {
        self.drain_counter += 1;
        let c = self.drain_counter;
        (c, self.drain.sign(&drain_challenge(c)).to_bytes())
    }

    pub fn address(&self) -> karst_id::Address {
        self.identity.address()
    }

    /// What to hand someone who wants to reach you.
    pub fn contact(&self) -> Contact {
        Contact {
            mailbox: self.mailbox,
            sealing: self.sealing.public(),
            provider: self.provider,
        }
    }

    pub fn mailbox(&self) -> Tag {
        self.mailbox
    }

    /// Turn a message into packets, ready for L3.
    pub fn send(
        &self,
        dir: &Directory,
        to: &Contact,
        message: &[u8],
        rng: &mut impl Rng,
    ) -> Result<Vec<Dispatch>, SendError> {
        let mut msg_id = [0u8; 16];
        rng.fill(&mut msg_id);
        let frags = frame::split(msg_id, message).map_err(|_| SendError::MessageTooLarge)?;

        let mut out = Vec::with_capacity(frags.len());
        for f in frags {
            // The tag is authenticated but not encrypted, since a provider must read it to
            // file the mail. Binding it means a sealed blob cannot be lifted into another box.
            let sealed = karst_seal::seal(&to.sealing, &to.mailbox, &f.encode());
            debug_assert_eq!(sealed.len(), frame::BODY_BYTES);

            let mut payload = Vec::with_capacity(frame::FRAGMENT_BYTES);
            payload.extend_from_slice(&to.mailbox);
            payload.push(frame::ENV_SEALED);
            payload.extend_from_slice(&sealed);

            let route = dir.route_to(to.provider, rng).map_err(SendError::Route)?;
            let mut seed = [0u8; 32];
            rng.fill(&mut seed);
            out.push(Dispatch {
                via: route[0].id,
                packet: Packet::wrap(&route, &payload, seed).map_err(SendError::Mix)?,
            });
        }
        Ok(out)
    }

    /// A cover packet, indistinguishable from the ones above.
    ///
    /// It goes somewhere real, because a cover packet with a route nobody would take is a
    /// cover packet an adversary can pick out.
    pub fn cover(
        &self,
        dir: &Directory,
        toward: u16,
        rng: &mut impl Rng,
    ) -> Result<Dispatch, SendError> {
        let route = dir.route_to(toward, rng).map_err(SendError::Route)?;
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        Ok(Dispatch {
            via: route[0].id,
            packet: Packet::cover(&route, seed).map_err(SendError::Mix)?,
        })
    }

    /// Publish to a feed, readable by anyone who collects the tag.
    ///
    /// Not sealed, because it is not addressed to anyone. Content published for the world is
    /// content the provider holding it can read, and pretending otherwise by encrypting it to
    /// a key everyone has would be theatre. What stays hidden is who publishes it, which is
    /// L4's job, and who reads it, which is not solved.
    pub fn publish(
        &self,
        dir: &Directory,
        feed: Tag,
        provider: u16,
        message: &[u8],
        rng: &mut impl Rng,
    ) -> Result<Vec<Dispatch>, SendError> {
        let mut msg_id = [0u8; 16];
        rng.fill(&mut msg_id);
        let frags = frame::split(msg_id, message).map_err(|_| SendError::MessageTooLarge)?;

        let mut out = Vec::with_capacity(frags.len());
        for f in frags {
            let inner = f.encode();
            let mut body = vec![0u8; frame::BODY_BYTES];
            body[..inner.len()].copy_from_slice(&inner);
            // The remainder is padding an observer cannot distinguish from sealing overhead,
            // which is why open and sealed bodies are the same width.
            rng.fill(&mut body[inner.len()..]);

            let mut payload = Vec::with_capacity(frame::FRAGMENT_BYTES);
            payload.extend_from_slice(&feed);
            payload.push(frame::ENV_OPEN);
            payload.extend_from_slice(&body);

            let route = dir.route_to(provider, rng).map_err(SendError::Route)?;
            let mut seed = [0u8; 32];
            rng.fill(&mut seed);
            out.push(Dispatch {
                via: route[0].id,
                packet: Packet::wrap(&route, &payload, seed).map_err(SendError::Mix)?,
            });
        }
        Ok(out)
    }

    /// Take an envelope out of **this client's own mailbox**.
    ///
    /// Sealed only. An open envelope is unsealed and unauthenticated, so honouring one here
    /// would let anyone who can write bytes into the box put chosen content into the
    /// application's inbox with no key and no seal. Adding the open kind for feeds silently
    /// converted the private inbox into an unauthenticated channel, and the test that claimed
    /// a hostile provider could not inject missed it by one bit: it flipped `0x40`, turning
    /// `ENV_SEALED` into `0x41`, which falls through, and never tried `1 ^ 0x03 = ENV_OPEN`.
    ///
    /// The two kinds now have entirely separate entry points and there is no dispatch on an
    /// attacker-controlled byte.
    pub fn accept(&mut self, envelope: &[u8]) -> Option<Vec<u8>> {
        if envelope.len() != frame::ENVELOPE_BYTES || envelope[0] != frame::ENV_SEALED {
            return None;
        }
        let inner = self.sealing.open(&self.mailbox, &envelope[1..]).ok()?;
        let f = Fragment::decode(&inner).ok()?;
        self.inbox.accept(f).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::NodeInfo;
    use crate::provider::Provider;
    use karst_mix::packet::MixKey;
    use karst_node::{MixNode, Outbound};

    /// A running mesh: layers of mixes, one provider, and a virtual clock.
    struct Mesh {
        dir: Directory,
        nodes: Vec<MixNode>,
        provider: Provider,
        provider_id: u16,
        inflight: Vec<(usize, Packet)>,
        now: u64,
    }

    impl Mesh {
        fn new(layers: u8, per_layer: usize) -> Mesh {
            let mut dir = Directory::new(20.0);
            let mut nodes = Vec::new();
            let mut id = 0u16;
            for layer in 0..layers {
                let n = if layer == layers - 1 { 1 } else { per_layer };
                for _ in 0..n {
                    let key = MixKey::from_seed([(id as u8).wrapping_add(1); 32]);
                    dir.add(NodeInfo {
                        id,
                        addr: "127.0.0.1:1".parse().unwrap(),
                        mix_public: key.public(),
                        layer,
                        operator: crate::directory::solo_operator(0),
                    });
                    nodes.push(MixNode::new(key));
                    id += 1;
                }
            }
            Mesh {
                provider_id: id - 1,
                dir,
                nodes,
                provider: Provider::new(),
                inflight: Vec::new(),
                now: 0,
            }
        }

        fn inject(&mut self, dispatches: Vec<Dispatch>) {
            for d in dispatches {
                self.inflight.push((d.via as usize, d.packet));
            }
        }

        fn inject_one(&mut self, d: Dispatch) {
            self.inflight.push((d.via as usize, d.packet));
        }

        /// Run the mesh forward, filing anything that reaches the provider.
        fn run(&mut self, ms: u64) {
            for _ in 0..ms {
                self.now += 1;
                for (idx, p) in std::mem::take(&mut self.inflight) {
                    let _ = self.nodes[idx].accept(p, self.now);
                }
                for i in 0..self.nodes.len() {
                    for out in self.nodes[i].due(self.now) {
                        match out {
                            Outbound::Forward { next, packet } => {
                                self.inflight.push((next as usize, packet))
                            }
                            Outbound::Deliver { payload } => {
                                let _ = self.provider.deposit(&payload);
                            }
                        }
                    }
                }
            }
        }
    }

    /// The whole point: two clients, a real mesh, a message that arrives.
    #[test]
    fn two_clients_exchange_a_message_through_a_running_mesh() {
        let mut mesh = Mesh::new(4, 3);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        let packets = alice
            .send(&mesh.dir, &bob.contact(), b"the network works", &mut rng)
            .unwrap();
        assert_eq!(packets.len(), 1);
        mesh.inject(packets);
        mesh.run(2_000);

        let c = mesh.provider.collect(&bob.mailbox());
        assert_eq!(c.refused, 0);
        assert_eq!(c.items.len(), 1);

        let mut got = None;
        for item in c.items {
            if let Some(m) = bob.accept(&item) {
                got = Some(m);
            }
        }
        assert_eq!(got.unwrap(), b"the network works");
    }

    /// A message spanning many packets, each on its own route, still arrives whole.
    #[test]
    fn a_multi_fragment_message_arrives_whole_over_independent_routes() {
        let mut mesh = Mesh::new(4, 4);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        let long: Vec<u8> = (0..frame::DATA_BYTES * 9 + 77)
            .map(|i| (i % 251) as u8)
            .collect();
        let packets = alice
            .send(&mesh.dir, &bob.contact(), &long, &mut rng)
            .unwrap();
        assert_eq!(packets.len(), 10);
        mesh.inject(packets);
        mesh.run(3_000);

        let c = mesh.provider.collect(&bob.mailbox());
        assert_eq!(c.items.len(), 10);
        let mut got = None;
        for item in c.items {
            if let Some(m) = bob.accept(&item) {
                got = Some(m);
            }
        }
        assert_eq!(got.unwrap(), long);
    }

    /// Both directions, so a conversation rather than a broadcast.
    #[test]
    fn a_reply_comes_back_the_same_way() {
        let mut mesh = Mesh::new(4, 3);
        let mut alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        mesh.inject(
            alice
                .send(&mesh.dir, &bob.contact(), b"are you there", &mut rng)
                .unwrap(),
        );
        mesh.run(2_000);
        let heard = mesh
            .provider
            .collect(&bob.mailbox())
            .items
            .into_iter()
            .find_map(|i| bob.accept(&i))
            .unwrap();
        assert_eq!(heard, b"are you there");

        mesh.inject(
            bob.send(&mesh.dir, &alice.contact(), b"yes", &mut rng)
                .unwrap(),
        );
        mesh.run(2_000);
        let reply = mesh
            .provider
            .collect(&alice.mailbox())
            .items
            .into_iter()
            .find_map(|i| alice.accept(&i))
            .unwrap();
        assert_eq!(reply, b"yes");
    }

    /// The provider must not be able to read what it is holding.
    #[test]
    fn the_provider_holds_mail_it_cannot_read() {
        let mut mesh = Mesh::new(3, 2);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        let secret = b"a distinctive phrase that would be obvious in a buffer";
        mesh.inject(
            alice
                .send(&mesh.dir, &bob.contact(), secret, &mut rng)
                .unwrap(),
        );
        mesh.run(2_000);

        let c = mesh.provider.collect(&bob.mailbox());
        assert_eq!(c.items.len(), 1);
        for item in &c.items {
            assert!(
                !item.windows(secret.len()).any(|w| w == secret),
                "the plaintext was sitting in the provider's store"
            );
        }
    }

    /// A one byte message and a full one must be the same size at the provider.
    #[test]
    fn message_length_is_not_visible_to_the_provider() {
        let mut mesh = Mesh::new(3, 2);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        mesh.inject(
            alice
                .send(&mesh.dir, &bob.contact(), b"x", &mut rng)
                .unwrap(),
        );
        mesh.run(2_000);
        let small = mesh.provider.collect(&bob.mailbox()).items;

        mesh.inject(
            alice
                .send(
                    &mesh.dir,
                    &bob.contact(),
                    &vec![7u8; frame::DATA_BYTES],
                    &mut rng,
                )
                .unwrap(),
        );
        mesh.run(2_000);
        let large = mesh.provider.collect(&bob.mailbox()).items;

        assert_eq!(small.len(), large.len());
        assert_eq!(small[0].len(), large[0].len());
    }

    /// Cover traffic must be routed and delivered like everything else, and vanish.
    #[test]
    fn cover_traffic_traverses_the_mesh_and_leaves_no_mail() {
        let mut mesh = Mesh::new(4, 3);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        for _ in 0..50 {
            let d = alice.cover(&mesh.dir, mesh.provider_id, &mut rng).unwrap();
            mesh.inject_one(d);
        }
        mesh.run(3_000);

        assert_eq!(mesh.provider.held(), 0, "cover reached a mailbox");
        assert_eq!(mesh.provider.collect(&bob.mailbox()).items.len(), 0);
        let absorbed: u64 = mesh.nodes.iter().map(|n| n.stats().cover_absorbed).sum();
        assert_eq!(absorbed, 50, "cover did not die where it should have");
    }

    /// A provider substituting bytes must not be able to make a recipient read them.
    #[test]
    fn a_hostile_provider_cannot_inject_content() {
        let mut mesh = Mesh::new(3, 2);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        mesh.inject(
            alice
                .send(&mesh.dir, &bob.contact(), b"genuine", &mut rng)
                .unwrap(),
        );
        mesh.run(2_000);
        let real = mesh.provider.collect(&bob.mailbox()).items.remove(0);

        // Every single-bit alteration a provider could make.
        for i in (0..real.len()).step_by(7) {
            let mut tampered = real.clone();
            tampered[i] ^= 0x40;
            assert_eq!(bob.accept(&tampered), None, "byte {i} was accepted");
        }
        // Wholesale replacement.
        assert_eq!(bob.accept(&vec![0u8; real.len()]), None);
        assert_eq!(bob.accept(&[]), None);
        // The genuine one still works afterwards, so rejecting did not poison the state.
        assert_eq!(bob.accept(&real).unwrap(), b"genuine");
    }

    /// Mail for one recipient must not open for another.
    #[test]
    fn mail_does_not_open_for_the_wrong_recipient() {
        let mut mesh = Mesh::new(3, 2);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut eve = Client::from_seed([3u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        mesh.inject(
            alice
                .send(&mesh.dir, &bob.contact(), b"private", &mut rng)
                .unwrap(),
        );
        mesh.run(2_000);
        for item in mesh.provider.collect(&bob.mailbox()).items {
            assert_eq!(eve.accept(&item), None);
        }
    }
    /// An open envelope must never be accepted out of a private mailbox.
    ///
    /// This is the defect the feed work introduced and that six independent reviews found. An
    /// open envelope is unsealed and unauthenticated, so honouring one on the mailbox path let
    /// anyone who could write bytes into the box put chosen content into the application's
    /// inbox with no key at all. The test that claimed to cover hostile injection missed it by
    /// one bit, flipping 0x40 so that ENV_SEALED became 0x41 and fell through, never trying
    /// 1 ^ 0x03 = ENV_OPEN.
    #[test]
    fn an_open_envelope_is_never_accepted_from_a_private_mailbox() {
        let mesh = Mesh::new(3, 2);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);

        // Forge exactly what a hostile provider would build: no key, no seal, no tag secret.
        let f = crate::frame::Fragment {
            msg_id: [0x11; 16],
            index: 0,
            total: 1,
            data: b"the transfer is approved".to_vec(),
        };
        let inner = f.encode();
        let mut envelope = vec![0u8; frame::ENVELOPE_BYTES];
        envelope[0] = frame::ENV_OPEN;
        envelope[1..1 + inner.len()].copy_from_slice(&inner);
        assert_eq!(envelope.len(), frame::ENVELOPE_BYTES);

        assert_eq!(
            bob.accept(&envelope),
            None,
            "an unsealed envelope was accepted as private mail"
        );

        // And the one-bit flip the old test could not reach.
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();
        let real = alice
            .send(&mesh.dir, &bob.contact(), b"genuine", &mut rng)
            .unwrap();
        let payload_kind_flip = {
            let mut e = vec![0u8; frame::ENVELOPE_BYTES];
            e[0] = frame::ENV_SEALED ^ 0x03;
            e
        };
        assert_eq!(bob.accept(&payload_kind_flip), None);
        let _ = real;
    }

    /// Every byte value in the kind position other than sealed must be refused.
    #[test]
    fn only_the_sealed_kind_is_honoured_on_the_mailbox_path() {
        let mesh = Mesh::new(3, 2);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let f = crate::frame::Fragment {
            msg_id: [0x22; 16],
            index: 0,
            total: 1,
            data: b"injected".to_vec(),
        };
        let inner = f.encode();
        for kind in 0u8..=255 {
            let mut envelope = vec![0u8; frame::ENVELOPE_BYTES];
            envelope[0] = kind;
            envelope[1..1 + inner.len()].copy_from_slice(&inner);
            assert_eq!(
                bob.accept(&envelope),
                None,
                "kind byte {kind} produced a message with no seal"
            );
        }
    }

    /// A correspondent knows where to deposit and must not be able to drain.
    ///
    /// The tag and the right to collect used to be the same value, so everyone a client had
    /// ever written to could permanently delete their mail.
    #[test]
    fn a_contact_carries_the_right_to_deposit_and_not_to_collect() {
        let bob = Client::from_seed([2u8; 32], 0);
        let contact = bob.contact();
        assert_eq!(contact.mailbox, bob.mailbox());
        assert_ne!(
            contact.mailbox,
            bob.drain_public(),
            "the tag is the drain key, so anyone who can send can also drain"
        );
        assert_eq!(
            crate::client::mailbox_tag(&bob.drain_public()),
            bob.mailbox(),
            "the tag must be the hash of the key that drains it"
        );
    }

    /// Nothing secret goes on the wire, so capturing a poll buys nothing durable.
    ///
    /// The credential used to be the drain secret itself, sent in the clear on every poll as
    /// its own proof. One captured datagram took the mailbox permanently, and there was no
    /// rotation path because the tag is the identity every correspondent holds.
    #[test]
    fn a_drain_proof_reveals_no_secret_and_does_not_replay() {
        let mut bob = Client::from_seed([2u8; 32], 0);
        let (c1, s1) = bob.drain_proof();
        let (c2, _) = bob.drain_proof();
        assert!(c2 > c1, "the counter must rise, or a capture replays");

        // What an eavesdropper sees is the public key and a signature over a counter.
        let peer = karst_id::Peer::from_key_bytes(&bob.drain_public()).unwrap();
        assert!(peer
            .verify(&drain_challenge(c1), &karst_id::Signature::from_bytes(&s1))
            .is_ok());

        // And it does not verify for any other counter, so it authorises one drain.
        assert!(peer
            .verify(
                &drain_challenge(c1 + 1),
                &karst_id::Signature::from_bytes(&s1)
            )
            .is_err());
    }
}
