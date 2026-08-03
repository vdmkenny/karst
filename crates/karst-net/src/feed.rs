//! Publishing to everyone, rather than sending to someone.
//!
//! A mailbox tag is 32 random bytes handed to correspondents, and its secrecy is what stops a
//! stranger flooding a box they were never told about. A **feed** cannot work that way: the
//! point of publishing is that people who have never met you can read you, so the tag has to be
//! derivable from your address alone.
//!
//! That makes a feed box public, floodable, and readable, and each of those needs an answer
//! rather than a hope.
//!
//! # Readable is intended
//!
//! Content published for the world is content the provider holding it can read. Encrypting it
//! to a key everybody has would be theatre. What stays hidden is **who published it**, which is
//! L4's job and holds, and **who reads it**, which is not solved and is #53.
//!
//! # Floodable is bounded and, more importantly, visible
//!
//! Anyone can compute a feed tag and deposit into it. They cannot forge content, because a
//! subscriber verifies every object against the publisher's key and discards the rest, so a
//! flood buys **denial and never substitution**.
//!
//! Denial is real: a full box refuses genuine deposits. It is not silent, because a provider
//! reports refusals to whoever collects, so a subscriber sees that a feed lost deposits and a
//! publisher watching their own feed sees it too. That is the same choice made everywhere in
//! this design, and it is weaker than prevention. The fix that would prevent it is named in
//! the issue rather than pretended at here: per-fragment authorisation, so a provider can
//! refuse a deposit into a feed it is not signed for, at a cost of 64 bytes per fragment.
//!
//! # Epochs
//!
//! A feed tag rotates, so a box does not accumulate for ever and a subscriber knows which box
//! to ask for. Old content does not vanish: it is objects, and keeping objects is L6's problem.
//! What rotates is only where the **live** feed is deposited.

use karst_id::Address;
use karst_object::Object;

use crate::client::Client;
use crate::provider::Tag;

/// Where a publisher deposits during an epoch.
///
/// Derived from the address rather than shared out of band, because a reader who must be given
/// a tag before they can read you is a reader you must already know.
pub fn feed_tag(publisher: &Address, epoch: u64) -> Tag {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.net.v1.feed");
    h.update(publisher.as_bytes());
    h.update(&epoch.to_le_bytes());
    *h.finalize().as_bytes()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeedStats {
    /// Objects accepted, verified, and from the expected publisher.
    pub accepted: u64,
    /// Envelopes that reassembled into something that was not a valid object.
    pub undecodable: u64,
    /// Valid objects signed by somebody other than the publisher of this feed.
    pub wrong_author: u64,
    /// Fragments refused for disagreeing with a publication already being collected.
    ///
    /// A feed box is world-writable and its message ids are readable out of it, so this counts
    /// deliberate interference rather than corruption. It is surfaced because a reader who
    /// silently collects less than a publisher wrote cannot tell that from a quiet publisher.
    pub conflicting: u64,
}

/// One publisher's feed, as a subscriber sees it.
///
/// Each feed reassembles into **its own buffer**. Sharing one with private mail let fragments
/// from a world-writable public box occupy and evict state belonging to sealed mail, so the
/// secrecy of a mailbox tag stopped being what gated reach into a client's reassembly. Sharing
/// one *between feeds* would be nearly as bad: a single flooded publisher would deny every
/// other publisher a subscriber follows.
pub struct FeedReader {
    publisher: Address,
    inbox: crate::frame::Reassembler,
    stats: FeedStats,
}

impl FeedReader {
    pub fn new(publisher: Address) -> Self {
        FeedReader {
            publisher,
            inbox: crate::frame::Reassembler::new(),
            stats: FeedStats::default(),
        }
    }

    /// Parse an open envelope. Open only: a sealed envelope has no business in a feed box, and
    /// dispatching on the kind byte is what put an unauthenticated path into private mail.
    fn open(&mut self, envelope: &[u8]) -> Option<Vec<u8>> {
        use crate::frame::{Fragment, ENVELOPE_BYTES, ENV_OPEN, INNER_BYTES};
        if envelope.len() != ENVELOPE_BYTES || envelope[0] != ENV_OPEN {
            return None;
        }
        let f = Fragment::decode(&envelope[1..1 + INNER_BYTES]).ok()?;
        self.inbox.accept(f).ok().flatten()
    }

    pub fn publisher(&self) -> Address {
        self.publisher
    }

    pub fn tag(&self, epoch: u64) -> Tag {
        feed_tag(&self.publisher, epoch)
    }

    pub fn stats(&self) -> FeedStats {
        self.stats
    }

    /// Offer an envelope collected from this feed's box.
    ///
    /// Returns an object only when it reassembled, decoded, verified, **and** was signed by
    /// the publisher whose feed this is. Anyone may deposit here, so the last check is what
    /// makes a flood useless for anything but denial.
    pub fn accept(&mut self, _client: &mut Client, envelope: &[u8]) -> Option<Object> {
        let bytes = self.open(envelope);
        // Interference is counted whether or not this envelope completed anything.
        self.stats.conflicting = self.inbox.conflicting();
        let bytes = bytes?;
        let Ok(obj) = Object::decode(&bytes) else {
            self.stats.undecodable += 1;
            return None;
        };
        match obj.verify() {
            Ok(author) if author == self.publisher => {
                self.stats.accepted += 1;
                Some(obj)
            }
            Ok(_) => {
                self.stats.wrong_author += 1;
                None
            }
            Err(_) => {
                self.stats.undecodable += 1;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{Directory, NodeInfo};
    use crate::provider::Provider;
    use karst_id::Identity;
    use karst_mix::packet::{MixKey, Packet};
    use karst_node::{MixNode, Outbound};
    use rand::Rng;

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
            let mut dir = Directory::new(15.0);
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

        fn inject(&mut self, ds: Vec<crate::client::Dispatch>) {
            for d in ds {
                self.inflight.push((d.via as usize, d.packet));
            }
        }

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

    fn publish_object(
        mesh: &mut Mesh,
        client: &Client,
        author: &Identity,
        epoch: u64,
        payload: &[u8],
        seq: u64,
    ) {
        let tag = feed_tag(&author.address(), epoch);
        publish_into(mesh, client, author, tag, payload, seq);
    }

    /// Publish signed by `author` into whatever box the caller names.
    ///
    /// Separate from `publish_object` because a feed tag is public: anyone may deposit into
    /// anyone's box, and a test that only ever deposits into its own is not testing that.
    fn publish_into(
        mesh: &mut Mesh,
        client: &Client,
        author: &Identity,
        tag: Tag,
        payload: &[u8],
        seq: u64,
    ) {
        let obj = Object::create(author, "doc", seq, payload.to_vec(), None);
        let mut rng = rand::thread_rng();
        let ds = client
            .publish(&mesh.dir, tag, mesh.provider_id, &obj.encode(), &mut rng)
            .unwrap();
        mesh.inject(ds);
    }

    /// A stranger reads a publisher they have never met, knowing only their address.
    ///
    /// This is the whole point of a feed: no introduction, no registry, no shared secret.
    #[test]
    fn a_stranger_reads_a_publisher_knowing_only_their_address() {
        let mut mesh = Mesh::new(4, 3);
        let author = Identity::from_seed([1u8; 32]);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);

        publish_object(&mut mesh, &alice, &author, 0, b"a public document", 0);
        mesh.run(2_000);

        // Bob has never spoken to alice. He derives the tag from her address alone.
        let mut feed = FeedReader::new(author.address());
        let items = mesh.provider.collect(&feed.tag(0)).items;
        assert_eq!(items.len(), 1);
        let obj = feed.accept(&mut bob, &items[0]).expect("nothing arrived");
        assert_eq!(obj.payload, b"a public document");
        assert_eq!(feed.stats().accepted, 1);
    }

    /// Anyone can deposit into a feed box, and nobody else can put words in the publisher's
    /// mouth.
    ///
    /// A flood therefore buys denial and never substitution, which is the property that makes
    /// a public tag survivable at all.
    #[test]
    fn a_flood_into_a_public_feed_cannot_forge_content() {
        let mut mesh = Mesh::new(4, 3);
        let author = Identity::from_seed([1u8; 32]);
        let impostor = Identity::from_seed([9u8; 32]);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let eve = Client::from_seed([9u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);

        let tag = feed_tag(&author.address(), 0);
        publish_object(&mut mesh, &alice, &author, 0, b"the genuine article", 0);
        // Eve deposits her own perfectly valid objects into ALICE's feed box, which she can
        // compute from alice's address like anybody else.
        for i in 0..25u64 {
            publish_into(&mut mesh, &eve, &impostor, tag, b"a forgery", i);
        }
        // And some bytes that are not objects at all.
        let mut rng = rand::thread_rng();
        for _ in 0..25 {
            let mut junk = vec![0u8; 400];
            rng.fill(&mut junk[..]);
            let ds = eve
                .publish(&mesh.dir, tag, mesh.provider_id, &junk, &mut rng)
                .unwrap();
            mesh.inject(ds);
        }
        mesh.run(3_000);

        let mut feed = FeedReader::new(author.address());
        let items = mesh.provider.collect(&tag).items;
        assert!(items.len() > 25, "vacuous: only {} deposits", items.len());

        let mut got = Vec::new();
        for item in &items {
            if let Some(o) = feed.accept(&mut bob, item) {
                got.push(o);
            }
        }
        assert_eq!(got.len(), 1, "the feed yielded something alice did not sign");
        assert_eq!(got[0].payload, b"the genuine article");
        assert!(
            feed.stats().wrong_author > 0,
            "the impostor's valid objects were not seen and rejected"
        );
    }

    /// Tampering must never change what a reader ends up holding.
    #[test]
    fn tampering_in_the_feed_cannot_change_content() {
        let mut mesh = Mesh::new(3, 2);
        let author = Identity::from_seed([1u8; 32]);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);

        publish_object(&mut mesh, &alice, &author, 0, b"unaltered", 0);
        mesh.run(2_000);
        let mut items = mesh.provider.collect(&feed_tag(&author.address(), 0)).items;
        assert_eq!(items.len(), 1);

        // The property is not "every flip is refused", it is **no flip produces something
        // else**. Most of an open envelope is padding, and most of the rest is fragment
        // bookkeeping; altering either leaves the reassembled bytes identical, so the object
        // is the same object and accepting it is correct.
        //
        // Padding in an open envelope is therefore malleable, and a relay can alter it without
        // detection. It carries no content and changes no outcome, so what it offers is a
        // covert channel between parties who are already relaying for each other and have
        // better ones. In a sealed envelope the padding is inside the seal and is
        // authenticated, because there the same bits would be a channel out of somebody's
        // private mail.
        let mut feed = FeedReader::new(author.address());
        let mut sampled = 0;
        for i in (1..items[0].len()).step_by(37) {
            let mut bad = items[0].clone();
            bad[i] ^= 0x20;
            sampled += 1;
            if let Some(obj) = feed.accept(&mut bob, &bad) {
                assert_eq!(
                    obj.payload, b"unaltered",
                    "a tampered envelope at byte {i} produced different content"
                );
            }
        }
        assert!(sampled > 15, "vacuous: only {sampled} positions tried");
        // The genuine one still works, so rejecting did not poison the reassembler.
        let obj = feed.accept(&mut bob, &items.remove(0)).unwrap();
        assert_eq!(obj.payload, b"unaltered");
    }

    /// Feeds rotate, so a box does not accumulate for ever.
    #[test]
    fn a_feed_rotates_between_epochs() {
        let a = Identity::from_seed([1u8; 32]).address();
        assert_ne!(feed_tag(&a, 0), feed_tag(&a, 1));
        // And two publishers never share a box.
        let b = Identity::from_seed([2u8; 32]).address();
        assert_ne!(feed_tag(&a, 0), feed_tag(&b, 0));
    }

    /// An object larger than one packet must still arrive whole.
    #[test]
    fn a_multi_fragment_publication_arrives_whole() {
        let mut mesh = Mesh::new(4, 3);
        let author = Identity::from_seed([1u8; 32]);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);

        let big: Vec<u8> = (0..crate::frame::DATA_BYTES * 6).map(|i| (i % 251) as u8).collect();
        publish_object(&mut mesh, &alice, &author, 0, &big, 0);
        mesh.run(3_000);

        let mut feed = FeedReader::new(author.address());
        let items = mesh.provider.collect(&feed_tag(&author.address(), 0)).items;
        assert!(items.len() >= 6);
        let mut got = None;
        for item in &items {
            if let Some(o) = feed.accept(&mut bob, item) {
                got = Some(o);
            }
        }
        assert_eq!(got.unwrap().payload, big);
    }

    /// Published content must be the same size on the wire as private mail.
    #[test]
    fn a_publication_is_indistinguishable_in_size_from_private_mail() {
        let mesh = Mesh::new(4, 3);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut rng = rand::thread_rng();

        let pubd = alice
            .publish(&mesh.dir, [7u8; 32], mesh.provider_id, b"public", &mut rng)
            .unwrap();
        let sent = alice
            .send(&mesh.dir, &bob.contact(), b"private", &mut rng)
            .unwrap();
        assert_eq!(
            pubd[0].packet.to_bytes().len(),
            sent[0].packet.to_bytes().len()
        );
    }
    /// Altering the signed region must be caught, which is the half that matters.
    #[test]
    fn altering_the_object_itself_is_caught() {
        let mut mesh = Mesh::new(3, 2);
        let author = Identity::from_seed([1u8; 32]);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);

        publish_object(&mut mesh, &alice, &author, 0, b"the real payload", 0);
        mesh.run(2_000);
        let items = mesh.provider.collect(&feed_tag(&author.address(), 0)).items;
        let mut feed = FeedReader::new(author.address());

        // Find where the payload sits in the envelope and corrupt it there.
        let needle = b"the real payload";
        let at = items[0]
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the payload should be readable, this is public content");
        for k in 0..needle.len() {
            let mut bad = items[0].clone();
            bad[at + k] ^= 0x01;
            assert!(
                feed.accept(&mut bob, &bad).is_none(),
                "a corrupted payload byte {k} was accepted"
            );
        }
    }

}
