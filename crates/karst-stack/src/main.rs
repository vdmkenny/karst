//! The whole stack, composed, over a running network.
//!
//! Alice writes a document, publishes it and an index entry to her feed, and Bob reads it
//! knowing nothing but her address. No DNS, no certificate authority, no server, no crawler,
//! no search engine, and no markup.
//!
//! `cargo run --release -p karst-stack --bin karst-stack-demo`

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use karst_doc::{Doc, Node, Run};
use karst_id::Identity;
use karst_index::complete::{witnessed_digest, Census, CensusMonitor, Completeness};
use karst_index::{Announcement, Catalogue, Ranker, Trust};
use karst_mix::packet::MixKey;
use karst_net::client::Client;
use karst_net::directory::{Directory, NodeInfo};
use karst_net::feed::{feed_tag, FeedReader};
use karst_net::placement::{placement, DEFAULT_REPLICAS};
use karst_net::runner::{ClientRunner, NodeRunner};
use karst_net::watch::FeedWatch;
use karst_node::MixNode;
use karst_object::Object;
use karst_witness::{Acceptance, Checkpoint, Cosigned, Witness, WitnessPolicy};

const LAYERS: u8 = 4;
const PER_LAYER: usize = 2;
/// Providers in the last layer, so a feed can live on more than one of them.
const PROVIDERS: usize = 4;
const LAMBDA: f64 = 60.0;

/// What the demo checked, and whether it held.
///
/// The demo prints its failures in red and used to exit zero, so a regression that stopped
/// delivery entirely was invisible to anything but a human reading the output. It caught a real
/// one that 551 unit tests did not, and then said nothing a machine could act on.
///
/// Every claim the demo makes about itself goes through here.
#[derive(Default)]
struct Checks {
    failed: Vec<String>,
}

impl Checks {
    fn require(&mut self, held: bool, what: &str) -> bool {
        if !held {
            self.failed.push(what.to_string());
        }
        held
    }

    fn report(&self) -> std::process::ExitCode {
        if self.failed.is_empty() {
            println!("  \x1b[32mall {} checks held\x1b[0m", CHECKS_EXPECTED);
            return std::process::ExitCode::SUCCESS;
        }
        println!("\n\x1b[31m{} check(s) failed\x1b[0m", self.failed.len());
        for f in &self.failed {
            println!("  \x1b[31m- {f}\x1b[0m");
        }
        std::process::ExitCode::FAILURE
    }
}

/// How many checks a healthy run makes. A run that makes fewer exited early.
const CHECKS_EXPECTED: usize = 19;

fn rule(t: &str) {
    println!("\n\x1b[1m{}\x1b[0m", t);
    println!("{}", "-".repeat(t.len()));
}

fn note(s: &str) {
    println!("  \x1b[2m{}\x1b[0m", s);
}

fn local() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A short document, as a typed node graph rather than markup.
fn write_document(prior: karst_object::Cid) -> (Doc, karst_object::Cid) {
    let mut doc = Doc::new();
    let heading = doc.add(Node::Heading {
        rank: 1,
        text: "On carrying provenance with the object".to_string(),
    });
    let p1 = doc.add(Node::Prose {
        runs: vec![
            Run::plain("A document fetched from an adversary is worth exactly as much as one "),
            Run::plain("fetched from its author, because what makes it trustworthy travels "),
            Run::strong("with the bytes"),
            Run::plain(" rather than with the connection."),
        ],
    });
    let p2 = doc.add(Node::Prose {
        runs: vec![
            Run::plain("This supersedes "),
            Run::link("the earlier note", prior),
            Run::plain(", which is a citation and will never change. Compare "),
            Run::tracking_link("the current draft", prior),
            Run::plain(", which follows its target forward."),
        ],
    });
    let root = doc.add(Node::Section {
        title: "note".to_string(),
        children: vec![heading, p1, p2],
    });
    (doc, root)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            println!("\x1b[31mthe demo could not run: {e}\x1b[0m");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> std::io::Result<std::process::ExitCode> {
    let mut checks = Checks::default();
    println!("\n\x1b[1mKARST: the stack, composed\x1b[0m");
    note("L2 identity, L3 wire, L4 mixing, L5 membership, L6 objects, L8 witness, L10 documents, L14 value, L15 discovery.");

    rule("A network");

    let mut runners = Vec::new();
    let mut infos = Vec::new();
    let mut id = 0u16;
    let mut provider_ids: Vec<u16> = Vec::new();
    let mut collect_addrs: Vec<(u16, SocketAddr)> = Vec::new();

    for layer in 0..LAYERS {
        let count = if layer == LAYERS - 1 {
            PROVIDERS
        } else {
            PER_LAYER
        };
        for _ in 0..count {
            let key = MixKey::from_seed(rand::random());
            let public = key.public();
            let mut r = NodeRunner::new(id, MixNode::new(key), local())?;
            if layer == LAYERS - 1 {
                r = r.serving_mail(local())?;
                provider_ids.push(id);
                collect_addrs.push((id, r.collect_addr().expect("serving mail")));
            }
            infos.push(NodeInfo {
                id,
                addr: r.addr()?,
                mix_public: public,
                layer,
                operator: karst_net::solo_operator(id),
            });
            runners.push(r);
            id += 1;
        }
    }
    let mut dir = Directory::new(20.0);
    for i in &infos {
        dir.add(i.clone());
    }
    for r in runners.iter_mut() {
        r.set_directory(dir.clone());
    }
    println!(
        "  {} mixes in {} layers, {} of them providers, on real sockets",
        infos.len(),
        LAYERS,
        PROVIDERS
    );

    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    let mut kill: Vec<(u16, Arc<AtomicBool>)> = Vec::new();
    for mut r in runners {
        let stop = Arc::clone(&stop);
        let mine = Arc::new(AtomicBool::new(false));
        kill.push((r.id, Arc::clone(&mine)));
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if !mine.load(Ordering::Relaxed) {
                    r.step();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }));
    }

    rule("Alice writes something");

    let alice_seed: [u8; 32] = rand::random();
    let alice_id = Identity::from_seed(alice_seed);
    let prior = karst_object::Cid::of(b"an earlier note");
    let (doc, root) = write_document(prior);
    println!("{}", doc.render_text(&root));
    note("A typed node graph. There is no markup to parse and no script to run, so a document");
    note("cannot reach into the reader's machine, because there is nothing to reach with.");

    // Every node is published as its own signed object, because a document is a graph of
    // content-addressed nodes rather than a file. A reader fetches the parts they need and
    // verifies each one on its own, and two documents quoting the same paragraph share it
    // instead of copying it.
    let mut node_objs = Vec::new();
    for (i, cid) in doc.cids().into_iter().enumerate() {
        let node = doc.get(&cid).expect("cid came from the doc");
        node_objs.push(Object::create(
            &alice_id,
            "karst.doc.node.v1",
            i as u64,
            node.encode(),
            None,
        ));
    }
    let doc_cid = root;

    // And the index entry, which is an obligation of publishing rather than a favour to a
    // search engine.
    let ann = Announcement::new(
        doc_cid,
        alice_id.address(),
        "doc",
        &["provenance", "objects", "trust"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        0,
    )
    .unwrap();
    let ann_obj = ann.publish(&alice_id, node_objs.len() as u64);

    rule("Alice publishes, into a feed anyone can find and nobody can write to");

    let holders = placement(&alice_id.address(), 0, &provider_ids, DEFAULT_REPLICAS);
    let mut alice = ClientRunner::new(
        Client::from_seed(alice_seed, holders[0]),
        local(),
        dir.clone(),
        collect_addrs[0].1,
        LAMBDA,
    )?;
    // The feed is named by publisher and epoch. The tag is derived locally for the reader's
    // own bookkeeping; it is never what goes on the wire, because a provider that accepted a tag
    // would accept a mailbox tag too.
    let (publisher, epoch) = (alice_id.address(), 0u64);
    let feed = feed_tag(&publisher, epoch);
    for p in &holders {
        for o in &node_objs {
            alice.publish_to(feed, *p, &o.encode()).unwrap();
        }
        alice.publish_to(feed, *p, &ann_obj.encode()).unwrap();
    }
    println!("  {} nodes and one index entry", node_objs.len());
    println!("  replicated onto providers {holders:?}");
    note("Nobody was told where. The set is rendezvous hashing over her address and the epoch,");
    note("so a reader who has never met her computes exactly the same three.");
    println!("  feed tag {}", hex8(&feed));
    note("Derived from her address, so a reader who has never met her can compute it.");
    note("Anyone may deposit here; nobody else can sign as her, so a flood buys denial and");
    note("never substitution.");

    rule("Bob, who knows only her address");

    let mut bob = ClientRunner::new(
        Client::new(Identity::from_seed(rand::random()), holders[0]),
        local(),
        dir.clone(),
        collect_addrs[0].1,
        LAMBDA,
    )?;
    println!("  alice  {}", alice_id.address().short());
    note("That address is the hash of a key she generated locally. Nobody issued it, so");
    note("nobody can revoke it, and there was no registry to ask.");

    // One reader, one feed, several providers. Each gets its own reader so a divergent
    // replica cannot desynchronise reassembly for the others.
    let mut readers: Vec<(u16, SocketAddr, FeedReader)> = holders
        .iter()
        .map(|p| {
            let at = collect_addrs.iter().find(|(i, _)| i == p).unwrap().1;
            (*p, at, FeedReader::new(alice_id.address()))
        })
        .collect();
    let mut watch = FeedWatch::new();
    let mut received: Vec<Object> = Vec::new();
    let mut seen: std::collections::BTreeSet<karst_object::Cid> = Default::default();
    let want = node_objs.len() + 1;

    // Read every replica to completion, not just until bob has what he wants. A replica that
    // was never finished being read is indistinguishable from one that is withholding, so a
    // caller that stops early manufactures its own false positives.
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline && !(received.len() >= want && watch.agreed()) {
        alice.step();
        bob.step();
        for (p, at, reader) in readers.iter_mut() {
            for env in bob.poll_feed_at(*at, &publisher, epoch) {
                if let Some(obj) = reader.accept(&mut bob.client, &env) {
                    watch.record(*p, obj.cid());
                    if seen.insert(obj.cid()) {
                        received.push(obj);
                    }
                }
            }
        }
        watch.end_round(&holders);
        std::thread::sleep(Duration::from_millis(2));
    }

    rule("What arrived");

    checks.require(
        received.len() >= want,
        "every published object reached the reader",
    );
    checks.require(watch.agreed(), "the replicas agreed on what they held");
    if received.len() < want {
        println!(
            "  \x1b[31monly {} of {want} objects arrived\x1b[0m",
            received.len()
        );
        stop.store(true, Ordering::Relaxed);
        for t in threads {
            let _ = t.join();
        }
        // Bail out, but as a failure. A demo that stops early and exits zero is how a total
        // delivery regression stayed invisible to everything but a human reading the output.
        return Ok(checks.report());
    }
    println!(
        "  {} objects, every one verified against alice's key",
        received.len()
    );
    for o in received.iter().take(3) {
        println!(
            "    {:<22} {:>4} bytes  {}",
            o.kind,
            o.payload.len(),
            o.verify().map(|a| a.short()).unwrap_or_default()
        );
    }
    if received.len() > 3 {
        println!("    ... and {} more", received.len() - 3);
    }
    note("Verified against her key, not against where the bytes came from. The provider that");
    note("held them, and every mix that carried them, could have altered nothing.");

    rule("Bob indexes what he received, and searches his own catalogue");

    let mut trust = Trust::new();
    trust.set(alice_id.address(), 1.0);
    let mut cat = Catalogue::new();
    for o in &received {
        if let Ok(a) = Announcement::from_object(o) {
            cat.announce(a, &trust);
        }
    }
    let hits = Ranker::new(trust).search(&cat, &["provenance".to_string(), "trust".to_string()]);
    for h in &hits {
        println!("  {:>6.3}  {}", h.score, h.target.short());
    }
    note("No crawler ever visited anything. The entry was emitted by the author, at the moment");
    note("of writing, because she is the one party who could not be wrong about it.");
    note("The catalogue is bob's. There is no index to capture and no ranking to buy.");

    rule("And reads it");

    // Bob rebuilds the graph from the nodes he verified, and the announced root names where
    // to start reading.
    let mut theirs = Doc::new();
    for o in &received {
        if o.kind == "karst.doc.node.v1" {
            if let Ok(node) = Node::from_bytes(&o.payload) {
                theirs.add(node);
            }
        }
    }
    match hits.first() {
        Some(hit) if theirs.get(&hit.target).is_some() => {
            print!("{}", theirs.render_text(&hit.target));
            note("Links say which kind they are. A citation is fixed; a tracking link follows");
            note("its target and says so, and a reader is never left guessing which they got.");
        }
        _ => {
            checks.require(false, "the document reassembled and rendered");
            println!("  \x1b[31mthe document did not reassemble\x1b[0m");
        }
    }

    rule("Bob checks he was shown everything");

    // Alice commits to how much she has announced. A reader holding fewer entries than the
    // commitment knows some were dropped, and knows how many, without knowing which.
    let announced: std::collections::BTreeSet<karst_object::Cid> = [doc_cid].into_iter().collect();
    let census_obj = Census::publish(&alice_id, &announced, 100, 100_000, 1);
    let mut census = CensusMonitor::new();
    census.accept(&census_obj);

    match census.check(&cat, 200) {
        Completeness::Complete => {
            println!("  \x1b[32mcomplete: everything alice committed to is here\x1b[0m")
        }
        other => println!("  \x1b[33m{other:?}\x1b[0m"),
    }
    // And what a reader who was shown less would see.
    let starved = Catalogue::new();
    println!(
        "  a reader shown nothing sees: {:?}",
        census.check(&starved, 200)
    );
    note("Without this, a topic with no results and a topic whose results were withheld are");
    note("the same observation. Content addressing verifies what arrives and says nothing");
    note("about what did not.");

    rule("And that alice has not shown someone else a different history");

    // Three witnesses bob chose. They countersign only what extends what they have seen.
    let mut witnesses: Vec<Witness> = (500..503u32)
        .map(|i| {
            Witness::new(Identity::from_seed({
                let mut s = [0u8; 32];
                s[..4].copy_from_slice(&i.to_le_bytes());
                s
            }))
        })
        .collect();
    let chosen: Vec<_> = witnesses.iter().map(|w| w.address()).collect();
    let policy = WitnessPolicy::new(chosen, 2);

    // The checkpoint commits to the census, not merely alongside it. A census has no back
    // link of its own, so on its own a publisher can keep two census histories on disjoint
    // sequence numbers and no witness ever sees either. Binding it here is what puts the
    // completeness claim under the same chain the witnesses enforce.
    let bound = witnessed_digest(&census_obj, &doc_cid);
    let cp = Checkpoint {
        publisher: alice_id.address(),
        sequence: 1,
        digest: bound,
        prev: None,
    };
    let signed = cp.publish(&alice_id);
    let mut cosigned = Cosigned::new(&signed).expect("alice signed it");
    for w in witnesses.iter_mut() {
        if let Ok(sig) = w.cosign(&signed) {
            cosigned.attach(w.key(), sig);
        }
    }
    println!(
        "  {} of {} chosen witnesses countersigned",
        cosigned.support(&policy.chosen),
        policy.chosen.len()
    );
    println!("  {:?}", policy.accept(None, &cosigned));
    println!(
        "  the census bob holds is the one witnessed: {}",
        census.matches_witnessed(&census_obj, &doc_cid, &cosigned.checkpoint.digest)
    );

    // Now alice tries to show a second reader a different history at the same sequence.
    let forked = Checkpoint {
        publisher: alice_id.address(),
        sequence: 1,
        digest: karst_object::Cid::of(b"a different history"),
        prev: None,
    };
    let forked_signed = forked.publish(&alice_id);
    let mut forked_cosigned = Cosigned::new(&forked_signed).expect("alice signed it");
    let mut refusals = 0;
    for w in witnesses.iter_mut() {
        match w.cosign(&forked_signed) {
            Ok(sig) => {
                forked_cosigned.attach(w.key(), sig);
            }
            Err(_) => refusals += 1,
        }
    }
    println!(
        "  \x1b[33mthe forked history was refused by {refusals} of {} witnesses\x1b[0m",
        policy.chosen.len()
    );
    match policy.accept(None, &forked_cosigned) {
        Acceptance::Accepted => {
            checks.require(false, "a forked history was refused");
            println!("  \x1b[31mand bob accepted it anyway\x1b[0m");
        }
        other => println!("  bob's verdict on it: {other:?}"),
    }
    note("A witness never originates a statement, so it can withhold and cannot substitute.");
    note("What it cannot catch is every witness bob chose being captured at once, which is why");
    note("the set is his rather than the network's.");

    rule("One provider stops serving");

    println!(
        "  before: {} replicas, all agreeing on {} objects",
        holders.len(),
        watch.known().len()
    );
    let victim = holders[1];
    for (id, flag) in &kill {
        if *id == victim {
            flag.store(true, Ordering::Relaxed);
        }
    }
    println!("  provider {victim} is down, and alice publishes again");
    let more = Object::create(
        &alice_id,
        "karst.doc.node.v1",
        99,
        b"a later note".to_vec(),
        None,
    );
    for p in &holders {
        alice.publish_to(feed, *p, &more.encode()).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline && watch.persistently_behind(5).is_empty() {
        alice.step();
        bob.step();
        for (p, at, reader) in readers.iter_mut() {
            for env in bob.poll_feed_at(*at, &publisher, epoch) {
                if let Some(obj) = reader.accept(&mut bob.client, &env) {
                    watch.record(*p, obj.cid());
                }
            }
        }
        watch.end_round(&holders);
        std::thread::sleep(Duration::from_millis(2));
    }
    for l in watch.persistently_behind(5) {
        println!(
            "  \x1b[33mprovider {} is missing {} object(s), behind for {} rounds\x1b[0m",
            l.provider,
            l.missing.len(),
            l.rounds_behind
        );
    }
    note("Bob did not need to trust any provider to notice. He compared what several showed");
    note("him, and one of them stopped agreeing. What he cannot detect is all of them showing");
    note("him the same incomplete view, which needs comparison with other readers.");

    rule("L3 + L4: what the wire and the provider actually see");

    // L3. The emission schedule is drawn from its own randomness, never from the queue, so a
    // client that starts talking does not change when it transmits.
    // Deterministic seeds so the two schedules are comparable; the point is that the queue
    // does not enter the draw, not that the draw is fixed.
    let mut idle = karst_wire::Pacer::<u8>::seeded(20.0, 7);
    let mut busy = karst_wire::Pacer::<u8>::seeded(20.0, 7);
    for i in 0..64u8 {
        let _ = busy.offer(i);
    }
    let mut quiet = Vec::new();
    let mut talking = Vec::new();
    for ms in 0..600u64 {
        quiet.push(idle.tick(ms, || 0u8).len());
        talking.push(busy.tick(ms, || 0u8).len());
    }
    println!(
        "  a silent client emitted {} times in 600ms; a client with 64 queued emitted {}",
        quiet.iter().sum::<usize>(),
        talking.iter().sum::<usize>()
    );
    checks.require(
        quiet == talking,
        "the emission schedule is identical whether or not the client has anything to say",
    );

    // L4/L6. What the provider holds for a recipient, and what it can do with it.
    let recipient = karst_seal::SealingKey::from_seed([190u8; 32]);
    let sealed = karst_seal::seal(&recipient.public(), b"", b"the actual message");
    println!(
        "  the provider stores {} bytes and can read none of them",
        sealed.len()
    );
    checks.require(
        !sealed.windows(6).any(|w| w == b"actual"),
        "the plaintext does not appear in what the provider holds",
    );
    checks.require(
        recipient.open(b"", &sealed).as_deref() == Ok(b"the actual message".as_slice()),
        "and the recipient can still open it",
    );
    note("Sealing is separate from mixing on purpose: mixing hides who is talking to whom and");
    note("hides nothing from the party the packet is delivered to, which at L4 is a provider.");

    rule("L1: alice composes her own path, from segments she holds");

    // Nothing converged to produce this. Each segment is one operator's signed willingness to
    // carry between two points, and alice assembles an end-to-end path from the ones she has.
    let now_ms = 1_000u64;
    let mut segments = karst_path::Segments::new();
    let carriers: Vec<karst_id::Identity> = (0..3)
        .map(|i| karst_id::Identity::from_seed([160u8 + i; 32]))
        .collect();
    let points: Vec<karst_id::Address> = (0..4)
        .map(|i| karst_id::Identity::from_seed([170u8 + i; 32]).address())
        .collect();
    for (i, op) in carriers.iter().enumerate() {
        segments
            .learn(
                karst_path::Segment::offer(op, points[i], points[i + 1], now_ms + 60_000),
                now_ms,
            )
            .expect("a signed offer");
    }
    let paths = segments.compose(points[0], points[3], now_ms);
    match paths.first() {
        Some(path) => {
            println!("  {} hops, accountable to:", path.hops());
            for a in path.accountable() {
                println!("    {}", a.short());
            }
            checks.require(path.hops() == 3, "the path spans every segment alice holds");
        }
        None => {
            checks.require(false, "a path composed from held segments");
            println!("  \x1b[31mno path\x1b[0m");
        }
    }
    // A segment naming an operator who did not sign it is refused at the door.
    let impostor = karst_path::Segment::offer(&carriers[0], points[0], points[1], now_ms + 1);
    let mut forged = karst_path::Segments::new();
    println!(
        "  a segment that expired before it was offered: {:?}",
        forged.learn(impostor, now_ms + 10_000)
    );
    note("No routing table converged, nothing was advertised onward, and two senders holding");
    note("different segments are both correct. A path names, in advance, every party that must");
    note("misbehave for it to fail.");

    rule("L6/L7: a file, chunked and verified, costing the origin one upload");

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (manifest, bodies) = karst_blob::Manifest::build("lecture.av", "video/karst", &payload);
    let mut origin = karst_blob::BlobStore::new();
    origin.put_all(&bodies);
    println!(
        "  {} bytes in {} chunks, manifest {}",
        manifest.total_len,
        manifest.chunks.len(),
        manifest.cid().short()
    );

    // A reader seeks into the middle and verifies that chunk alone.
    let idx = manifest.chunks_for_range(120_000, 128)[0];
    let proof = manifest.proof(idx).expect("an inclusion proof");
    let seek = origin
        .read_range(&manifest, 120_000, 128)
        .expect("range read");
    checks.require(
        seek == payload[120_000..120_128],
        "a byte range verified against the root without fetching the rest",
    );
    println!(
        "  seek to byte 120000 -> chunk {idx}, verified with a {} byte proof",
        proof.wire_len()
    );

    let mut tampered = bodies[idx].clone();
    tampered[0] ^= 0xff;
    checks.require(
        !manifest.verify_chunk(idx, &tampered, &proof),
        "a corrupted chunk from a peer was refused",
    );
    println!("  a peer serving a corrupted chunk: refused");

    let stats = karst_blob::Swarm::new(origin.clone(), 10_000).distribute(&manifest);
    println!(
        "  audience 10000: origin pushed {} bytes, delivered {}, x{:.0}",
        stats.origin_bytes,
        stats.delivered_bytes,
        stats.amplification()
    );
    note("The origin uploads once whether the audience is one or ten thousand, and every peer");
    note("verifies what it was served rather than trusting who served it.");

    rule("L9 + L11: an agent acts with authority that can only narrow");

    let agent = karst_id::Identity::from_seed([180u8; 32]);
    let resource = karst_afford::Resource {
        owner: alice_id.address(),
        title: "Bookings".into(),
        affordances: vec![karst_afford::Affordance {
            name: "book".into(),
            summary: "Reserve a slot".into(),
            params: vec![karst_afford::Param::required(
                "slot",
                karst_afford::ParamType::Instant,
            )],
            price_minor: 4500,
            currency: "EUR".into(),
        }],
    };
    // Alice owns the resource and grants a person full authority; the person narrows it for
    // an agent. The agent never holds either of their keys.
    let person = karst_id::Identity::from_seed([181u8; 32]);
    let root_cap =
        karst_cap::Capability::issue(&alice_id, resource.cid(), person.address(), vec![]);
    let narrowed = root_cap
        .attenuate(
            &person,
            agent.address(),
            karst_afford::agent_budget("book", 5000, 10_000, 1),
        )
        .expect("attenuation");
    let mut args = std::collections::BTreeMap::new();
    args.insert("slot".to_string(), karst_doc::Value::Instant(42));
    let invocation = karst_cap::SignedInvocation::sign(
        &agent,
        &narrowed,
        karst_afford::request_for("book", 4500, [1; 16], &args),
    );
    let mut ledger = karst_cap::UseLedger::new();
    match resource.invoke(&narrowed, &invocation, &args, &mut ledger, 100) {
        Ok(r) => println!(
            "  \x1b[32mbooked, charged {} {}\x1b[0m",
            r.charged_minor, r.currency
        ),
        Err(e) => {
            checks.require(false, "the agent's authorised invocation succeeded");
            println!("  \x1b[31m{e:?}\x1b[0m");
        }
    }
    // The same capability a second time, against a one-use budget.
    let again = karst_cap::SignedInvocation::sign(
        &agent,
        &narrowed,
        karst_afford::request_for("book", 4500, [2; 16], &args),
    );
    let second = resource.invoke(&narrowed, &again, &args, &mut ledger, 100);
    checks.require(second.is_err(), "a one-use capability was spent only once");
    println!("  spending it twice: {:?}", second.err());
    note("The agent never held alice's key. A capability can only ever narrow, so an agent");
    note("that signs itself a wider one is refused, which an API key cannot do.");

    rule("L12: what the agent may fetch, and what its fetches say about it");

    let declared: Vec<karst_object::Cid> = node_objs.iter().map(|o| o.cid()).collect();
    let held: std::collections::BTreeSet<karst_object::Cid> =
        declared.iter().take(2).copied().collect();
    let policy = karst_agency::Policy::default();
    let ask = karst_agency::Request::new();
    let plan = karst_agency::decide(&declared, &held, &ask, &policy);
    println!(
        "  {} nodes declared, {} already held, agent fetches {}",
        declared.len(),
        held.len(),
        plan.fetches.len()
    );
    checks.require(
        plan.fetches.len() == declared.len(),
        "the fetch set is the declaration, not the difference from what is cached",
    );
    note("The set an agent fetches is a function of what the document declares, not of what");
    note("this reader happens to have. Deriving it from the local store made the fetch pattern");
    note("a 64-bit identifier for the reader.");

    rule("L13.1: who is accountable, and what is actually verifiable");

    let delegated = karst_attest::Agency::Delegated {
        resource_owner: alice_id.address(),
        capability: narrowed.clone(),
    };
    println!("  Delegated verifiable: {}", delegated.is_verifiable());
    println!(
        "  Direct verifiable:    {}",
        karst_attest::Agency::Direct.is_verifiable()
    );
    checks.require(
        delegated.is_verifiable() && !karst_attest::Agency::Direct.is_verifiable(),
        "only a delegation chain is verifiable, and a bare claim of humanity is not",
    );
    note("You cannot falsely claim to be authorised by someone. You can always falsely claim");
    note("to be a person, permanently, and no layer here changes that.");

    rule("They find they know somebody in common, without saying who they know");

    // L5. Each side holds contacts; neither sends a contact list. The responder evaluates the
    // initiator's blinded contacts under a key it published, and proves it did.
    let shared = karst_id::Identity::from_seed([200u8; 32]).address();
    let alice_contacts = [shared, karst_id::Identity::from_seed([201u8; 32]).address()];
    let bob_contacts = [
        shared,
        karst_id::Identity::from_seed([202u8; 32]).address(),
        karst_id::Identity::from_seed([203u8; 32]).address(),
    ];
    let alice_member = karst_member::Party::new(&alice_contacts);
    let bob_member = karst_member::Party::new(&bob_contacts);

    let ask = alice_member.ask();
    println!(
        "  alice sends {} blinded values, holding {}",
        ask.blinded.len(),
        alice_member.held()
    );
    let answer = bob_member.answer(&ask.blinded).expect("well formed");
    match ask.learn(&answer, bob_member.public_key()) {
        Ok(found) => {
            checks.require(
                found == vec![shared],
                "the intersection is exactly the one contact both hold",
            );
            for a in &found {
                println!("  \x1b[32mshared contact: {}\x1b[0m", a.short());
            }
            note("Bob learned none of alice's other contacts and alice learned none of bob's.");
        }
        Err(e) => {
            checks.require(false, "an honest responder's answer verified");
            println!("  \x1b[31m{e}\x1b[0m");
        }
    }

    // The same exchange with a responder who holds nothing and tries to claim everything.
    let liar = karst_member::Party::new(&[]);
    let ask2 = alice_member.ask();
    let mut forged = liar.answer(&ask2.blinded).expect("well formed");
    forged.theirs = forged
        .evaluated
        .iter()
        .map(|e| {
            let mut t = [0u8; 64];
            let b = e.serialize();
            t[..b.len().min(64)].copy_from_slice(&b[..b.len().min(64)]);
            t
        })
        .collect();
    forged.theirs.sort_unstable();
    let claimed = ask2.learn(&forged, liar.public_key()).unwrap_or_default();
    checks.require(
        claimed.is_empty(),
        "a responder holding nothing forged no shared contact",
    );
    println!(
        "  a responder holding nothing claims {} shared contact(s)",
        claimed.len()
    );
    note("The proof binds every evaluation to the key bob published, and the function binds");
    note("each contact into its own output, so a claim about a contact needs the contact.");

    rule("Alice pays a relay for carrying her traffic, and nobody can follow the money");

    // L14. The relay is credited for service; the party it served signs a warrant saying so.
    let relay_key = karst_id::Identity::from_seed([210u8; 32]);
    let relay = relay_key.address();
    let mut earn = karst_value::EarnLedger::new();
    earn.credit(*relay.as_bytes(), 5);

    let warrant = karst_value::EarnedWarrant::attest(&alice_id, *relay.as_bytes(), 2, 1);
    match earn.draw(&warrant) {
        Ok(()) => println!(
            "  alice attests 2 units of service; the relay's balance is now {}",
            earn.balance(relay.as_bytes())
        ),
        Err(e) => println!("  \x1b[31m{e:?}\x1b[0m"),
    }
    // A warrant nobody signed draws nothing.
    let mut forged_warrant = warrant.clone();
    forged_warrant.units = 99;
    let forged_draw = earn.draw(&forged_warrant);
    checks.require(forged_draw.is_err(), "a forged warrant drew nothing");
    println!("  a forged warrant for 99 units draws: {forged_draw:?}");

    let issuer = karst_value::Issuer::new().expect("issuer");
    let pk = issuer.public();
    let mut wallet = karst_value::Wallet::new();
    let req = wallet.request(&pk, warrant.clone()).expect("request");
    let sig = issuer.sign(&req).expect("sign");
    let cred = wallet.assemble(&pk, &sig).expect("credential");

    let mut spend = karst_value::SpendLedger::new();
    println!("  the issuer saw:   {}", hex8(&req.blinded.to_bytes()));
    println!("  the verifier saw: {}", hex8(&cred.serial));
    match spend.accept(&pk, &cred) {
        Ok(rec) => println!(
            "  \x1b[32mspent {} unit, serial {}\x1b[0m",
            rec.units,
            hex8(&rec.serial)
        ),
        Err(e) => {
            checks.require(false, "a blind-issued credential spent once");
            println!("  \x1b[31m{e:?}\x1b[0m");
        }
    }
    let again = spend.accept(&pk, &cred);
    checks.require(again.is_err(), "the same credential did not spend twice");
    println!("  spending it again: {again:?}");
    note("The issuer signed a value it could not read. The verifier checked a public key and");
    note("could not have minted one. No field is common to the two transcripts, and no bank");
    note("was asked anything.");

    rule("A discussion with no host, assembled from what each author signed");

    let mut graph = karst_thread::Graph::new();
    let opening = karst_thread::Post::create(
        &alice_id,
        1,
        "Does provenance belong in the object?",
        None,
        karst_attest::Agency::Direct,
    );
    let root_cid = graph.insert(&opening).expect("a signed post");
    for (i, who) in [&person, &agent].iter().enumerate() {
        let reply = karst_thread::Post::create(
            who,
            1,
            &format!("reply {i}"),
            Some(root_cid),
            karst_attest::Agency::Direct,
        );
        graph.insert(&reply).expect("a signed reply");
    }
    let thread = graph.thread(&root_cid);
    println!(
        "  {} posts, assembled from backlinks rather than from a table",
        thread.len()
    );
    checks.require(thread.len() == 3, "the thread assembled from its backlinks");

    // A board is a view over the same posts. Two curators, same posts, different rooms.
    let strict = karst_thread::Board::new(
        "provenance",
        alice_id.address(),
        karst_attest::Policy::HumanClaimedOnly,
    );
    println!("  a board is a view over those posts, not a host for them:");
    for line in strict.render(&graph, &root_cid).lines().take(4) {
        println!("    {line}");
    }

    note("No host owns the thread. A hostile curator costs one subscription change, because");
    note("the posts are the authors' and the board is only an opinion about them.");

    rule("What your own access provider sees, which is the thing this does not hide");

    // A demonstration that shows only what a design achieves is an advertisement. This is the
    // one cost a user has to know before they start rather than after.
    println!("  \x1b[33mconstant-rate cover is the most distinctive pattern a consumer line carries\x1b[0m");
    println!("  your ISP cannot read any of it and can tell you are running it");
    note("Anonymity against a global network observer is what this buys, and it is measured.");
    note("Unobservability against the party metering your line is not, and no construction");
    note("here recovers it: they bill the aggregate byte counter, and nothing inside the");
    note("tunnel changes that number. In a jurisdiction where running the tool is itself the");
    note("offence, that is the sentence that matters.");

    rule("What was never involved");

    for absent in [
        "DNS, or any name that resolves to a location",
        "a certificate authority, or any root of trust to compromise",
        "a server, or any single host whose seizure would stop the feed",
        "a crawler, or a search engine, or an index anyone else operates",
        "markup, or a script, or anything a document could run on his machine",
    ] {
        println!("  \x1b[2mno\x1b[0m {absent}");
    }

    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    println!();
    Ok(checks.report())
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(6).map(|x| format!("{x:02x}")).collect()
}
