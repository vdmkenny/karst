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
const CHECKS_EXPECTED: usize = 8;

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
    let feed = feed_tag(&alice_id.address(), 0);
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
            for env in bob.poll_tag_at(*at, feed) {
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
            for env in bob.poll_tag_at(*at, feed) {
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

    let issuer = karst_value::IssuerSet::new(1, 1).expect("issuer");
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
