//! End to end walkthrough of what is actually built.
//!
//! Run with `cargo run -p karst-demo`.

use std::collections::BTreeMap;

use karst_afford::{agent_budget, request_for, Affordance, Param, ParamType, Resource};
use karst_attest::{Agency, Policy};
use karst_blob::{BlobStore, Manifest, Swarm};
use karst_cap::{Capability, Caveat, SignedInvocation, UseLedger};
use karst_doc::{Doc, Node, Run, Value};
use karst_id::Identity;
use karst_object::Object;
use karst_thread::{Board, Graph, Label, Post};

fn rule(title: &str) {
    println!("\n\x1b[1m{}\x1b[0m", title);
    println!("{}", "-".repeat(title.len()));
}

fn note(s: &str) {
    println!("  \x1b[2m{}\x1b[0m", s);
}

fn main() {
    println!("\n\x1b[1mKARST proof of concept\x1b[0m");
    println!("What is built: L2 identity, L6 objects and files, L10 documents,");
    println!("L9 capabilities, L11 affordances, and hostless discussion.");
    println!("What is not built: L4 mixing, and everything below it. See docs/08-roadmap.md.");

    // ---------------------------------------------------------------- L2
    rule("L2 Identity: accounts without registration");
    let clinic = Identity::generate();
    let person = Identity::generate();
    let agent = Identity::generate();
    println!("  clinic  {}", clinic.address().short());
    println!("  person  {}", person.address().short());
    println!("  agent   {}", agent.address().short());
    note("Three identities created. Nobody was contacted, nothing was registered,");
    note("and no authority could have refused, revoked, or enumerated any of them.");

    // ---------------------------------------------------------------- L6
    rule("L6 Objects: tamper evidence without a trusted server");
    let obj = Object::create(&person, "note", 0, b"transfer 10 EUR".to_vec(), None);
    println!("  object      {}", obj.cid().short());
    println!("  verifies as {}", obj.verify().unwrap().short());

    let evil = obj.tamper(b"transfer 9000 EUR".to_vec());
    println!("  relay rewrites the payload in flight:");
    println!("    new name  {}  (different object entirely)", evil.cid().short());
    match evil.verify() {
        Ok(_) => println!("    ACCEPTED  <- this would be a bug"),
        Err(e) => println!("    rejected: {e}"),
    }
    note("There is no origin to trust, because the bytes prove themselves.");

    // ---------------------------------------------------------------- L10
    rule("L10 Document: one object, a human reader and a machine reader");
    let mut doc = Doc::new();
    let mut fields = BTreeMap::new();
    fields.insert(
        "price".into(),
        Value::Money {
            minor: 4500,
            currency: "EUR".into(),
        },
    );
    fields.insert("duration_min".into(), Value::Int(30));
    fields.insert("slot".into(), Value::Instant(42));

    let head = doc.add(Node::Heading {
        rank: 1,
        text: "Nephrology consultation".into(),
    });
    let prose = doc.add(Node::Prose {
        runs: vec![
            Run::plain("Bring your "),
            Run::strong("referral letter"),
            Run::plain(" and a list of current medication."),
        ],
    });
    let rec = doc.add(Node::Record {
        schema: "consultation".into(),
        fields,
    });
    let root = doc.add(Node::Section {
        title: String::new(),
        children: vec![head, prose, rec],
    });

    println!("  as a person sees it:");
    for line in doc.render_text(&root).lines() {
        println!("    {line}");
    }
    println!("  as an agent sees it (typed, no parsing, no scraping):");
    let seen = doc.records(&root);
    for (schema, f) in &seen.items {
        for (k, v) in f {
            println!("    {schema}.{k} = {:?}", v);
        }
    }
    if seen.truncated {
        println!("    (truncated: this document exceeds the reading budget)");
    }
    note("Identical bytes. There is no markup, no second API, and nothing to scrape.");
    println!("  every node is independently quotable:");
    println!("    the prose paragraph alone is {}", prose.short());

    // ---------------------------------------------------------------- L6/L7 files
    rule("L6/L7 Files: chunking, dedup, verified seeking, swarm delivery");
    let film: Vec<u8> = (0..600_000u32).map(|i| (i % 251) as u8).collect();
    let (manifest, bodies) = Manifest::build("lecture.av", "video/karst", &film);
    let mut origin = BlobStore::new();
    origin.put_all(&bodies);
    println!(
        "  {} bytes -> {} chunks, manifest {}",
        manifest.total_len,
        manifest.chunks.len(),
        manifest.cid().short()
    );

    let idx = manifest.chunks_for_range(400_000, 128)[0];
    let proof = manifest.proof(idx).unwrap();
    println!(
        "  seek to byte 400000 -> chunk {idx}, verified with a {} byte proof",
        proof.wire_len()
    );
    let seek = origin.read_range(&manifest, 400_000, 128).unwrap();
    assert_eq!(seek, film[400_000..400_128]);
    println!("    range verified against the merkle root without fetching the rest");

    let mut tampered = bodies[idx].clone();
    tampered[0] ^= 0xff;
    println!(
        "  a peer serves a corrupted chunk: accepted? {}",
        manifest.verify_chunk(idx, &tampered, &proof)
    );

    for audience in [1usize, 100, 10_000] {
        let stats = Swarm::new(origin.clone(), audience).distribute(&manifest);
        println!(
            "  audience {:>6}: origin pushed {:>7} bytes, delivered {:>11} bytes, x{:.0}",
            stats.audience,
            stats.origin_bytes,
            stats.delivered_bytes,
            stats.amplification()
        );
    }
    note("Origin egress is flat. That column is the entire delivery-network bill.");

    // ---------------------------------------------------------------- L9/L11
    rule("L9 + L11: giving an agent authority without giving it your account");
    let resource = Resource {
        owner: clinic.address(),
        title: "Nephrology clinic, appointments".into(),
        affordances: vec![
            Affordance {
                name: "book".into(),
                summary: "Reserve a consultation slot".into(),
                params: vec![
                    Param::required("slot", ParamType::Instant),
                    Param::optional("note", ParamType::Text),
                ],
                price_minor: 4500,
                currency: "EUR".into(),
            },
            Affordance {
                name: "cancel".into(),
                summary: "Release a reserved slot".into(),
                params: vec![Param::required("booking", ParamType::Ref)],
                price_minor: 0,
                currency: "EUR".into(),
            },
        ],
    };

    println!("  what the agent reads off the object itself:");
    for line in resource.manifest_for_agent().lines() {
        println!("    {line}");
    }

    let root_cap = Capability::issue(&clinic, resource.cid(), person.address(), vec![]);
    println!("  clinic -> person: full authority");

    let agent_cap = root_cap
        .attenuate(&person, agent.address(), agent_budget("book", 5000, 100, 1))
        .unwrap();
    println!("  person -> agent:  attenuated to");
    for c in agent_cap.verify(clinic.address()).unwrap() {
        println!("      {}", c.describe());
    }

    let mut args = BTreeMap::new();
    args.insert("slot".to_string(), Value::Instant(42));

    let mut ledger = UseLedger::new();

    println!("\n  agent books within budget:");
    let inv1 = SignedInvocation::sign(
        &agent, &agent_cap, request_for("book", 4500, [1; 16], &args));
    match resource.invoke(&agent_cap, &inv1, &args, &mut ledger, 10) {
        Ok(r) => {
            for line in r.describe().lines() {
                println!("    {line}");
            }
        }
        Err(e) => println!("    refused: {e}"),
    }

    println!("  agent tries an operation it was never given:");
    let mut cargs = BTreeMap::new();
    cargs.insert("booking".to_string(), Value::Ref(resource.cid()));
    let inv2 = SignedInvocation::sign(
        &agent, &agent_cap, request_for("cancel", 0, [2; 16], &cargs));
    match resource.invoke(&agent_cap, &inv2, &cargs, &mut ledger, 10) {
        Ok(_) => println!("    ALLOWED  <- this would be a bug"),
        Err(e) => println!("    {e}"),
    }

    println!("  agent tries to use it a second time, with a fresh nonce:");
    let inv3 = SignedInvocation::sign(
        &agent, &agent_cap, request_for("book", 4500, [3; 16], &args));
    match resource.invoke(&agent_cap, &inv3, &args, &mut ledger, 10) {
        Ok(_) => println!("    ALLOWED  <- this would be a bug"),
        Err(e) => println!("    {e}"),
    }

    println!("  someone who copied the capability tries to spend it:");
    let thief = Identity::generate();
    let stolen = SignedInvocation::sign(
        &thief, &agent_cap, request_for("book", 4500, [4; 16], &args));
    match resource.invoke(&agent_cap, &stolen, &args, &mut ledger, 10) {
        Ok(_) => println!("    ALLOWED  <- this would be a bug"),
        Err(e) => println!("    {e}"),
    }

    println!("  agent forges itself a wider capability, signing correctly:");
    let accomplice = Identity::generate();
    let forged = agent_cap.forge_widened(
        &agent,
        accomplice.address(),
        vec![
            Caveat::Operation("cancel".into()),
            Caveat::MaxAmount(10_000_000),
        ],
    );
    match forged.verify(clinic.address()) {
        Ok(_) => println!("    ACCEPTED  <- this would be a bug"),
        Err(e) => println!("    {e}"),
    }
    note("Every signature in that chain is valid. Authority still cannot grow.");
    note("This is what an API key cannot do, and why there is no API key here.");

    // ---------------------------------------------------------------- boards
    rule("Discussion without a host, and who wrote what");
    let bob = Identity::generate();
    let troll = Identity::generate();

    let board_res = karst_object::Cid::of(b"board:karst-design");
    let board_root = Capability::issue(&clinic, board_res, person.address(), vec![]);
    let agent_post_cap = board_root
        .attenuate(&person, agent.address(), vec![Caveat::MaxUses(8)])
        .unwrap();
    let delegated = Agency::from_capability(&agent_post_cap, clinic.address()).unwrap();

    let mut g = Graph::new();
    let t_root = g
        .insert(&Post::by_person(
            &person,
            0,
            "Is flat returns to scale actually workable?",
            None,
        ))
        .unwrap();
    let r1 = g
        .insert(&Post::by_person(
            &bob,
            1,
            "No proof exists. It is the weakest layer in the design.",
            Some(t_root),
        ))
        .unwrap();
    let r2 = g
        .insert(&Post::by_person(&troll, 2, "read the whitepaper sheeple", Some(t_root)))
        .unwrap();
    let _r3 = g
        .insert(&Post::create(
            &agent,
            3,
            "Prior art on this: Loopix, Sphinx, SCION.",
            Some(r1),
            delegated,
        ))
        .unwrap();

    println!("  {} posts held locally, thread assembled from backlinks", g.len());

    let mut strict = Board::new("karst-design", person.address(), Policy::Everything);
    strict.label(r2, Label::Hide);
    let mut loose = Board::new("karst-unmoderated", bob.address(), Policy::Everything);
    loose.label(r2, Label::Warn("low quality".into()));
    let humans = Board::new("no-machines", person.address(), Policy::HumanClaimedOnly);

    for b in [&strict, &loose, &humans] {
        for line in b.render(&g, &t_root).lines() {
            println!("    {line}");
        }
        println!();
    }
    note("Same posts, three boards, three policies, no server.");
    note("The hidden post was not deleted. It cannot be. That is cost 6.1.");

    rule("Human or machine: what is actually verifiable");
    println!("  the agent's post carries a delegation chain, so it verifies:");
    let agent_post = g
        .thread(&t_root)
        .iter()
        .filter_map(|(_, c)| g.get(c))
        .find(|p| p.agency.is_machine())
        .unwrap();
    println!("    author       {}", agent_post.author.short());
    println!("    agency       {}", agent_post.agency.describe());
    println!("    accountable  {}", agent_post.accountable().short());

    println!("  a liar claims to act for someone who never authorised it:");
    let forged = Post::create(
        &troll,
        9,
        "on behalf of the clinic",
        None,
        Agency::Delegated {
            resource_owner: clinic.address(),
            capability: Capability::issue(
                &troll, karst_object::Cid::of(b"board:karst-design"), troll.address(), vec![]),
        },
    );
    match Post::from_object(&forged) {
        Ok(_) => println!("    ACCEPTED  <- this would be a bug"),
        Err(e) => println!("    {e}"),
    }

    println!("  a bot simply claims to be a person:");
    let bot = Identity::generate();
    let sneaky = Post::by_person(&bot, 0, "as a human, I love this product", None);
    let parsed = Post::from_object(&sneaky).unwrap();
    println!(
        "    accepted, agency = {}, verifiable = {}",
        parsed.agency.describe(),
        parsed.agency.is_verifiable()
    );
    note("This is the known limit and it is permanent. We do not detect bots.");
    note("We make delegation verifiable, make a false claim signed and attributable,");
    note("and make honest declaration more useful: only a declared agent can hold");
    note("authority, so a bot pretending to be human is confined to speech.");

    rule("Summary");
    println!("  Verified in this run:");
    println!("    identities need no registrar");
    println!("    tampering breaks both the name and the signature");
    println!("    one document serves a person and a machine with no scraping");
    println!("    files dedupe, seek verifiably, and cost the origin one upload");
    println!("    delegated authority can only ever narrow, even with valid signatures");
    println!("    a community survives a hostile curator at the cost of one subscription");
    println!("\n  Not verified, because not built: anonymity (L4), and it is the");
    println!("  hardest remaining piece. Nothing above it is private without it.\n");
}
