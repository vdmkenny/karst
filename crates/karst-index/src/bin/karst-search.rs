//! Discovery, with an adversary in the room.
//!
//! `cargo run -p karst-index --bin karst-search`

use karst_id::{Address, Identity};
use karst_index::{Announcement, Catalogue, Claim, Ranker, Trust, Verdict};
use karst_object::Cid;

fn rule(t: &str) {
    println!("\n\x1b[1m{}\x1b[0m", t);
    println!("{}", "-".repeat(t.len()));
}

fn note(s: &str) {
    println!("  \x1b[2m{}\x1b[0m", s);
}

fn ident(n: u32) -> Identity {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&n.to_le_bytes());
    Identity::from_seed(seed)
}

fn addr(n: u32) -> Address {
    ident(n).address()
}

/// Publish and verify, which is the only path into a catalogue.
fn announce(cat: &mut Catalogue, who: u32, target: Cid, terms: &[&str], trust: &Trust) {
    let id = ident(who);
    let obj = Announcement::new(target, id.address(), "doc", &t(terms), 0)
        .unwrap()
        .publish(&id, 0);
    cat.announce(Announcement::from_object(&obj).unwrap(), trust);
}

fn t(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn show(r: &Ranker, cat: &Catalogue, query: &[&str], names: &[(Cid, &str)]) {
    for hit in r.search(cat, &t(query)).iter().take(5) {
        let name = names
            .iter()
            .find(|(c, _)| *c == hit.target)
            .map(|(_, n)| *n)
            .unwrap_or("(unknown)");
        println!(
            "  {:>7.3}  {:<34} trusted +{} -{}, strangers {}",
            hit.score, name, hit.trusted_support, hit.trusted_disputes, hit.untrusted_sources
        );
    }
}

fn main() {
    println!("\n\x1b[1mKARST discovery\x1b[0m");
    note("Nobody crawled anything. Every entry here was emitted by whoever published it.");

    let paper = Cid::of(b"a paper on continuous mixes");
    let blog = Cid::of(b"someone's notes on mixing");
    let spam = Cid::of(b"buy cheap mixing");

    let researcher = addr(1);
    let friend = addr(2);
    let spammer = addr(3);
    let moderator = addr(50);

    let mut trust = Trust::new();
    trust.set(researcher, 1.0);
    trust.set(friend, 0.8);

    let mut cat = Catalogue::new();
    for (target, who, terms) in [
        (paper, 1u32, &["mixing", "anonymity", "poisson"][..]),
        (blog, 2, &["mixing", "notes"][..]),
        // The spammer claims the same terms. Nothing stops them.
        (spam, 3, &["mixing", "anonymity", "poisson"][..]),
    ] {
        announce(&mut cat, who, target, terms, &trust);
    }

    let names = [
        (paper, "a paper on continuous mixes"),
        (blog, "someone's notes"),
        (spam, "buy cheap mixing"),
    ];

    rule("Searching 'mixing anonymity'");
    show(
        &Ranker::new(trust.clone()),
        &cat,
        &["mixing", "anonymity"],
        &names,
    );
    note("The spammer claimed identical terms and is not lying about existence, only quality.");
    note("Two axes decide the order: how well a statement matches the query, and how much the");
    note("reader weights whoever made it. The notes match half the query and are weighted 0.8,");
    note("so they score 0.4; the spam matches all of it but comes from nobody the reader knows,");
    note("so it scores the untrusted ceiling of 0.5. A chosen source wins at EQUAL relevance,");
    note("which is the claim that survives. Weighting a source above 1.0 makes trust dominate.");

    rule("The spammer buys 200,000 identities and announces from all of them");
    for i in 0..200_000u32 {
        announce(&mut cat, 1_000 + i, spam, &["mixing", "anonymity"], &trust);
    }
    show(
        &Ranker::new(trust.clone()),
        &cat,
        &["mixing", "anonymity"],
        &names,
    );
    note(&format!(
        "The catalogue held {} of them and refused the rest, and all of them together are",
        cat.untrusted_held()
    ));
    note("worth exactly one untrusted voice. Nothing moved: the second identity gains nothing,");
    note("and neither does the two hundred thousandth. Cheng and Friedman (2005) prove no");
    note("name-blind ranking can manage this, which is why ranking is anchored at the reader.");
    note("Every statement above was signed and verified, so no identity could be borrowed.");

    rule("A moderator the reader trusts disputes the spam");
    trust.set(moderator, 1.0);
    cat.retrust(&trust);
    let mod_id = ident(50);
    let mod_obj = Claim::new(spam, moderator, Verdict::Dispute, &t(&["spam"]), 1)
        .unwrap()
        .publish(&mod_id, 0);
    cat.claim(Claim::from_object(&mod_obj).unwrap(), &trust);
    show(
        &Ranker::new(trust.clone()),
        &cat,
        &["mixing", "anonymity"],
        &names,
    );
    note("Moderation, and the reader can drop this moderator and see the previous list again.");

    rule("A second reader, who trusts the spammer and not the researcher");

    // A catalogue belongs to one reader. Eviction already happened according to the first
    // reader's trust, so the second reader builds their own from the same statements.
    let mut other = Trust::new();
    other.set(spammer, 1.0);
    let mut theirs = Catalogue::new();
    for (target, who, terms) in [
        (paper, 1u32, &["mixing", "anonymity", "poisson"][..]),
        (blog, 2, &["mixing", "notes"][..]),
        (spam, 3, &["mixing", "anonymity", "poisson"][..]),
    ] {
        announce(&mut theirs, who, target, terms, &other);
    }
    show(
        &Ranker::new(other),
        &theirs,
        &["mixing", "anonymity"],
        &names,
    );
    note("Same statements, different order, and a different store. A catalogue is shaped by");
    note("its owner's trust, so there is no single ranking and no single index to capture.");
    println!();
}
