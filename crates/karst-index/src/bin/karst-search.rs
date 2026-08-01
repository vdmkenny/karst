//! Discovery, with an adversary in the room.
//!
//! `cargo run -p karst-index --bin karst-search`

use karst_id::Address;
use karst_index::{Announcement, Catalogue, Claim, Ranker, Trust, Verdict};
use karst_object::Cid;

fn rule(t: &str) {
    println!("\n\x1b[1m{}\x1b[0m", t);
    println!("{}", "-".repeat(t.len()));
}

fn note(s: &str) {
    println!("  \x1b[2m{}\x1b[0m", s);
}

fn addr(n: u32) -> Address {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    Address::from_raw(b)
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
        (paper, researcher, &["mixing", "anonymity", "poisson"][..]),
        (blog, friend, &["mixing", "notes"][..]),
        // The spammer claims the same terms. Nothing stops them.
        (spam, spammer, &["mixing", "anonymity", "poisson"][..]),
    ] {
        cat.announce(
            Announcement::new(target, who, "doc", &t(terms), 0).unwrap(),
            &trust,
        );
    }

    let names = [(paper, "a paper on continuous mixes"), (blog, "someone's notes"), (spam, "buy cheap mixing")];

    rule("Searching 'mixing anonymity'");
    show(&Ranker::new(trust.clone()), &cat, &["mixing", "anonymity"], &names);
    note("The spammer claimed identical terms and is not lying about existence, only quality.");
    note("They rank last because the reader has no opinion about them, not because anyone");
    note("adjudicated the content.");

    rule("The spammer buys 200,000 identities and announces from all of them");
    for i in 0..200_000u32 {
        cat.announce(
            Announcement::new(spam, addr(1_000 + i), "doc", &t(&["mixing", "anonymity"]), 0)
                .unwrap(),
            &trust,
        );
    }
    show(&Ranker::new(trust.clone()), &cat, &["mixing", "anonymity"], &names);
    note(&format!(
        "The catalogue held {} of them and refused the rest. What got in saturates:",
        cat.untrusted_held()
    ));
    note("a thousand strangers are worth barely more than one, and less than anyone chosen.");

    rule("A moderator the reader trusts disputes the spam");
    trust.set(moderator, 1.0);
    cat.retrust(&trust);
    cat.claim(
        Claim::new(spam, moderator, Verdict::Dispute, &t(&["spam"]), 1).unwrap(),
        &trust,
    );
    show(&Ranker::new(trust.clone()), &cat, &["mixing", "anonymity"], &names);
    note("Moderation, and the reader can drop this moderator and see the previous list again.");

    rule("A second reader, who trusts the spammer and not the researcher");

    // A catalogue belongs to one reader. Eviction already happened according to the first
    // reader's trust, so the second reader builds their own from the same statements.
    let mut other = Trust::new();
    other.set(spammer, 1.0);
    let mut theirs = Catalogue::new();
    for (target, who, terms) in [
        (paper, researcher, &["mixing", "anonymity", "poisson"][..]),
        (blog, friend, &["mixing", "notes"][..]),
        (spam, spammer, &["mixing", "anonymity", "poisson"][..]),
    ] {
        theirs.announce(
            Announcement::new(target, who, "doc", &t(terms), 0).unwrap(),
            &other,
        );
    }
    show(&Ranker::new(other), &theirs, &["mixing", "anonymity"], &names);
    note("Same statements, different order, and a different store. A catalogue is shaped by");
    note("its owner's trust, so there is no single ranking and no single index to capture.");
    println!();
}
