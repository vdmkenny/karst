//! Property tests for design commitment 4: **reject, never recover.**
//!
//! Issue #25. The claim throughout the design is that malformed input is an error rather
//! than something to be heroically repaired, because parser differentials are how a signed
//! document comes to mean two things to two implementations. A claim like that deserves a
//! fuzzer rather than confidence.
//!
//! Four properties, checked against every decoder in the stack:
//!
//! 1. **No panic.** Arbitrary bytes produce `Ok` or `Err`, never a crash. A decoder that
//!    panics on hostile input is a denial of service in a network where anyone may send you
//!    anything.
//! 2. **No unbounded allocation.** Length prefixes are attacker-controlled and are read
//!    before the elements exist, so every count is capped before it reaches
//!    `Vec::with_capacity`.
//! 3. **Round trip.** `decode(encode(v)) == v` for every value.
//! 4. **Canonicality.** `encode(decode(b)) == b` for every byte string that decodes. This is
//!    the strong one: it means exactly one byte string names each value, so no two
//!    implementations can disagree about what a document says, and a content address remains
//!    a function of its content.
//!
//! Property 4 is what actually forecloses the differential. Property 1 only stops the crash.

use std::collections::BTreeMap;

use karst_attest::Agency;
use karst_cap::{Capability, Caveat};
use karst_doc::{Emphasis, Node, Run, Value};
use karst_id::Identity;
use karst_object::{Cid, Dec, Enc};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Every decoder in the stack, behind one interface so the properties apply uniformly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    DocNode,
    DocValue,
    DocRun,
    CapCaveat,
    CapCapability,
    AttestAgency,
}

pub const ALL_TARGETS: [Target; 6] = [
    Target::DocNode,
    Target::DocValue,
    Target::DocRun,
    Target::CapCaveat,
    Target::CapCapability,
    Target::AttestAgency,
];

/// Decode `bytes` and, if it succeeds, re-encode the result.
///
/// Returns `None` when the input is rejected, which is the expected outcome for almost all
/// input. Returns `Some(reencoded)` when it decodes, and canonicality demands that equal the
/// original bytes.
pub fn round_trip(target: Target, bytes: &[u8]) -> Option<Vec<u8>> {
    match target {
        Target::DocNode => {
            let n = Node::from_bytes(bytes).ok()?;
            Some(n.encode())
        }
        Target::DocValue => {
            let mut d = Dec::new(bytes);
            let v = Value::decode(&mut d).ok()?;
            d.end().ok()?;
            let mut e = Enc::new();
            v.encode(&mut e);
            Some(e.finish())
        }
        Target::DocRun => {
            let mut d = Dec::new(bytes);
            let r = Run::decode(&mut d).ok()?;
            d.end().ok()?;
            let mut e = Enc::new();
            r.encode(&mut e);
            Some(e.finish())
        }
        Target::CapCaveat => {
            let mut d = Dec::new(bytes);
            let c = Caveat::decode(&mut d).ok()?;
            d.end().ok()?;
            let mut e = Enc::new();
            c.encode_public(&mut e);
            Some(e.finish())
        }
        Target::CapCapability => {
            let mut d = Dec::new(bytes);
            let c = Capability::decode(&mut d).ok()?;
            d.end().ok()?;
            let mut e = Enc::new();
            c.encode(&mut e);
            Some(e.finish())
        }
        Target::AttestAgency => {
            let mut d = Dec::new(bytes);
            let a = Agency::decode(&mut d).ok()?;
            d.end().ok()?;
            let mut e = Enc::new();
            a.encode(&mut e);
            Some(e.finish())
        }
    }
}

/// A corpus of valid encodings, one per shape the format can take.
pub fn valid_corpus() -> Vec<(Target, Vec<u8>)> {
    let mut out = Vec::new();
    let cid = Cid::of(b"anchor");

    // Documents.
    let mut fields = BTreeMap::new();
    fields.insert("alpha".to_string(), Value::Int(-9));
    fields.insert(
        "beta".to_string(),
        Value::Money {
            minor: 4500,
            currency: "EUR".into(),
        },
    );
    fields.insert("gamma".to_string(), Value::Ref(cid));

    for n in [
        Node::Prose {
            runs: vec![Run::plain("a"), Run::strong("b"), Run::link("c", cid)],
        },
        Node::Prose { runs: vec![] },
        Node::Heading {
            rank: 3,
            text: "title".into(),
        },
        Node::List {
            ordered: true,
            items: vec![cid, cid],
        },
        Node::List {
            ordered: false,
            items: vec![],
        },
        Node::Record {
            schema: "s".into(),
            fields: fields.clone(),
        },
        Node::Record {
            schema: String::new(),
            fields: BTreeMap::new(),
        },
        Node::Media {
            mime: "video/x".into(),
            source: cid,
            description: "d".into(),
            duration_ms: Some(90_000),
        },
        Node::Media {
            mime: "image/x".into(),
            source: cid,
            description: String::new(),
            duration_ms: None,
        },
        Node::Quote {
            source: cid,
            comment: "why".into(),
        },
        Node::Section {
            title: "t".into(),
            children: vec![cid],
        },
    ] {
        out.push((Target::DocNode, n.encode()));
    }

    for v in [
        Value::Text("x".into()),
        Value::Text(String::new()),
        Value::Int(i64::MIN),
        Value::Int(i64::MAX),
        Value::Bool(true),
        Value::Bool(false),
        Value::Money {
            minor: -1,
            currency: "USD".into(),
        },
        Value::Instant(u64::MAX),
        Value::Ref(cid),
    ] {
        let mut e = Enc::new();
        v.encode(&mut e);
        out.push((Target::DocValue, e.finish()));
    }

    for r in [
        Run::plain(""),
        Run::strong("bold"),
        Run::link("linked", cid),
        Run {
            text: "s".into(),
            emphasis: Emphasis::Stress,
            link: None,
        },
        Run {
            text: "l".into(),
            emphasis: Emphasis::Literal,
            link: Some(karst_doc::Link::Pinned(cid)),
        },
    ] {
        let mut e = Enc::new();
        r.encode(&mut e);
        out.push((Target::DocRun, e.finish()));
    }

    // Capabilities.
    for c in [
        Caveat::Operation("book".into()),
        Caveat::Operation(String::new()),
        Caveat::MaxAmount(0),
        Caveat::MaxAmount(u64::MAX),
        Caveat::ExpiresAt(7),
        Caveat::MaxUses(u32::MAX),
    ] {
        let mut e = Enc::new();
        c.encode_public(&mut e);
        out.push((Target::CapCaveat, e.finish()));
    }

    let owner = Identity::from_seed([1u8; 32]);
    let person = Identity::from_seed([2u8; 32]);
    let agent = Identity::from_seed([3u8; 32]);
    let root = Capability::issue(&owner, cid, person.address(), vec![]);
    let scoped = root
        .attenuate(
            &person,
            agent.address(),
            vec![Caveat::MaxUses(1), Caveat::MaxAmount(500)],
        )
        .expect("attenuation of a fresh root capability");

    for c in [&root, &scoped] {
        let mut e = Enc::new();
        c.encode(&mut e);
        out.push((Target::CapCapability, e.finish()));
    }

    // Authorship.
    for a in [
        Agency::Direct,
        Agency::Assisted {
            tool: "editor".into(),
        },
        Agency::Assisted {
            tool: String::new(),
        },
        Agency::Autonomous {
            operator: agent.address(),
        },
        Agency::from_capability(&scoped, owner.address()).expect("valid capability"),
    ] {
        let mut e = Enc::new();
        a.encode(&mut e);
        out.push((Target::AttestAgency, e.finish()));
    }

    out
}

/// Mutations that a hostile peer can apply for free.
pub fn mutate(rng: &mut StdRng, base: &[u8]) -> Vec<u8> {
    if base.is_empty() {
        return vec![rng.gen()];
    }
    let mut v = base.to_vec();
    match rng.gen_range(0..7) {
        // Flip one bit.
        0 => {
            let i = rng.gen_range(0..v.len());
            v[i] ^= 1 << rng.gen_range(0..8);
        }
        // Replace one byte.
        1 => {
            let i = rng.gen_range(0..v.len());
            v[i] = rng.gen();
        }
        // Truncate.
        2 => {
            let n = rng.gen_range(0..v.len());
            v.truncate(n);
        }
        // Append, which canonicality must reject as trailing bytes.
        3 => {
            let n = rng.gen_range(1..8);
            for _ in 0..n {
                v.push(rng.gen());
            }
        }
        // Swap two bytes, which reorders fields.
        4 => {
            let (i, j) = (rng.gen_range(0..v.len()), rng.gen_range(0..v.len()));
            v.swap(i, j);
        }
        // Overwrite a length prefix with something enormous.
        5 => {
            if v.len() >= 4 {
                let i = rng.gen_range(0..v.len() - 3);
                v[i..i + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            }
        }
        // Duplicate a slice, which duplicates fields.
        _ => {
            let i = rng.gen_range(0..v.len());
            let j = rng.gen_range(i..v.len());
            let piece: Vec<u8> = v[i..j].to_vec();
            v.extend_from_slice(&piece);
        }
    }
    v
}

/// Run the campaign. Returns the number of inputs that decoded, for reporting.
pub fn campaign(iterations: usize, seed: u64) -> CampaignReport {
    let mut rng = StdRng::seed_from_u64(seed);
    let corpus = valid_corpus();
    let mut report = CampaignReport::default();

    for _ in 0..iterations {
        let (target, base) = &corpus[rng.gen_range(0..corpus.len())];
        let candidate = mutate(&mut rng, base);

        match round_trip(*target, &candidate) {
            None => report.rejected += 1,
            Some(reencoded) => {
                report.accepted += 1;
                if reencoded != candidate {
                    report.non_canonical.push((*target, candidate));
                }
            }
        }
    }

    // Purely random input, which should essentially never decode.
    for _ in 0..iterations {
        let n = rng.gen_range(0..96);
        let bytes: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        for t in ALL_TARGETS {
            match round_trip(t, &bytes) {
                None => report.rejected += 1,
                Some(reencoded) => {
                    report.accepted += 1;
                    if reencoded != bytes {
                        report.non_canonical.push((t, bytes.clone()));
                    }
                }
            }
        }
    }

    report
}

#[derive(Default, Debug)]
pub struct CampaignReport {
    pub accepted: usize,
    pub rejected: usize,
    /// Inputs that decoded but did not re-encode to themselves. Every one is a parser
    /// differential.
    pub non_canonical: Vec<(Target, Vec<u8>)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_object::Object;

    #[test]
    fn the_corpus_itself_round_trips() {
        for (target, bytes) in valid_corpus() {
            let back = round_trip(target, &bytes)
                .unwrap_or_else(|| panic!("{target:?} rejected its own encoding"));
            assert_eq!(back, bytes, "{target:?} did not re-encode to itself");
        }
    }

    /// Property 1 and 4 together, over a large mutated corpus. A panic fails the test by
    /// itself; canonicality is checked explicitly.
    #[test]
    fn no_input_panics_and_everything_accepted_is_canonical() {
        let r = campaign(40_000, 1);
        assert!(
            r.non_canonical.is_empty(),
            "{} non-canonical input(s), first: {:?}",
            r.non_canonical.len(),
            r.non_canonical.first().map(|(t, b)| (t, b.len()))
        );
        assert!(
            r.rejected > 0,
            "the campaign rejected nothing, which cannot be right"
        );
    }

    #[test]
    fn a_second_seed_finds_nothing_either() {
        let r = campaign(40_000, 99);
        assert!(
            r.non_canonical.is_empty(),
            "{} non-canonical",
            r.non_canonical.len()
        );
    }

    /// Property 2. A four byte length prefix can name four billion elements, and reading it
    /// before the elements exist is exactly where a decoder reserves memory it will never
    /// use.
    #[test]
    fn an_enormous_length_prefix_does_not_allocate() {
        // Node::Prose with a run count of u64::MAX.
        let mut e = Enc::new();
        e.str("karst.node.v1").u8(0).u64(u64::MAX);
        assert!(Node::from_bytes(&e.finish()).is_err());

        // Section, List and Record take the same path.
        for tag in [2u8, 6u8] {
            let mut e = Enc::new();
            e.str("karst.node.v1").u8(tag);
            if tag == 2 {
                e.bool(true);
            } else {
                e.str("t");
            }
            e.u64(u64::MAX);
            assert!(
                Node::from_bytes(&e.finish()).is_err(),
                "tag {tag} allocated"
            );
        }

        // And a capability chain length.
        let mut e = Enc::new();
        e.cid(&Cid::of(b"x")).u64(u64::MAX);
        let bytes = e.finish();
        let mut d = Dec::new(&bytes);
        assert!(Capability::decode(&mut d).is_err());
    }

    /// Property 3, stated as its own test so a regression is unambiguous.
    #[test]
    fn every_value_decodes_to_itself() {
        let cid = Cid::of(b"z");
        for v in [
            Value::Text("hello".into()),
            Value::Int(-1),
            Value::Bool(false),
            Value::Money {
                minor: 1,
                currency: "GBP".into(),
            },
            Value::Instant(0),
            Value::Ref(cid),
        ] {
            let mut e = Enc::new();
            v.encode(&mut e);
            let bytes = e.finish();
            let mut d = Dec::new(&bytes);
            assert_eq!(Value::decode(&mut d).unwrap(), v);
            assert!(d.end().is_ok());
        }
    }

    /// Reordered record keys must be refused. Accepting them would let several byte strings
    /// build one `BTreeMap`, so a node would have more than one content address.
    #[test]
    fn record_keys_must_be_strictly_increasing() {
        let mut e = Enc::new();
        e.str("karst.node.v1").u8(3).str("schema").u64(2);
        // Descending order.
        e.str("b");
        Value::Int(1).encode(&mut e);
        e.str("a");
        Value::Int(2).encode(&mut e);
        assert!(
            Node::from_bytes(&e.finish()).is_err(),
            "descending keys accepted"
        );

        // Duplicate keys.
        let mut e = Enc::new();
        e.str("karst.node.v1").u8(3).str("schema").u64(2);
        e.str("a");
        Value::Int(1).encode(&mut e);
        e.str("a");
        Value::Int(2).encode(&mut e);
        assert!(
            Node::from_bytes(&e.finish()).is_err(),
            "duplicate keys accepted"
        );
    }

    #[test]
    fn unknown_tags_are_refused_rather_than_skipped() {
        for tag in [7u8, 8, 200, 255] {
            let mut e = Enc::new();
            e.str("karst.node.v1").u8(tag);
            assert!(
                Node::from_bytes(&e.finish()).is_err(),
                "node tag {tag} accepted"
            );
        }
        for tag in [6u8, 9, 255] {
            let mut e = Enc::new();
            e.u8(tag);
            let b = e.finish();
            let mut d = Dec::new(&b);
            assert!(Value::decode(&mut d).is_err(), "value tag {tag} accepted");
        }
        // Emphasis is a closed set of four.
        for tag in [4u8, 5, 255] {
            assert!(Emphasis::from_tag(tag).is_err(), "emphasis {tag} accepted");
        }
    }

    #[test]
    fn the_wrong_format_version_is_refused() {
        let mut e = Enc::new();
        e.str("karst.node.v2").u8(1).u8(1).str("t");
        assert!(Node::from_bytes(&e.finish()).is_err());
    }

    #[test]
    fn trailing_bytes_are_refused_everywhere() {
        for (target, bytes) in valid_corpus() {
            let mut extended = bytes.clone();
            extended.push(0);
            assert!(
                round_trip(target, &extended).is_none(),
                "{target:?} accepted a trailing byte"
            );
        }
    }

    /// A signed object carrying a document node still rejects a tampered payload, so the
    /// canonicality guarantee composes with the signature rather than sitting beside it.
    #[test]
    fn canonicality_composes_with_signing() {
        let author = Identity::from_seed([9u8; 32]);
        let node = Node::Heading {
            rank: 1,
            text: "notice".into(),
        };
        let obj = Object::create(&author, "doc", 0, node.encode(), None);

        assert_eq!(Node::from_bytes(&obj.payload).unwrap(), node);
        assert!(obj.verify().is_ok());

        let mut evil_payload = node.encode();
        evil_payload.push(0);
        let evil = obj.tamper(evil_payload);
        assert!(evil.verify().is_err(), "signature must catch the change");
        assert!(
            Node::from_bytes(&evil.payload).is_err(),
            "and the decoder must catch it independently"
        );
    }
}

#[cfg(test)]
mod coverage {
    use super::*;

    /// A fuzzer that never accepts anything proves nothing: every property about accepted
    /// input would hold vacuously. This asserts the campaign is actually exercising the
    /// decode path.
    #[test]
    fn the_campaign_accepts_a_meaningful_share_of_mutations() {
        let r = campaign(40_000, 1);
        let total = r.accepted + r.rejected;
        let rate = r.accepted as f64 / total as f64;
        println!(
            "accepted {} rejected {} ({:.2}% accepted), non-canonical {}",
            r.accepted,
            r.rejected,
            rate * 100.0,
            r.non_canonical.len()
        );
        assert!(
            r.accepted > 500,
            "only {} inputs decoded, so the canonicality property is near-vacuous",
            r.accepted
        );
    }
}
