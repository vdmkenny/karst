//! Does the index survive a corpus worth having?
//!
//! Reynolds and Vahdat evaluated peer-to-peer keyword search at 100,000 documents and reported
//! sub-kilobyte queries. Li, Loo, Hellerstein, Kaashoek, Karger and Morris then showed the same
//! approach costs 530 MB per query at three billion documents, a factor of 530 over any
//! plausible budget. **An evaluation of a decentralised index at small corpus size tells you
//! nothing**, and every test in this crate until now was at small corpus size.
//!
//! `cargo run --release -p karst-index --bin karst-indexscale`

use std::time::Instant;

use karst_id::Address;
use karst_index::{Announcement, Catalogue, Ranker, Trust};
use karst_object::Cid;

fn addr(n: u32) -> Address {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    Address::from_raw(b)
}

fn cid(n: u32) -> Cid {
    Cid::of(&n.to_le_bytes())
}

/// A vocabulary with a realistic shape: a few terms are on almost everything, most are rare.
///
/// This matters. Li et al.'s worst case was the query "the who", where one term appears on
/// three billion documents. A uniform vocabulary hides exactly the case that broke the
/// published designs.
fn terms_for(doc: u32, vocab: u32) -> Vec<String> {
    let mut v = vec!["the".to_string()];
    for k in 0..3u32 {
        // Zipf-ish: low ids are common, high ids are rare.
        let t = (doc.wrapping_mul(2654435761).wrapping_add(k * 40503)) % vocab;
        let skewed = (t as f64).powf(1.8) as u32 % vocab;
        v.push(format!("t{skewed}"));
    }
    v
}

fn build(n: u32, vocab: u32, trust: &Trust) -> Catalogue {
    let mut cat = Catalogue::new().with_untrusted_capacity(n as usize * 2);
    for i in 0..n {
        cat.announce(
            Announcement::new(cid(i), addr(i % 5_000), "doc", &terms_for(i, vocab), 0).unwrap(),
            trust,
        );
    }
    cat
}

fn main() {
    println!("\n\x1b[1mL15 at scale\x1b[0m");
    println!("Small-corpus evaluation of a decentralised index is worthless (Li et al. 2003).\n");

    let mut trust = Trust::new();
    for i in 0..64u32 {
        trust.set(addr(i), 1.0);
    }

    println!(
        "  {:>10}  {:>12}  {:>14}  {:>14}",
        "objects", "rare query", "common query", "ratio"
    );
    println!("  {}", "-".repeat(56));

    let mut prev: Option<(u32, f64)> = None;
    for n in [1_000u32, 4_000, 16_000, 64_000, 256_000] {
        let cat = build(n, 20_000, &trust);
        let r = Ranker::new(trust.clone());

        // A rare term: few results, so a well-built index should be nearly free.
        let rare = vec![format!("t{}", 19_997)];
        let t0 = Instant::now();
        let rare_hits = r.search(&cat, &rare).len();
        let rare_ms = t0.elapsed().as_secs_f64() * 1000.0;

        // The term on everything. This is "the who".
        let common = vec!["the".to_string()];
        let t1 = Instant::now();
        let common_hits = r.search(&cat, &common).len();
        let common_ms = t1.elapsed().as_secs_f64() * 1000.0;

        let growth = match prev {
            Some((pn, pms)) if pms > 0.0 => {
                format!("{:.1}x per 4x", common_ms / pms.max(0.0001))
            }
            _ => "-".to_string(),
        };
        prev = Some((n, common_ms));

        println!(
            "  {:>10}  {:>9.2}ms  {:>11.2}ms  {:>14}",
            n, rare_ms, common_ms, growth
        );
        let _ = (rare_hits, common_hits);

        if common_ms > 60_000.0 {
            println!("\n  \x1b[31mabandoned: one query took over a minute\x1b[0m");
            break;
        }
    }

    println!();
    println!("  A linear index grows 4x per 4x. Anything meaningfully above that is");
    println!("  super-linear, and the corpus size where it stops being usable is a");
    println!("  property of the design rather than of the hardware.");
    println!();
}
