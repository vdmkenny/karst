use karst_index::{Announcement, Catalogue, Trust};
use karst_id::Address;
use karst_object::Cid;

fn terms(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Public-API probe: after eviction, does the term index still name the evicted targets?
#[test]
fn probe_by_term_residue() {
    let mut c = Catalogue::new().with_untrusted_capacity(64);
    let t = Trust::new();
    let n = 20_000u32;
    for i in 0..n {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        c.announce(
            Announcement::new(Cid::of(&b), Address::from_raw(b), "doc", &terms(&["x"]), 0).unwrap(),
            &t,
        );
    }
    let cands = c.candidates(&terms(&["x"]));
    eprintln!(
        "untrusted_held={} announcements_len={} candidates_for_x={}",
        c.untrusted_held(),
        c.len(),
        cands.len()
    );
    assert_eq!(c.untrusted_held(), 64);
    assert_eq!(c.len(), 64, "announcements map is bounded");
    assert_eq!(cands.len(), 64, "term index should shrink with eviction");
}

/// Fresh terms per statement: does the term keyspace itself grow without bound?
#[test]
fn probe_fresh_terms_growth() {
    let mut c = Catalogue::new().with_untrusted_capacity(64);
    let t = Trust::new();
    let n = 5_000u32;
    for i in 0..n {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        let ts: Vec<String> = (0..32).map(|j| format!("{:0>60}-{}", i, j)).collect();
        c.announce(
            Announcement::new(Cid::of(&b), Address::from_raw(b), "doc", &ts, 0).unwrap(),
            &t,
        );
    }
    // Probe how many distinct terms are still resolvable.
    let mut live = 0usize;
    for i in 0..n {
        let q: Vec<String> = (0..32).map(|j| format!("{:0>60}-{}", i, j)).collect();
        live += c.candidates(&q).len().min(1) * 32;
    }
    eprintln!(
        "untrusted_held={} announcements_len={} live_term_keys~{} (inserted {})",
        c.untrusted_held(),
        c.len(),
        live,
        n as usize * 32
    );
    assert_eq!(live, 64 * 32, "only surviving statements' terms should resolve");
}
