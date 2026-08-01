//! Ranking, in the client, against the reader's own weights.
//!
//! Search has two halves. Discovering that a thing exists is expensive and is solved at L15 by
//! making the author do it once. Deciding what to show first is the other half, and it is the
//! half that must never be solved globally, because a single ranking is a single lever and
//! everyone who wants to pull it knows where it is.
//!
//! So there is no ranking here, only a ranker: a function of the reader's own weights over
//! sources. Two readers with different weights get different orders from identical inputs, and
//! that is the intended behaviour rather than a failure of consistency.
//!
//! # Sybil resistance is L16's mechanic, applied here
//!
//! An adversary with no standing can manufacture identities without limit, so any scheme where
//! untrusted sources contribute additively is defeated by volume alone. Setting their
//! contribution to zero defeats the adversary and also defeats every new author, which is a
//! cold start problem severe enough to make the layer useless.
//!
//! The answer is the one L16 already uses against acquisition: **let it saturate.** The
//! aggregate contribution of untrusted sources approaches a ceiling, so a thousand of them are
//! worth barely more than one, while a single source the reader actually trusts outweighs all
//! of them. Scale stops paying, and it stops paying without anyone having to detect who
//! controls what.
//!
//! ```text
//! untrusted(n) = ceiling * n / (n + K)
//!
//!   n=1     0.50 * ceiling
//!   n=10    0.91 * ceiling
//!   n=1000  0.999 * ceiling
//! ```
//!
//! # What ranking cannot fix
//!
//! An author may lie about their own terms and this layer expects it. The corrective is that
//! third parties dispute, and a reader who trusts a disputer sees the correction. A reader who
//! trusts nobody sees an unfiltered catalogue, which is the honest consequence of choosing to
//! trust nobody rather than a defect to be designed around.

use std::collections::BTreeMap;

use karst_id::Address;
use karst_object::Cid;

use super::{normalise, Catalogue, Verdict};

/// A reader's weights over sources.
#[derive(Debug, Clone)]
pub struct Trust {
    weights: BTreeMap<Address, f64>,
    /// The ceiling that all untrusted sources together approach.
    untrusted_ceiling: f64,
    /// How fast that ceiling is approached. Smaller means faster.
    saturation: f64,
}

impl Default for Trust {
    fn default() -> Self {
        Trust {
            weights: BTreeMap::new(),
            // Below 1.0 on purpose: any single source the reader has actually chosen outweighs
            // every source they have not, no matter how many of the latter there are.
            untrusted_ceiling: 0.5,
            saturation: 1.0,
        }
    }
}

impl Trust {
    pub fn new() -> Self {
        Trust::default()
    }

    /// Trust a source. Weight is the reader's business; 1.0 is a sensible unit.
    pub fn set(&mut self, who: Address, weight: f64) -> &mut Self {
        self.weights.insert(who, weight);
        self
    }

    pub fn with_ceiling(mut self, ceiling: f64) -> Self {
        self.untrusted_ceiling = ceiling;
        self
    }

    pub fn weight_of(&self, who: &Address) -> Option<f64> {
        self.weights.get(who).copied()
    }

    /// What `n` untrusted sources are worth in total.
    pub fn untrusted(&self, n: usize) -> f64 {
        if n == 0 {
            return 0.0;
        }
        let n = n as f64;
        self.untrusted_ceiling * n / (n + self.saturation)
    }
}

/// What a search cost, in statements examined.
///
/// Exposed because the alternative way to check that ranking has not become quadratic is to
/// time it, and a timing assertion is flaky enough that it gets deleted the first time CI is
/// busy. Work is countable, so it is counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchCost {
    /// Objects that matched at least one query term.
    pub candidates: usize,
    /// Statements read while ranking them.
    pub examined: usize,
    /// Results dropped because the reader asked for fewer than were found.
    pub truncated: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ranked {
    pub target: Cid,
    pub score: f64,
    /// Sources the reader trusts that said something positive.
    pub trusted_support: usize,
    /// Sources the reader trusts that disputed it.
    pub trusted_disputes: usize,
    /// Sources the reader has no opinion about.
    pub untrusted_sources: usize,
}

pub struct Ranker {
    pub trust: Trust,
}

impl Ranker {
    pub fn new(trust: Trust) -> Self {
        Ranker { trust }
    }

    /// Rank everything in the catalogue matching `query`, best first.
    pub fn search(&self, cat: &Catalogue, query: &[String]) -> Vec<Ranked> {
        self.search_counted(cat, query).0
    }

    /// Rank the best `k`, and say how many were dropped.
    ///
    /// A query on a common term matches a large fraction of the catalogue, and ranking that
    /// many results is linear in the catalogue however good the index is. Li, Loo, Hellerstein,
    /// Kaashoek, Karger and Morris (IPTPS 2003) established that a decentralised index becomes
    /// feasible only by giving up either ranking quality or decentralisation; **this is the
    /// first trade, taken deliberately.** The truncation is reported rather than silent, so a
    /// reader is never told "these are the results" when it means "these are some of them".
    pub fn search_top(
        &self,
        cat: &Catalogue,
        query: &[String],
        k: usize,
    ) -> (Vec<Ranked>, SearchCost) {
        let (mut out, mut cost) = self.search_counted(cat, query);
        if out.len() > k {
            cost.truncated = out.len() - k;
            out.truncate(k);
        }
        (out, cost)
    }

    /// Rank, and report what it cost.
    pub fn search_counted(&self, cat: &Catalogue, query: &[String]) -> (Vec<Ranked>, SearchCost) {
        let q: Vec<String> = query.iter().map(|s| normalise(s)).collect();
        let mut out = Vec::new();
        let mut cost = SearchCost::default();

        for target in cat.candidates(&q) {
            cost.candidates += 1;
            let mut score = 0.0;
            let mut trusted_support = 0;
            let mut trusted_disputes = 0;
            let mut untrusted = 0;

            // The author's own announcement establishes that the object exists and claims
            // terms. It is worth the reader's weight for that author and nothing more.
            for a in cat.announcements_about(&target) {
                cost.examined += 1;
                let hits = a.matches(&q);
                if hits == 0 {
                    continue;
                }
                let relevance = hits as f64 / q.len().max(1) as f64;
                match self.trust.weight_of(&a.author) {
                    Some(w) => {
                        score += w * relevance;
                        trusted_support += 1;
                    }
                    None => untrusted += 1,
                }
            }

            for c in cat.claims_about(&target) {
                cost.examined += 1;
                let sign = match c.verdict {
                    Verdict::Commend => 1.0,
                    Verdict::Corroborate => 0.5,
                    Verdict::Dispute => -2.0,
                };
                match self.trust.weight_of(&c.claimant) {
                    Some(w) => {
                        score += w * sign;
                        if sign < 0.0 {
                            trusted_disputes += 1;
                        } else {
                            trusted_support += 1;
                        }
                    }
                    None => untrusted += 1,
                }
            }

            // Everything the reader has no opinion about, together, is worth at most the
            // ceiling. This is the whole Sybil defence, and it is the same shape as L16.
            score += self.trust.untrusted(untrusted);

            out.push(Ranked {
                target,
                score,
                trusted_support,
                trusted_disputes,
                untrusted_sources: untrusted,
            });
        }

        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                // Ties break on the content address, so ranking is deterministic and does not
                // depend on the order statements happened to arrive in.
                .then_with(|| a.target.cmp(&b.target))
        });
        (out, cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Announcement, Claim};

    fn addr(n: u32) -> Address {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        Address::from_raw(b)
    }

    fn terms(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn announce(c: &mut Catalogue, target: Cid, who: Address, t: &[&str]) {
        announce_as(c, target, who, t, &Trust::new());
    }

    fn announce_as(c: &mut Catalogue, target: Cid, who: Address, t: &[&str], trust: &Trust) {
        c.announce(Announcement::new(target, who, "doc", &terms(t), 0).unwrap(), trust);
    }

    /// A hundred thousand Sybils must not outrank one source the reader chose.
    ///
    /// This is the property the whole layer stands on. Identities are free, so any additive
    /// scheme loses to volume, and a scheme that ignores strangers entirely can never surface
    /// anything new.
    #[test]
    fn a_flood_of_sybils_cannot_outrank_one_trusted_source() {
        let mut cat = Catalogue::new();
        let good = Cid::of(b"the real thing");
        let spam = Cid::of(b"the spam");

        let trusted = addr(1);
        let mut t = Trust::new();
        t.set(trusted, 1.0);
        announce_as(&mut cat, good, trusted, &["mixing"], &t);

        for i in 0..100_000u32 {
            announce_as(&mut cat, spam, addr(1000 + i), &["mixing"], &t);
        }

        let results = Ranker::new(t).search(&cat, &terms(&["mixing"]));

        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].target, good,
            "100k sybils outranked one trusted source: {:.3} vs {:.3}",
            results[0].score, results[1].score
        );
        // Two defences compose. The catalogue refused to hold more than its untrusted bound,
        // and the ranker saturates whatever did get in. Either alone would be enough here;
        // both matter because the bound protects memory and the saturation protects rank.
        assert_eq!(results[1].untrusted_sources, Catalogue::DEFAULT_UNTRUSTED_CAPACITY);
        assert!(results[1].score <= 0.5, "saturation failed: {}", results[1].score);
    }

    /// Untrusted contribution must saturate rather than accumulate.
    #[test]
    fn untrusted_sources_saturate() {
        let t = Trust::new();
        assert_eq!(t.untrusted(0), 0.0);
        let one = t.untrusted(1);
        let many = t.untrusted(1_000_000);
        assert!(many < 2.0 * one, "{many} is more than twice {one}");
        assert!(many <= 0.5, "the ceiling was exceeded: {many}");
    }

    /// Publishing more must not raise a source's own weight.
    #[test]
    fn volume_does_not_buy_rank() {
        let target = Cid::of(b"x");
        let me = addr(1);

        let mut once = Catalogue::new();
        announce(&mut once, target, me, &["thing"]);

        let mut often = Catalogue::new();
        for i in 0..5_000 {
            often.announce(
                Announcement::new(target, me, "doc", &terms(&["thing"]), i).unwrap(),
                &Trust::new(),
            );
        }

        let mut t = Trust::new();
        t.set(me, 1.0);
        let r = Ranker::new(t);
        let a = r.search(&once, &terms(&["thing"]));
        let b = r.search(&often, &terms(&["thing"]));
        assert_eq!(a[0].score, b[0].score, "repetition changed the score");
    }

    /// Two readers must be able to get different orders from identical inputs.
    ///
    /// A single ranking is a single lever. If every reader saw the same order, there would be
    /// exactly one thing to capture, which is the arrangement this layer exists to remove.
    #[test]
    fn two_readers_with_different_weights_see_different_orders() {
        let mut cat = Catalogue::new();
        let a_doc = Cid::of(b"a");
        let b_doc = Cid::of(b"b");
        announce(&mut cat, a_doc, addr(1), &["topic"]);
        announce(&mut cat, b_doc, addr(2), &["topic"]);

        let mut alice = Trust::new();
        alice.set(addr(1), 1.0);
        let mut bob = Trust::new();
        bob.set(addr(2), 1.0);

        let ra = Ranker::new(alice).search(&cat, &terms(&["topic"]));
        let rb = Ranker::new(bob).search(&cat, &terms(&["topic"]));
        assert_eq!(ra[0].target, a_doc);
        assert_eq!(rb[0].target, b_doc);
    }

    /// A trusted disputer must be able to sink something.
    ///
    /// This is the corrective for an author lying about their own terms, and it is why a
    /// reader who trusts nobody sees an unfiltered catalogue.
    #[test]
    fn a_trusted_dispute_sinks_a_lying_announcement() {
        let mut cat = Catalogue::new();
        let honest = Cid::of(b"honest");
        let liar = Cid::of(b"liar");
        announce(&mut cat, honest, addr(1), &["recipes"]);
        announce(&mut cat, liar, addr(2), &["recipes"]);

        let mut t = Trust::new();
        t.set(addr(1), 1.0);
        t.set(addr(2), 1.0);
        // Before the dispute the two are level and the tie breaks on the address.
        let before = Ranker::new(t.clone()).search(&cat, &terms(&["recipes"]));
        assert_eq!(before[0].score, before[1].score);

        let moderator = addr(50);
        t.set(moderator, 1.0);
        cat.claim(
            Claim::new(liar, moderator, Verdict::Dispute, &terms(&["recipes"]), 1).unwrap(),
            &t,
        );
        let after = Ranker::new(t).search(&cat, &terms(&["recipes"]));
        assert_eq!(after[0].target, honest);
        assert_eq!(after[1].target, liar);
        assert_eq!(after[1].trusted_disputes, 1);
    }

    /// A disputer the reader does not trust must not be able to sink anything.
    ///
    /// Otherwise disputing is a censorship primitive available to anyone with an identity, and
    /// identities are free.
    #[test]
    fn an_untrusted_disputer_cannot_censor() {
        let mut cat = Catalogue::new();
        let target = Cid::of(b"target");
        announce(&mut cat, target, addr(1), &["topic"]);

        let mut t = Trust::new();
        t.set(addr(1), 1.0);
        let before = Ranker::new(t.clone()).search(&cat, &terms(&["topic"]))[0].score;

        for i in 0..50_000u32 {
            cat.claim(
                Claim::new(target, addr(9000 + i), Verdict::Dispute, &terms(&["topic"]), 1)
                    .unwrap(),
                &t,
            );
        }
        let after = Ranker::new(t).search(&cat, &terms(&["topic"]))[0].score;
        assert!(
            after >= before,
            "50k untrusted disputes lowered the score from {before:.3} to {after:.3}"
        );
    }

    /// A reader who trusts nobody still finds things, in a stable order.
    #[test]
    fn a_reader_who_trusts_nobody_sees_an_unfiltered_catalogue() {
        let mut cat = Catalogue::new();
        for i in 0..10u32 {
            announce(&mut cat, Cid::of(&[i as u8]), addr(i), &["topic"]);
        }
        let r = Ranker::new(Trust::new());
        let a = r.search(&cat, &terms(&["topic"]));
        let b = r.search(&cat, &terms(&["topic"]));
        assert_eq!(a.len(), 10);
        assert_eq!(a, b, "ranking was not deterministic");
    }

    /// Matching more of the query must rank higher, all else equal.
    #[test]
    fn relevance_counts_matched_terms() {
        let mut cat = Catalogue::new();
        let both = Cid::of(b"both");
        let one = Cid::of(b"one");
        announce(&mut cat, both, addr(1), &["mixing", "anonymity"]);
        announce(&mut cat, one, addr(2), &["mixing"]);

        let mut t = Trust::new();
        t.set(addr(1), 1.0);
        t.set(addr(2), 1.0);
        let r = Ranker::new(t).search(&cat, &terms(&["mixing", "anonymity"]));
        assert_eq!(r[0].target, both);
        assert!(r[0].score > r[1].score);
    }
    /// Trust acquired after the fact must protect what was already heard.
    ///
    /// Admission is decided when a statement arrives. Without a re-evaluation, a reader who
    /// hears about a source and *then* decides to trust it still has that source's statements
    /// in the evictable pool, and a flood of strangers pushes them out. Hearing first and
    /// deciding second is the ordinary order of events, so this is the common case rather than
    /// an edge one.
    #[test]
    fn deciding_to_trust_a_source_protects_what_was_already_heard() {
        let source = addr(1);
        let target = Cid::of(b"heard before trusted");
        let mut cat = Catalogue::new().with_untrusted_capacity(8);

        // Heard while the reader had no opinion.
        announce_as(&mut cat, target, source, &["topic"], &Trust::new());

        // The reader decides.
        let mut t = Trust::new();
        t.set(source, 1.0);
        cat.retrust(&t);

        // Now the flood.
        for i in 0..5_000u32 {
            announce_as(&mut cat, Cid::of(&i.to_le_bytes()), addr(9000 + i), &["topic"], &t);
        }

        let r = Ranker::new(t).search(&cat, &terms(&["topic"]));
        assert_eq!(
            r[0].target, target,
            "the entry was evicted after the reader chose to trust its source"
        );
    }

    /// A rare query must cost what its results cost, not what the catalogue costs.
    ///
    /// This is the regression test for the defect that every other test in this crate missed.
    /// Ranking originally scanned the whole catalogue once per candidate, which is quadratic
    /// for any query whose terms are common: 21.7 seconds for one query over 64,000 objects,
    /// growing 37x per 4x growth in corpus. Twenty-one passing tests did not see it, because
    /// every one of them used a catalogue small enough for quadratic to look instant.
    ///
    /// Reynolds and Vahdat reported sub-kilobyte queries for peer-to-peer keyword search at
    /// 100,000 documents; Li et al. measured the same approach at 530 MB per query over three
    /// billion. **Small-corpus evaluation of a decentralised index is worthless**, so this
    /// asserts on work performed rather than on a clock, which would be flaky and get deleted.
    #[test]
    fn a_rare_query_does_not_pay_for_the_whole_catalogue() {
        let trust = Trust::new();
        let mut small = Catalogue::new().with_untrusted_capacity(1 << 20);
        let mut large = Catalogue::new().with_untrusted_capacity(1 << 20);

        for (cat, n) in [(&mut small, 200u32), (&mut large, 40_000u32)] {
            for i in 0..n {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&i.to_le_bytes());
                cat.announce(
                    Announcement::new(
                        Cid::of(&b),
                        Address::from_raw(b),
                        "doc",
                        &terms(&["common"]),
                        0,
                    )
                    .unwrap(),
                    &trust,
                );
            }
            // One object, and only one, carries the rare term.
            cat.announce(
                Announcement::new(Cid::of(b"needle"), addr(7), "doc", &terms(&["rare"]), 0)
                    .unwrap(),
                &trust,
            );
        }

        let r = Ranker::new(Trust::new());
        let (_, small_cost) = r.search_counted(&small, &terms(&["rare"]));
        let (hits, large_cost) = r.search_counted(&large, &terms(&["rare"]));

        assert_eq!(hits.len(), 1);
        assert_eq!(small_cost.candidates, 1);
        assert_eq!(large_cost.candidates, 1);
        assert_eq!(
            large_cost.examined, small_cost.examined,
            "a 200x larger catalogue changed the cost of a one-result query: {} vs {}",
            large_cost.examined, small_cost.examined
        );
    }

    /// Ranking a common query must be linear in what matched, not quadratic in the catalogue.
    #[test]
    fn a_common_query_costs_what_it_matches_and_no_more() {
        let trust = Trust::new();
        let mut cat = Catalogue::new().with_untrusted_capacity(1 << 20);
        let n = 20_000u32;
        for i in 0..n {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            cat.announce(
                Announcement::new(Cid::of(&b), Address::from_raw(b), "doc", &terms(&["the"]), 0)
                    .unwrap(),
                &trust,
            );
        }
        let (hits, cost) = Ranker::new(Trust::new()).search_counted(&cat, &terms(&["the"]));
        assert_eq!(hits.len(), n as usize);
        assert_eq!(
            cost.examined, n as usize,
            "examined {} statements to rank {} results",
            cost.examined, n
        );
    }

    /// Truncation must be reported, never silent.
    ///
    /// A reader told "these are the results" when it means "these are some of them" cannot
    /// tell a sparse topic from a truncated one, and that difference is exactly what an
    /// adversary suppressing entries wants to be invisible.
    #[test]
    fn asking_for_fewer_results_says_how_many_were_dropped() {
        let trust = Trust::new();
        let mut cat = Catalogue::new().with_untrusted_capacity(1 << 20);
        for i in 0..500u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            cat.announce(
                Announcement::new(Cid::of(&b), Address::from_raw(b), "doc", &terms(&["t"]), 0)
                    .unwrap(),
                &trust,
            );
        }
        let r = Ranker::new(Trust::new());
        let (hits, cost) = r.search_top(&cat, &terms(&["t"]), 10);
        assert_eq!(hits.len(), 10);
        assert_eq!(cost.truncated, 490);

        // Asking for more than exists truncates nothing and says so.
        let (all, cost) = r.search_top(&cat, &terms(&["t"]), 10_000);
        assert_eq!(all.len(), 500);
        assert_eq!(cost.truncated, 0);
    }

    /// Truncation must keep the best, not an arbitrary slice.
    #[test]
    fn truncation_keeps_the_highest_ranked() {
        let mut cat = Catalogue::new();
        let favourite = Cid::of(b"the one i want");
        let chosen = addr(1);
        let mut t = Trust::new();
        t.set(chosen, 1.0);
        announce_as(&mut cat, favourite, chosen, &["t"], &t);
        for i in 0..300u32 {
            announce_as(&mut cat, Cid::of(&i.to_le_bytes()), addr(500 + i), &["t"], &t);
        }
        let (hits, cost) = Ranker::new(t).search_top(&cat, &terms(&["t"]), 3);
        assert_eq!(hits[0].target, favourite);
        assert!(cost.truncated > 0);
    }

}
