//! Comparing what several providers show you.
//!
//! Replication buys availability. It also buys something less obvious and more valuable: a
//! reader who collects the same feed from several providers has **several views to compare**,
//! and a provider that is quietly not showing them everything stops being invisible.
//!
//! # What replication cannot make worse
//!
//! Every object is verified against the publisher's key wherever it came from, so a hostile
//! replica cannot inject, alter, or attribute. It can only **omit**. Adding replicas therefore
//! adds parties who can fail to serve and no parties who can lie, which is why the number of
//! replicas is a storage and privacy decision rather than a trust one.
//!
//! # Divergence is not proof
//!
//! A provider that lacks an object the others have is either withholding it or has not
//! received it yet. Nothing here distinguishes those from a single observation, and claiming
//! otherwise would turn ordinary propagation delay into an accusation. What distinguishes them
//! is **persistence**: a replica that never catches up across many rounds is not lagging.
//!
//! # The limit this cannot cross
//!
//! One reader comparing `k` providers detects disagreement **among those `k`**. If all of them
//! show that reader the same incomplete view, the reader sees perfect agreement and learns
//! nothing. Catching that requires comparing against what *other readers* were shown, which
//! means a channel between readers.
//!
//! This is the same wall Certificate Transparency hit: a log can show different clients
//! different trees, and the answer is gossip between clients rather than anything a lone client
//! can do. Stating it plainly matters because the mechanism here looks like it detects
//! withholding and only detects *disagreement about* withholding.

use std::collections::{BTreeMap, BTreeSet};

use karst_object::Cid;

/// What one reader has been shown, by whom.
#[derive(Debug, Default)]
pub struct FeedWatch {
    by_provider: BTreeMap<u16, BTreeSet<Cid>>,
    everything: BTreeSet<Cid>,
    /// Rounds in which a provider was asked and lacked something already seen elsewhere.
    behind: BTreeMap<u16, u32>,
    rounds: u32,
}

/// A provider that has fallen behind, and by how much.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lagging {
    pub provider: u16,
    pub missing: Vec<Cid>,
    /// Rounds this provider has been missing something others had.
    pub rounds_behind: u32,
}

impl FeedWatch {
    pub fn new() -> Self {
        FeedWatch::default()
    }

    /// Note that `provider` served `cid`.
    pub fn record(&mut self, provider: u16, cid: Cid) {
        self.by_provider.entry(provider).or_default().insert(cid);
        self.everything.insert(cid);
    }

    /// Note that a round of collection finished, so lag can be counted in rounds rather than
    /// in observations. A provider asked twice in one round is not twice as suspect.
    ///
    /// **A round only means anything if every provider in `asked` was given a fair chance to
    /// serve everything it had.** A caller that stops polling as soon as it has what it wants
    /// leaves the replicas it did not finish reading looking exactly like replicas that are
    /// withholding, because from this structure's point of view they are missing content
    /// others served. That is not a defect in the counting; it is a requirement on the caller,
    /// and it is easy to get wrong: the first version of the demo did exactly this and
    /// reported two honest providers as behind alongside the one that was actually down.
    pub fn end_round(&mut self, asked: &[u16]) {
        self.rounds += 1;
        for &p in asked {
            let held = self.by_provider.entry(p).or_default();
            let missing = self.everything.difference(held).count();
            if missing > 0 {
                *self.behind.entry(p).or_insert(0) += 1;
            }
        }
    }

    pub fn rounds(&self) -> u32 {
        self.rounds
    }

    /// Everything any provider has shown this reader.
    pub fn known(&self) -> &BTreeSet<Cid> {
        &self.everything
    }

    /// Providers missing something another provider served.
    pub fn lagging(&self) -> Vec<Lagging> {
        let mut out: Vec<Lagging> = self
            .by_provider
            .iter()
            .filter_map(|(p, held)| {
                let missing: Vec<Cid> = self.everything.difference(held).copied().collect();
                if missing.is_empty() {
                    None
                } else {
                    Some(Lagging {
                        provider: *p,
                        missing,
                        rounds_behind: self.behind.get(p).copied().unwrap_or(0),
                    })
                }
            })
            .collect();
        out.sort_by_key(|l| std::cmp::Reverse(l.rounds_behind));
        out
    }

    /// Providers behind for at least `rounds` consecutive opportunities to catch up.
    ///
    /// The threshold is the caller's, because what counts as too long depends on how often
    /// they collect and how fast the publisher writes. There is no safe default and offering
    /// one would invite treating propagation delay as misconduct.
    pub fn persistently_behind(&self, rounds: u32) -> Vec<Lagging> {
        self.lagging()
            .into_iter()
            .filter(|l| l.rounds_behind >= rounds)
            .collect()
    }

    /// Whether every provider asked has shown the same set.
    ///
    /// Agreement is not evidence of completeness. It is evidence that whoever is withholding
    /// is withholding consistently, which a colluding replica set does by definition.
    pub fn agreed(&self) -> bool {
        self.lagging().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(n: u8) -> Cid {
        Cid::of(&[n])
    }

    #[test]
    fn providers_that_agree_are_reported_as_agreeing() {
        let mut w = FeedWatch::new();
        for p in [1u16, 2, 3] {
            for c in 0..5u8 {
                w.record(p, cid(c));
            }
        }
        w.end_round(&[1, 2, 3]);
        assert!(w.agreed());
        assert!(w.lagging().is_empty());
    }

    /// A provider missing what the others served must be named.
    #[test]
    fn a_provider_missing_content_is_named() {
        let mut w = FeedWatch::new();
        for c in 0..5u8 {
            w.record(1, cid(c));
            w.record(2, cid(c));
            if c < 3 {
                w.record(3, cid(c));
            }
        }
        w.end_round(&[1, 2, 3]);

        let lag = w.lagging();
        assert_eq!(lag.len(), 1);
        assert_eq!(lag[0].provider, 3);
        assert_eq!(lag[0].missing.len(), 2);
        assert!(!w.agreed());
    }

    /// A replica that catches up must stop being reported.
    ///
    /// Otherwise ordinary propagation delay accumulates into a permanent accusation, and the
    /// signal becomes useless within an hour of the network being busy.
    #[test]
    fn catching_up_clears_the_report() {
        let mut w = FeedWatch::new();
        w.record(1, cid(0));
        w.record(1, cid(1));
        w.record(2, cid(0));
        w.end_round(&[1, 2]);
        assert_eq!(w.lagging().len(), 1);

        w.record(2, cid(1));
        w.end_round(&[1, 2]);
        assert!(w.lagging().is_empty(), "a caught-up replica is still accused");
    }

    /// Persistence is what separates withholding from lag.
    #[test]
    fn only_persistent_absence_counts_as_withholding() {
        let mut w = FeedWatch::new();
        w.record(1, cid(0));
        w.record(2, cid(0));

        // Provider 1 serves something new every round; provider 2 never catches up.
        for c in 1..10u8 {
            w.record(1, cid(c));
            w.end_round(&[1, 2]);
        }
        assert!(w.persistently_behind(20).is_empty());
        let stubborn = w.persistently_behind(5);
        assert_eq!(stubborn.len(), 1);
        assert_eq!(stubborn[0].provider, 2);
        assert!(stubborn[0].rounds_behind >= 9);
    }

    /// A provider nobody asked must not be reported as behind.
    #[test]
    fn a_provider_not_asked_is_not_accused() {
        let mut w = FeedWatch::new();
        w.record(1, cid(0));
        w.record(1, cid(1));
        for _ in 0..10 {
            w.end_round(&[1]);
        }
        assert!(w.lagging().is_empty());
        assert!(w.persistently_behind(1).is_empty());
    }

    /// Agreement across every replica must not be mistaken for completeness.
    ///
    /// A colluding replica set shows one reader a consistent, incomplete view, and this
    /// mechanism reports perfect agreement. Catching that needs comparison against what other
    /// readers were shown, which needs a channel between readers, which is not built. The test
    /// exists so the limit is written down where the mechanism is, rather than only in prose.
    #[test]
    fn a_colluding_replica_set_looks_exactly_like_a_healthy_one() {
        let mut honest = FeedWatch::new();
        let mut deceived = FeedWatch::new();
        for p in [1u16, 2, 3] {
            for c in 0..6u8 {
                honest.record(p, cid(c));
            }
            // Every replica hides the same two objects from this reader.
            for c in 0..4u8 {
                deceived.record(p, cid(c));
            }
        }
        honest.end_round(&[1, 2, 3]);
        deceived.end_round(&[1, 2, 3]);

        assert!(honest.agreed());
        assert!(
            deceived.agreed(),
            "if this ever fails, the mechanism became stronger than its own documentation"
        );
        assert_ne!(honest.known().len(), deceived.known().len());
    }

    /// A hostile replica can omit and cannot lie, which is why replicas are cheap to add.
    ///
    /// Every object is verified against the publisher's key wherever it came from, so this
    /// structure only ever records content that already passed that check.
    #[test]
    fn replication_adds_parties_who_can_omit_and_none_who_can_lie() {
        let mut w = FeedWatch::new();
        // Whatever a hostile replica serves, it is recorded under a content address, so two
        // replicas serving different bytes for one address is not representable here.
        w.record(1, cid(0));
        w.record(2, cid(0));
        assert_eq!(w.known().len(), 1);
        w.end_round(&[1, 2]);
        assert!(w.agreed());
    }
}
