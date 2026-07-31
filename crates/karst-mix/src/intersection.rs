//! Statistical disclosure: what a patient adversary learns from repeated use.
//!
//! The passive and active harnesses both measure **one message**. They report that a
//! whole-network observer is held to chance, and that claim is true for a single message and
//! says nothing about a thousand.
//!
//! The long-run attack is the statistical disclosure attack (Danezis, 2003), extending
//! Kesdogan's disclosure attack. It works by differencing: observe the recipient population
//! in rounds where Alice is sending against rounds where she is not, and the excess is
//! Alice's contribution. Repeat until the estimate separates her recipients from background.
//! Against a steady-state mix network the attack is **slowed but still succeeds**.
//!
//! The literature names three conditions that make it impractical: highly variable delivery
//! times, an adversary who observes very little, and users who pad consistently while the
//! adversary cannot learn how the network behaves in their absence.
//!
//! KARST's constant-rate emission targets the third directly. **If Alice always emits, there
//! are no rounds in which she is absent, so the difference the attack is built on does not
//! exist.** This module tests whether that reasoning survives contact with a simulation, and
//! measures what it costs when it does not apply.

use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    /// Alice transmits only when she has something to say. Every deployed messenger.
    None,
    /// Alice transmits every round regardless, which is KARST's L4 default.
    ConstantRate,
    /// Alice transmits every round while she is a participant, but her participation has an
    /// observable start. Modelling a user who joins the network partway through.
    ConstantRateAfterJoining { joins_at: u64 },
}

#[derive(Clone, Debug)]
pub struct DisclosureConfig {
    /// Total population an observer sees.
    pub users: usize,
    /// Possible recipients.
    pub recipients: usize,
    /// How many recipients Alice actually communicates with.
    pub alice_contacts: usize,
    /// Probability Alice has real traffic in a round.
    pub alice_rate: f64,
    /// Probability any other user has real traffic in a round.
    pub background_rate: f64,
    /// Messages per round from the rest of the population, delivered into the observed set.
    pub rounds: u64,
    pub padding: Padding,
    pub seed: u64,
}

impl DisclosureConfig {
    pub fn base(padding: Padding, seed: u64) -> Self {
        DisclosureConfig {
            users: 200,
            recipients: 100,
            alice_contacts: 3,
            alice_rate: 0.30,
            background_rate: 0.30,
            rounds: 4_000,
            padding,
            seed,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DisclosureResult {
    pub label: String,
    /// How many of Alice's real contacts appear in the adversary's top-k estimate, where k is
    /// the true number of contacts. 1.0 means fully deanonymised.
    pub recall: f64,
    /// Rounds observed before recall first reaches 1.0. `None` if it never does.
    pub rounds_to_full_recall: Option<u64>,
    /// Separation between the mean score of true contacts and of everyone else, in units of
    /// the background standard deviation.
    ///
    /// On its own this is **not** evidence of deanonymisation. Alice's contacts are elevated
    /// because Alice writes to them, and so is every other user's contact set for the same
    /// reason. A high separation with no attribution means the adversary has found which
    /// recipients are popular, which is not a secret.
    pub separation: f64,
    /// The same recall computed against an uninvolved user's contacts, from the identical
    /// observations.
    pub decoy_recall: f64,
    /// `recall - decoy_recall`. **This is the measure that matters.**
    ///
    /// It asks whether the adversary does better at finding *Alice's* contacts than at
    /// finding a stranger's, given the same data. Near zero means the observations carry
    /// nothing about Alice specifically, however much they carry about recipient popularity.
    pub attribution: f64,
}

/// Run a statistical disclosure attack against one sender.
///
/// The adversary observes, per round, whether Alice transmitted and which recipients received
/// anything. It scores each recipient by how much more often they appear in rounds where
/// Alice transmitted than in rounds where she did not, which is the disclosure attack in its
/// simplest honest form.
pub fn statistical_disclosure(cfg: &DisclosureConfig) -> DisclosureResult {
    let mut rng = StdRng::seed_from_u64(cfg.seed);

    // Alice is user 0, with her own stable contacts like everybody else.
    let contacts = contacts_of(0, cfg.alice_contacts, cfg.recipients);

    // Adversary state: recipient appearance counts, split by whether Alice was observed
    // transmitting.
    let mut with_alice = vec![0u64; cfg.recipients];
    let mut without_alice = vec![0u64; cfg.recipients];
    let mut rounds_with = 0u64;
    let mut rounds_without = 0u64;
    let mut rounds_to_full: Option<u64> = None;

    for round in 0..cfg.rounds {
        // Before joining, Alice is not on the network at all, so she sends nothing real
        // either. Modelling her as sending while unjoined would put her traffic in both the
        // "with" and "without" populations and hide the very boundary under test.
        let joined = match cfg.padding {
            Padding::ConstantRateAfterJoining { joins_at } => round >= joins_at,
            _ => true,
        };
        let alice_has_traffic = joined && rng.gen_bool(cfg.alice_rate);

        // What the adversary sees of Alice on the wire.
        let alice_observed_transmitting = match cfg.padding {
            Padding::None => alice_has_traffic,
            Padding::ConstantRate => true,
            Padding::ConstantRateAfterJoining { joins_at } => round >= joins_at,
        };

        // Recipients that receive something this round.
        let mut receivers = vec![false; cfg.recipients];

        // Background traffic from everyone else.
        //
        // Every other user has their own stable contact set, exactly as Alice does. This
        // matters more than it looks: with uniformly random background, Alice is the only
        // structured sender in the data, so any recipient with an elevated rate is hers by
        // elimination, and *any* structure detector finds her regardless of padding. That
        // measures the model, not the defence.
        //
        // Real populations are all structured. The question is whether Alice's structure is
        // separable from everyone else's, not whether it exists.
        // From index 1: Alice is user 0 and is modelled separately below. Including her here
        // would have her send twice per round, doubling her contacts' traffic relative to
        // everyone else's and making her trivially findable for a reason that has nothing to
        // do with the anonymity system.
        for u in 1..cfg.users {
            if rng.gen_bool(cfg.background_rate) {
                let their_contacts = contacts_of(u, cfg.alice_contacts, cfg.recipients);
                let pick = their_contacts[rng.gen_range(0..their_contacts.len())];
                receivers[pick] = true;
            }
        }

        // Alice's real message, which exists only when she has traffic. Padding changes what
        // the adversary sees of her, not whether she actually says anything.
        if alice_has_traffic {
            let target = contacts[rng.gen_range(0..contacts.len())];
            receivers[target] = true;
        }

        if alice_observed_transmitting {
            rounds_with += 1;
            for (r, got) in receivers.iter().enumerate() {
                if *got {
                    with_alice[r] += 1;
                }
            }
        } else {
            rounds_without += 1;
            for (r, got) in receivers.iter().enumerate() {
                if *got {
                    without_alice[r] += 1;
                }
            }
        }

        // Only meaningful once both populations have samples. With one side empty the score
        // degenerates to a raw rate and the ranking carries no information, so a "full
        // recall" reported there would be coincidence.
        if round % 100 == 99
            && rounds_to_full.is_none()
            && rounds_with > 0
            && rounds_without > 0
        {
            let scores = score(&with_alice, &without_alice, rounds_with, rounds_without);
            if recall_at_k(&scores, &contacts) >= 1.0 {
                rounds_to_full = Some(round + 1);
            }
        }
    }

    let scores = score(&with_alice, &without_alice, rounds_with, rounds_without);
    let recall = recall_at_k(&scores, &contacts);

    // A user the adversary was not attacking, scored from the same observations. If the
    // adversary does no better on Alice than on this stranger, it has learned about traffic
    // rather than about Alice.
    //
    // The decoy must have contacts genuinely disjoint from Alice's. `contacts_of` is periodic
    // in the user index, so a decoy chosen carelessly can share her contact set exactly, and
    // then the comparison is Alice against Alice and always reads zero.
    let decoy = (1..cfg.users)
        .map(|u| contacts_of(u, cfg.alice_contacts, cfg.recipients))
        .find(|c| c.iter().all(|r| !contacts.contains(r)))
        .expect("some user has contacts disjoint from Alice's");
    let decoy_recall = recall_at_k(&scores, &decoy);

    DisclosureResult {
        label: format!("{:?}", cfg.padding),
        recall,
        rounds_to_full_recall: rounds_to_full,
        separation: separation(&scores, &contacts),
        decoy_recall,
        attribution: recall - decoy_recall,
    }
}

/// Each user's stable contact set. Deterministic, and deliberately overlapping, so that no
/// recipient belongs to exactly one sender.
fn contacts_of(user: usize, k: usize, recipients: usize) -> Vec<usize> {
    (0..k)
        .map(|i| (user * 3 + i * 11 + 1) % recipients)
        .collect()
}

/// The differencing step. A recipient's score is the excess rate at which it appears when
/// Alice is transmitting.
///
/// With no rounds in which Alice is absent there is nothing to subtract, and every score is
/// identical. That is not a defect of the attack, it is the attack having no input.
fn score(with: &[u64], without: &[u64], n_with: u64, n_without: u64) -> Vec<f64> {
    let rate = |c: u64, n: u64| if n == 0 { 0.0 } else { c as f64 / n as f64 };
    with.iter()
        .zip(without.iter())
        .map(|(w, o)| rate(*w, n_with) - rate(*o, n_without))
        .collect()
}

/// Fraction of Alice's true contacts that appear in the top-k scores.
fn recall_at_k(scores: &[f64], contacts: &[usize]) -> f64 {
    if contacts.is_empty() {
        return 0.0;
    }
    let mut idx: Vec<usize> = (0..scores.len()).collect();
    idx.sort_by(|a, b| scores[*b].partial_cmp(&scores[*a]).unwrap());
    let top: Vec<usize> = idx.into_iter().take(contacts.len()).collect();
    let hits = contacts.iter().filter(|c| top.contains(c)).count();
    hits as f64 / contacts.len() as f64
}

/// How far the true contacts sit above the background, in background standard deviations.
fn separation(scores: &[f64], contacts: &[usize]) -> f64 {
    let others: Vec<f64> = (0..scores.len())
        .filter(|i| !contacts.contains(i))
        .map(|i| scores[i])
        .collect();
    if others.is_empty() {
        return 0.0;
    }
    let mean_o = others.iter().sum::<f64>() / others.len() as f64;
    let var = others.iter().map(|s| (s - mean_o).powi(2)).sum::<f64>() / others.len() as f64;
    let sd = var.sqrt();

    let mean_c: f64 = contacts.iter().map(|c| scores[*c]).sum::<f64>() / contacts.len() as f64;
    if sd <= 1e-12 {
        // No spread in the background at all, so nothing distinguishes anything.
        return 0.0;
    }
    (mean_c - mean_o) / sd
}

/// How the attack scales with observation length, for reporting.
pub fn recall_over_time(cfg: &DisclosureConfig, checkpoints: &[u64]) -> BTreeMap<u64, f64> {
    checkpoints
        .iter()
        .map(|r| {
            let mut c = cfg.clone();
            c.rounds = *r;
            (*r, statistical_disclosure(&c).recall)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without cover traffic, patience wins. This is the attack working as documented, and it
    /// is what every messenger that transmits only on demand is exposed to.
    #[test]
    fn without_padding_a_patient_adversary_identifies_the_contacts() {
        let r = statistical_disclosure(&DisclosureConfig::base(Padding::None, 1));
        assert_eq!(
            r.recall, 1.0,
            "expected full deanonymisation, got recall {:.2}",
            r.recall
        );
        assert!(
            r.separation > 3.0,
            "contacts should stand well clear of background, got {:.1} sd",
            r.separation
        );
    }

    #[test]
    fn the_attack_gets_better_the_longer_it_runs() {
        let cfg = DisclosureConfig::base(Padding::None, 4);
        let curve = recall_over_time(&cfg, &[100, 500, 4_000]);
        let short = curve[&100];
        let long = curve[&4_000];
        assert!(
            long >= short,
            "more observation must not help less: {short:.2} then {long:.2}"
        );
        assert_eq!(long, 1.0);
    }

    /// **The claim under test.** Constant-rate emission removes the differencing signal
    /// entirely, because there are no rounds in which Alice is observed absent.
    ///
    /// Note what is measured. Alice's contacts remain elevated in the raw counts, because she
    /// writes to them and that traffic exists. So does every other user's contact set. What
    /// the adversary cannot do is say which of the elevated recipients are *hers*, and
    /// `attribution` is the test of that.
    #[test]
    fn constant_rate_emission_leaves_nothing_attributable_to_alice() {
        let r = statistical_disclosure(&DisclosureConfig::base(Padding::ConstantRate, 1));
        assert!(
            r.attribution.abs() < 0.35,
            "adversary must do no better on Alice than on a stranger, got {:.2} \
             (recall {:.2}, decoy {:.2})",
            r.attribution,
            r.recall,
            r.decoy_recall
        );
    }

    /// Without padding the adversary does markedly better on its target than on a stranger,
    /// which is what deanonymisation actually looks like.
    #[test]
    fn without_padding_the_adversary_attributes_contacts_to_alice_specifically() {
        let r = statistical_disclosure(&DisclosureConfig::base(Padding::None, 1));
        assert!(
            r.attribution > 0.5,
            "expected strong attribution, got {:.2} (recall {:.2}, decoy {:.2})",
            r.attribution,
            r.recall,
            r.decoy_recall
        );
    }

    /// **The hole.** A user who joins partway through has an observable before and after, so
    /// the adversary differences across the join instead of across her idle rounds.
    ///
    /// Constant-rate cover protects a participant. It does not protect the act of becoming
    /// one, and every user becomes one exactly once.
    #[test]
    fn joining_the_network_reintroduces_the_differencing_signal() {
        let joined = statistical_disclosure(&DisclosureConfig::base(
            Padding::ConstantRateAfterJoining { joins_at: 500 },
            1,
        ));
        let always = statistical_disclosure(&DisclosureConfig::base(Padding::ConstantRate, 1));

        assert!(
            joined.attribution > always.attribution,
            "a join boundary must leak more than none: {:.2} vs {:.2}",
            joined.attribution,
            always.attribution
        );
    }

    /// The leak scales with how long the adversary watched before Alice arrived. Half an
    /// observation window of pre-join baseline is enough to identify her contacts completely.
    #[test]
    fn the_longer_the_adversary_waits_before_you_join_the_worse_the_join_leaks() {
        let short = statistical_disclosure(&DisclosureConfig::base(
            Padding::ConstantRateAfterJoining { joins_at: 500 },
            1,
        ));
        let long = statistical_disclosure(&DisclosureConfig::base(
            Padding::ConstantRateAfterJoining { joins_at: 2_000 },
            1,
        ));

        assert!(
            long.attribution > short.attribution,
            "more pre-join baseline must leak more: {:.2} then {:.2}",
            short.attribution,
            long.attribution
        );
        assert_eq!(long.attribution, 1.0, "a long baseline fully deanonymises");
        assert!(long.rounds_to_full_recall.is_some());
    }

    #[test]
    fn results_are_deterministic() {
        let a = statistical_disclosure(&DisclosureConfig::base(Padding::None, 9));
        let b = statistical_disclosure(&DisclosureConfig::base(Padding::None, 9));
        assert_eq!(a.recall, b.recall);
        assert_eq!(a.rounds_to_full_recall, b.rounds_to_full_recall);
    }
}

