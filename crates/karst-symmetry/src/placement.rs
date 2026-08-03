//! Why diversity-aware path selection backfires.
//!
//! The L16 simulation confirms that observation is bought with node count and that no
//! reputation rule touches it. The obvious response is to make path selection *aware* of
//! structure: prefer relays in under-represented networks, jurisdictions, or social
//! neighbourhoods, so an adversary cannot cheaply hold both ends of a path.
//!
//! **That response is known to make things worse.** Wan, Johnson et al. (PoPETs 2019) show
//! guard placement attacks against Counter-RAPTOR, DeNASA and LASTor, the three
//! state-of-the-art location-aware path selection algorithms for Tor, defeating the defences
//! all three were built around. An adversary contributing **0.216% of Tor's bandwidth
//! attains 18.22% guard selection probability, 84 times what vanilla Tor would give it.**
//!
//! The mechanism is simple and it generalises to any selection rule an adversary can read:
//! the rule says which positions are preferred, so the adversary puts its relays exactly
//! there. Preference intended to reward scarcity becomes a map to the most valuable place to
//! stand.
//!
//! This module quantifies the effect for the rule L16 proposes, which is preference for
//! standing-disjoint neighbourhoods. It is a warning, not a feature.

/// A selection rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    /// Every relay equally likely. No structure to exploit because none is read.
    Uniform,
    /// Relays in under-populated neighbourhoods are preferred, weighted by how scarce their
    /// neighbourhood is. This is the shape of Counter-RAPTOR, DeNASA, LASTor, and of L16's
    /// standing-disjoint path rule.
    DiversityAware,
}

#[derive(Clone, Debug)]
pub struct Placement {
    /// Honest relays per neighbourhood.
    pub honest: Vec<usize>,
    /// Adversary relays per neighbourhood, chosen by the adversary after reading the rule.
    pub adversary: Vec<usize>,
    pub rule: Selection,
}

#[derive(Clone, Copy, Debug)]
pub struct PlacementResult {
    /// Adversary relays as a fraction of all relays.
    pub resource_share: f64,
    /// Probability a given hop selects an adversary relay.
    pub selection_probability: f64,
    /// Selection probability divided by resource share. Above 1.0 means the rule is paying
    /// the adversary a premium for showing up.
    pub amplification: f64,
    /// Probability the adversary holds both ends of a three-hop path.
    pub both_endpoints: f64,
}

impl Placement {
    /// Weight of one relay in neighbourhood `i`.
    fn weight(&self, i: usize, total_in_hood: usize, total_relays: usize) -> f64 {
        match self.rule {
            Selection::Uniform => 1.0,
            Selection::DiversityAware => {
                // Scarcer neighbourhood, higher weight. Any monotone decreasing function of
                // local population has this property; the exact shape does not matter.
                if total_in_hood == 0 {
                    0.0
                } else {
                    let _ = i;
                    total_relays as f64 / total_in_hood as f64
                }
            }
        }
    }

    pub fn evaluate(&self) -> PlacementResult {
        let hoods = self.honest.len().max(self.adversary.len());
        let total_relays: usize =
            self.honest.iter().sum::<usize>() + self.adversary.iter().sum::<usize>();
        if total_relays == 0 {
            return PlacementResult {
                resource_share: 0.0,
                selection_probability: 0.0,
                amplification: 0.0,
                both_endpoints: 0.0,
            };
        }

        let mut total_weight = 0.0;
        let mut adv_weight = 0.0;
        for i in 0..hoods {
            let h = self.honest.get(i).copied().unwrap_or(0);
            let a = self.adversary.get(i).copied().unwrap_or(0);
            let pop = h + a;
            if pop == 0 {
                continue;
            }
            let w = self.weight(i, pop, total_relays);
            total_weight += w * pop as f64;
            adv_weight += w * a as f64;
        }

        let adv_relays: usize = self.adversary.iter().sum();
        let resource_share = adv_relays as f64 / total_relays as f64;
        let selection_probability = if total_weight <= 0.0 {
            0.0
        } else {
            adv_weight / total_weight
        };

        PlacementResult {
            resource_share,
            selection_probability,
            amplification: if resource_share <= 0.0 {
                0.0
            } else {
                selection_probability / resource_share
            },
            both_endpoints: selection_probability * selection_probability,
        }
    }
}

/// An adversary with `budget` relays, spread across the scarcest neighbourhoods.
///
/// Reading the rule and placing against it costs nothing beyond the relays themselves.
pub fn place_adversarially(honest: &[usize], budget: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..honest.len()).collect();
    order.sort_by_key(|i| honest[*i]);

    let mut adv = vec![0usize; honest.len()];
    // Concentrate in the emptiest neighbourhoods, where per-relay weight is highest.
    let targets = order.len().clamp(1, 4);
    let per = budget / targets;
    let mut left = budget;
    for &i in order.iter().take(targets) {
        adv[i] = per.min(left);
        left -= adv[i];
    }
    if left > 0 {
        adv[order[0]] += left;
    }
    adv
}

/// A skewed but realistic relay population: a few crowded networks, a long tail of empty
/// ones. This shape is what makes diversity-aware rules attractive and exploitable.
pub fn realistic_population() -> Vec<usize> {
    vec![
        3000, 2200, 1500, 900, 500, 300, 120, 60, 30, 12, 6, 3, 2, 1, 1, 1,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_selection_pays_no_premium() {
        let honest = realistic_population();
        let adv = place_adversarially(&honest, 20);
        let r = Placement {
            honest,
            adversary: adv,
            rule: Selection::Uniform,
        }
        .evaluate();

        assert!(
            (r.amplification - 1.0).abs() < 1e-9,
            "uniform must give exactly resource share, got {:.4}",
            r.amplification
        );
    }

    /// The result that matters. A rule that rewards scarcity tells the adversary exactly
    /// where scarcity is.
    #[test]
    fn diversity_aware_selection_massively_amplifies_a_tiny_adversary() {
        let honest = realistic_population();
        let total: usize = honest.iter().sum();
        let budget = total / 400; // roughly a quarter of one percent
        let adv = place_adversarially(&honest, budget);

        let aware = Placement {
            honest: honest.clone(),
            adversary: adv.clone(),
            rule: Selection::DiversityAware,
        }
        .evaluate();
        let uniform = Placement {
            honest,
            adversary: adv,
            rule: Selection::Uniform,
        }
        .evaluate();

        assert!(
            aware.amplification > 20.0,
            "expected large amplification, got {:.1}x",
            aware.amplification
        );
        assert!(
            aware.selection_probability > uniform.selection_probability * 20.0,
            "aware {:.4} vs uniform {:.4}",
            aware.selection_probability,
            uniform.selection_probability
        );
    }

    /// Endpoint correlation is what actually deanonymises, and it goes as the square, so
    /// amplification hurts twice.
    #[test]
    fn amplification_hits_endpoint_correlation_quadratically() {
        let honest = realistic_population();
        let total: usize = honest.iter().sum();
        let adv = place_adversarially(&honest, total / 400);

        let aware = Placement {
            honest: honest.clone(),
            adversary: adv.clone(),
            rule: Selection::DiversityAware,
        }
        .evaluate();
        let uniform = Placement {
            honest,
            adversary: adv,
            rule: Selection::Uniform,
        }
        .evaluate();

        let ratio = aware.both_endpoints / uniform.both_endpoints.max(1e-12);
        assert!(
            ratio > 400.0,
            "endpoint correlation should worsen by the square, got {ratio:.0}x"
        );
    }

    #[test]
    fn a_crowded_network_gives_the_adversary_nothing_extra() {
        // Placing where everyone already is earns the same as uniform, which is why the
        // attack requires the rule to be readable rather than merely present.
        let honest = realistic_population();
        let mut adv = vec![0usize; honest.len()];
        adv[0] = 20; // the most crowded neighbourhood

        let r = Placement {
            honest,
            adversary: adv,
            rule: Selection::DiversityAware,
        }
        .evaluate();
        assert!(
            r.amplification < 1.0,
            "crowding should be penalised, got {:.3}",
            r.amplification
        );
    }
}
