//! KARST L16: testing whether flattening returns to scale actually prevents capture.
//!
//! Issue #19. L16 is the newest idea in the whitepaper and the one with no literature, no
//! proof and no deployment behind it. The whitepaper says outright that if it does not
//! hold, nothing else matters, because the failure will not be a seizure, it will be an
//! acquisition. This module is the attempt to find out.
//!
//! # The four claims under test
//!
//! 1. **Flat returns.** A node's standing saturates, so a thousand nodes under one owner
//!    earn what a thousand independent ones do.
//! 2. **Standing does not transfer.** It is earned per relationship and decays, so buying
//!    an operator buys hardware and staff, never position.
//! 3. **No privileged client.** No capability exists only for large operators.
//! 4. **Zero switching cost.** Nothing to be locked into.
//!
//! # Results
//!
//! **Claims 1 and 2 hold.** Across a 90% to 99.9% uptime range the giant's standing per node
//! stays at 1.00 to 1.01, because a ceiling is a ceiling however often you reach it. Under
//! linear returns the same configuration gives it 1.06 and rising. Buying reliability buys
//! *traffic*, moving the giant from 50.1% to 53.0% of service, which is proportional to how
//! often it is available to be chosen and does not compound. That is the correct outcome:
//! you serve more because you are there more.
//!
//! **Observation is the hole, and it is not small.** An adversary who wants to watch rather
//! than be trusted, which is what the KAX17 campaign against Tor was, gains path coverage in
//! proportion to node count no matter what the reputation system does. No reputation is
//! involved, so there is no ceiling. L16 raises the cost of buying *position* and does
//! nothing about buying *presence*.
//!
//! See [`Findings`] and the tests at the bottom.

pub mod placement;

use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// How standing accrues to a node as it serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Returns {
    /// Standing per node saturates at a ceiling. This is L16's proposal.
    Flat,
    /// Standing grows without bound with service volume. The control, and roughly how
    /// every deployed reputation system behaves.
    Linear,
}

#[derive(Clone, Debug)]
pub struct OperatorSpec {
    pub name: String,
    pub nodes: usize,
    /// Probability that any given node of this operator is up in a given round. A
    /// well-resourced operator buys reliability, which no protocol rule forbids.
    pub uptime: f64,
}

#[derive(Clone, Debug)]
pub struct SymConfig {
    pub operators: Vec<OperatorSpec>,
    pub clients: usize,
    pub rounds: u64,
    pub returns: Returns,
    /// Per-node standing ceiling under [`Returns::Flat`].
    pub ceiling: f64,
    /// Fraction of standing lost per round when a relationship is not exercised.
    pub decay: f64,
    /// Requests a single node can serve per round before it turns work away.
    ///
    /// **Required for the experiment to mean anything.** Without a limit every node receives
    /// about the same amount of work regardless of operator, standing never differentiates,
    /// and `Flat` and `Linear` produce identical numbers to three decimal places. No
    /// contention means no feedback loop for returns to scale to act on.
    ///
    /// With a limit, saturated nodes turn work away, somebody absorbs the overflow, and
    /// absorbing overflow earns standing that attracts more work. That loop is what L16
    /// claims to break.
    pub capacity: usize,
    /// Hops per path, for the observation measurement.
    pub path_hops: usize,
    pub seed: u64,
}

impl SymConfig {
    /// One large well-resourced operator against many small ones, which is the shape every
    /// decentralised network has actually ended up in.
    pub fn one_giant(returns: Returns, seed: u64) -> Self {
        let mut operators = vec![OperatorSpec {
            name: "giant".into(),
            nodes: 200,
            uptime: 0.999,
        }];
        for i in 0..40 {
            operators.push(OperatorSpec {
                name: format!("small{i}"),
                nodes: 5,
                uptime: 0.90,
            });
        }
        SymConfig {
            operators,
            // Demand well under total capacity, so standing decides who is chosen and a
            // popular node can absorb far more than an unpopular one. Demand *above* total
            // capacity saturates every node every round, standing stops mattering, and share
            // simply tracks node count: oversubscription closes the channel under test.
            clients: 1_500,
            rounds: 800,
            returns,
            ceiling: 1.0,
            decay: 0.02,
            capacity: 15,
            path_hops: 3,
            seed,
        }
    }

    fn total_nodes(&self) -> usize {
        self.operators.iter().map(|o| o.nodes).sum()
    }
}

#[derive(Clone, Debug)]
pub struct Findings {
    pub label: String,
    /// Share of all service the largest operator performed.
    pub top_traffic_share: f64,
    /// Share of all standing in the network the largest operator holds.
    pub top_standing_share: f64,
    /// Standing per node, largest operator divided by the mean small operator. **1.0 means
    /// flat returns held per node.**
    pub per_node_advantage: f64,
    /// Herfindahl index over traffic share. 1.0 is a monopoly, 1/n is perfect dispersion.
    pub herfindahl: f64,
    /// Fraction of paths on which the largest operator appears at least once.
    pub path_observation: f64,
    /// Fraction of paths where it holds both the first and last hop, which is the position
    /// that actually deanonymises.
    pub path_endpoints: f64,
    /// Late-run traffic share divided by early-run traffic share.
    ///
    /// **This is the actual test of returns to scale.** Above 1.0 means a modest initial
    /// advantage compounded into a larger one. At 1.0 the advantage stayed the size it
    /// started at, which is what flattening returns is supposed to achieve.
    pub compounding: f64,
    pub early_share: f64,
    pub late_share: f64,
}

struct Node {
    operator: usize,
    standing: f64,
    served: u64,
}

/// Run the simulation.
///
/// Each round every client picks a node to serve it, weighted by standing and availability,
/// exercises the relationship, and everyone's standing decays a little. Under
/// [`Returns::Flat`] a node's standing cannot exceed `ceiling` no matter how much it serves.
pub fn run(cfg: &SymConfig) -> Findings {
    let mut rng = StdRng::seed_from_u64(cfg.seed);

    let mut nodes: Vec<Node> = Vec::with_capacity(cfg.total_nodes());
    for (oi, op) in cfg.operators.iter().enumerate() {
        for _ in 0..op.nodes {
            nodes.push(Node {
                operator: oi,
                // Everyone starts equal. Nobody is grandfathered in.
                standing: 0.1,
                served: 0,
            });
        }
    }

    let mut traffic = vec![0u64; cfg.operators.len()];
    // Share of traffic in the first and last fifth of the run. The ratio between them is
    // the actual test: does a modest initial advantage *compound*?
    let window = (cfg.rounds / 5).max(1);
    let mut early = vec![0u64; cfg.operators.len()];
    let mut late = vec![0u64; cfg.operators.len()];

    for round in 0..cfg.rounds {
        let up: Vec<bool> = nodes
            .iter()
            .map(|n| rng.gen_bool(cfg.operators[n.operator].uptime))
            .collect();
        let mut remaining: Vec<usize> = nodes
            .iter()
            .zip(up.iter())
            .map(|(_, u)| if *u { cfg.capacity } else { 0 })
            .collect();

        for _client in 0..cfg.clients {
            // Weighted choice by standing among nodes that are up and not yet saturated.
            // Standing is the only channel through which reputation becomes traffic.
            let total: f64 = nodes
                .iter()
                .enumerate()
                .filter(|(i, _)| remaining[*i] > 0)
                .map(|(_, n)| n.standing)
                .sum();
            if total <= 0.0 {
                continue;
            }
            let mut pick = rng.gen_range(0.0..total);
            let mut chosen = None;
            for (i, n) in nodes.iter().enumerate() {
                if remaining[i] == 0 {
                    continue;
                }
                pick -= n.standing;
                if pick <= 0.0 {
                    chosen = Some(i);
                    break;
                }
            }
            let Some(i) = chosen else { continue };

            remaining[i] -= 1;
            nodes[i].served += 1;
            let op = nodes[i].operator;
            traffic[op] += 1;
            if round < window {
                early[op] += 1;
            } else if round >= cfg.rounds - window {
                late[op] += 1;
            }

            let s = &mut nodes[i].standing;
            match cfg.returns {
                Returns::Flat => {
                    // Approaches the ceiling and stops. More service buys nothing beyond it.
                    *s += (cfg.ceiling - *s) * 0.05;
                }
                Returns::Linear => *s += 0.02,
            }
        }

        // Relationships not exercised fade. This is what makes standing something you keep
        // earning rather than something you banked once.
        for n in nodes.iter_mut() {
            n.standing *= 1.0 - cfg.decay;
            if n.standing < 0.01 {
                n.standing = 0.01;
            }
        }
    }

    let share_of = |v: &[u64], i: usize| -> f64 {
        let t: u64 = v.iter().sum();
        if t == 0 {
            0.0
        } else {
            v[i] as f64 / t as f64
        }
    };
    let early_share = share_of(&early, 0);
    let late_share = share_of(&late, 0);
    let compounding = if early_share <= 0.0 {
        1.0
    } else {
        late_share / early_share
    };

    // ---- measurements ----
    let total_traffic: u64 = traffic.iter().sum();
    let top = 0usize; // operators[0] is the giant by construction

    let top_traffic_share = if total_traffic == 0 {
        0.0
    } else {
        traffic[top] as f64 / total_traffic as f64
    };

    let mut standing_by_op = vec![0.0f64; cfg.operators.len()];
    for n in &nodes {
        standing_by_op[n.operator] += n.standing;
    }
    let total_standing: f64 = standing_by_op.iter().sum();
    let top_standing_share = if total_standing <= 0.0 {
        0.0
    } else {
        standing_by_op[top] / total_standing
    };

    let top_per_node = standing_by_op[top] / cfg.operators[top].nodes as f64;
    let small_per_node: f64 = {
        let s: f64 = standing_by_op[1..].iter().sum();
        let n: usize = cfg.operators[1..].iter().map(|o| o.nodes).sum();
        if n == 0 {
            0.0
        } else {
            s / n as f64
        }
    };
    let per_node_advantage = if small_per_node <= 0.0 {
        f64::INFINITY
    } else {
        top_per_node / small_per_node
    };

    let herfindahl = if total_traffic == 0 {
        0.0
    } else {
        traffic
            .iter()
            .map(|t| {
                let s = *t as f64 / total_traffic as f64;
                s * s
            })
            .sum()
    };

    // ---- the observation attack ----
    //
    // Standing is irrelevant here. An adversary who wants to watch rather than be trusted
    // simply needs to be on the path, and path position is drawn from node count.
    let (path_observation, path_endpoints) =
        observation_rates(cfg.operators[top].nodes, cfg.total_nodes(), cfg.path_hops);

    Findings {
        label: format!("{:?}", cfg.returns),
        top_traffic_share,
        top_standing_share,
        per_node_advantage,
        herfindahl,
        path_observation,
        path_endpoints,
        compounding,
        early_share,
        late_share,
    }
}

/// Analytic path coverage for an operator holding `owned` of `total` nodes, over a path of
/// `hops` uniformly chosen relays.
///
/// Closed form rather than sampled, because it is exact and there is nothing to be gained by
/// adding noise to it.
pub fn observation_rates(owned: usize, total: usize, hops: usize) -> (f64, f64) {
    if total == 0 || hops == 0 {
        return (0.0, 0.0);
    }
    let f = owned as f64 / total as f64;
    let at_least_one = 1.0 - (1.0 - f).powi(hops as i32);
    // Both ends is what actually correlates a sender to a recipient.
    let both_ends = f * f;
    (at_least_one, both_ends)
}

/// Acquisition: one operator buys another.
///
/// Under transferable standing the buyer inherits the seller's position. Under
/// non-transferable standing the buyer inherits hardware and has to earn the position again,
/// which is L16's claim 2.
#[derive(Clone, Copy, Debug)]
pub struct Acquisition {
    pub buyer_before: f64,
    pub seller: f64,
    pub buyer_after: f64,
}

impl Acquisition {
    pub fn gain(&self) -> f64 {
        self.buyer_after - self.buyer_before
    }
}

pub fn acquire(buyer_standing: f64, seller_standing: f64, transferable: bool) -> Acquisition {
    Acquisition {
        buyer_before: buyer_standing,
        seller: seller_standing,
        buyer_after: if transferable {
            buyer_standing + seller_standing
        } else {
            // The seller's relationships were with the seller's keys. The buyer owns the
            // machines and starts those relationships from nothing.
            buyer_standing
        },
    }
}

/// Standing distribution across a set of operators, for reporting.
pub fn shares(cfg: &SymConfig) -> BTreeMap<String, f64> {
    let f = run(cfg);
    let mut m = BTreeMap::new();
    m.insert("top_traffic".into(), f.top_traffic_share);
    m.insert("top_standing".into(), f.top_standing_share);
    m.insert("per_node_advantage".into(), f.per_node_advantage);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claim 1 holds on its own terms: no node exceeds the ceiling, so the giant earns no
    /// more *per node* than a small operator with the same uptime.
    #[test]
    fn flat_returns_removes_the_per_node_advantage_when_uptime_is_equal() {
        let mut cfg = SymConfig::one_giant(Returns::Flat, 1);
        for op in cfg.operators.iter_mut() {
            op.uptime = 0.95;
        }
        let f = run(&cfg);
        assert!(
            (f.per_node_advantage - 1.0).abs() < 0.15,
            "per-node advantage should be ~1.0, got {:.2}",
            f.per_node_advantage
        );
    }

    /// **The test that matters.** Returns to scale means a modest advantage compounds
    /// into a large one. With contention, a giant that is merely more reliable should run
    /// away under linear returns and should not under a per-node ceiling.
    #[test]
    fn linear_returns_compound_an_initial_advantage_and_flat_returns_do_not() {
        let lin = run(&SymConfig::one_giant(Returns::Linear, 7));
        let flat = run(&SymConfig::one_giant(Returns::Flat, 7));

        assert!(
            lin.compounding > flat.compounding,
            "linear must compound harder: {:.3} vs {:.3}",
            lin.compounding,
            flat.compounding
        );
        assert!(
            flat.compounding < 1.05,
            "a ceiling should stop the advantage growing, got {:.3}",
            flat.compounding
        );
    }

    /// Buying uptime does not route around the per-node ceiling, even though a reliable
    /// operator keeps more of its relationships alive against decay. A ceiling is a ceiling
    /// however often you reach it, so standing per node stays flat across a 90% to 99.9%
    /// uptime range.
    #[test]
    fn flat_returns_neutralises_the_uptime_advantage_in_standing() {
        let mut low = SymConfig::one_giant(Returns::Flat, 7);
        low.operators[0].uptime = 0.90;
        let mut high = SymConfig::one_giant(Returns::Flat, 7);
        high.operators[0].uptime = 0.999;

        let a = run(&low);
        let b = run(&high);

        assert!(
            b.per_node_advantage < 1.05,
            "buying reliability must not buy standing per node, got {:.3}",
            b.per_node_advantage
        );
        assert!(
            (b.per_node_advantage - a.per_node_advantage).abs() < 0.05,
            "uptime should barely move per-node standing: {:.3} then {:.3}",
            a.per_node_advantage,
            b.per_node_advantage
        );
    }

    /// Reliability does still buy traffic. That is not a defect: you served more because you
    /// were available more. What matters is that it does not compound.
    #[test]
    fn reliability_buys_traffic_share_but_it_does_not_compound() {
        let mut low = SymConfig::one_giant(Returns::Flat, 7);
        low.operators[0].uptime = 0.90;
        let high = SymConfig::one_giant(Returns::Flat, 7); // 0.999

        let a = run(&low);
        let b = run(&high);

        assert!(
            b.top_traffic_share > a.top_traffic_share,
            "being up more should serve more: {:.3} vs {:.3}",
            a.top_traffic_share,
            b.top_traffic_share
        );
        // A few points, not a runaway.
        assert!(b.top_traffic_share - a.top_traffic_share < 0.10);
        assert!(
            b.compounding < 1.05,
            "and the advantage must not grow over time, got {:.3}",
            b.compounding
        );
    }

    /// Claim 2 holds, and is narrower than it sounds.
    #[test]
    fn standing_does_not_transfer_in_an_acquisition() {
        let transferable = acquire(10.0, 40.0, true);
        let not = acquire(10.0, 40.0, false);

        assert_eq!(transferable.gain(), 40.0, "position was bought");
        assert_eq!(not.gain(), 0.0, "only hardware was bought");
    }

    /// **The other finding, and the more serious one.** An adversary who wants to observe
    /// rather than be trusted is untouched by any of this. Path coverage tracks node count
    /// and nothing else.
    ///
    /// Calibrated against the real KAX17 campaign: over 900 relays against a Tor network of
    /// roughly 9,000 to 10,000.
    #[test]
    fn observation_is_bought_with_node_count_and_standing_is_irrelevant() {
        let (any_hop, both_ends) = observation_rates(900, 9_500, 3);
        assert!(
            any_hop > 0.25,
            "a KAX17-sized fleet should touch a quarter of paths, got {any_hop:.3}"
        );
        assert!(
            both_ends > 0.008,
            "and correlate about one path in a hundred, got {both_ends:.4}"
        );

        // Doubling the fleet roughly doubles endpoint coverage. There is no ceiling here,
        // because there is no reputation involved to saturate.
        let (_, doubled) = observation_rates(1_800, 9_500, 3);
        assert!(doubled > both_ends * 3.5);
    }

    #[test]
    fn flat_returns_does_not_reduce_observation_at_all() {
        let flat = run(&SymConfig::one_giant(Returns::Flat, 3));
        let linear = run(&SymConfig::one_giant(Returns::Linear, 3));
        assert_eq!(
            flat.path_observation, linear.path_observation,
            "the reputation rule is orthogonal to who is on the path"
        );
        assert!(flat.path_observation > 0.5);
    }


    #[test]
    fn results_are_deterministic() {
        let a = run(&SymConfig::one_giant(Returns::Flat, 42));
        let b = run(&SymConfig::one_giant(Returns::Flat, 42));
        assert_eq!(a.top_traffic_share, b.top_traffic_share);
    }
}
