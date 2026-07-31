//! A global passive adversary simulator.
//!
//! Issue #6. Until this existed, every anonymity claim in the whitepaper was an
//! intention rather than a result.
//!
//! # What is modelled
//!
//! A stratified mix topology, clients emitting at a constant rate, sender-chosen
//! exponential per-hop delays, and an adversary who observes **every link in the network
//! simultaneously** and sees, for each tick, how many packets crossed each link. That is
//! the global passive adversary: the one Tor explicitly does not defend against.
//!
//! Because all packets are one fixed size and are bitwise unlinkable between hops
//! (see [`crate::packet`]), the adversary gets no content and no length. Timing and
//! volume are all that remain, and this simulator measures exactly how much they leak.
//!
//! # What is not modelled
//!
//! This measures the *design*, not an implementation. It does not model an active
//! adversary, node compromise, long-run intersection attacks across sessions, bandwidth
//! limits, or packet loss. A result here is necessary and nowhere near sufficient.

use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub label: String,
    pub clients: usize,
    /// Mix layers between sender and recipient.
    pub layers: usize,
    /// Mixes per layer.
    pub width: usize,
    pub ticks: u64,
    /// Mean per-hop delay, in ticks. Ignored when `mixing` is false.
    pub mean_delay: f64,
    /// Constant rate emission. When false, a client only transmits when it has something
    /// to say, which is how almost every deployed system behaves.
    pub cover: bool,
    /// Poisson per-hop delay. When false, packets are forwarded immediately, which is
    /// approximately onion routing.
    pub mixing: bool,
    /// Probability that a given client has a real message on a given tick.
    pub real_rate: f64,
    pub seed: u64,
}

impl SimConfig {
    /// The KARST default: constant rate cover and Poisson mixing, both on.
    pub fn karst(seed: u64) -> Self {
        SimConfig {
            label: "KARST (cover + mixing)".into(),
            clients: 200,
            layers: 3,
            width: 4,
            ticks: 1500,
            mean_delay: 8.0,
            cover: true,
            mixing: true,
            // Deliberately low. At a high duty cycle almost every client is transmitting
            // in any given window, so even a bad design looks anonymous. Sparse traffic is
            // the hard case and therefore the honest one to measure.
            real_rate: 0.005,
            seed,
        }
    }

    /// Approximately onion routing: no cover traffic, prompt forwarding.
    pub fn onion_routing(seed: u64) -> Self {
        SimConfig {
            label: "onion routing (no cover, no delay)".into(),
            cover: false,
            mixing: false,
            ..SimConfig::karst(seed)
        }
    }

    /// Delay but no cover: shows that mixing alone is not enough.
    pub fn mixing_only(seed: u64) -> Self {
        SimConfig {
            label: "mixing only (no cover)".into(),
            cover: false,
            mixing: true,
            ..SimConfig::karst(seed)
        }
    }

    /// Cover but no delay: shows that padding alone is not enough.
    pub fn cover_only(seed: u64) -> Self {
        SimConfig {
            label: "cover only (no delay)".into(),
            cover: true,
            mixing: false,
            ..SimConfig::karst(seed)
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimResult {
    pub label: String,
    pub clients: usize,
    pub real_messages: usize,
    pub delivered: usize,
    pub packets_sent: usize,
    /// Coefficient of variation of per-client emission counts. Zero means an observer
    /// learns nothing at all from how much anyone transmitted.
    pub volume_leak: f64,
    /// Mean number of clients the adversary cannot rule out as the sender of a delivered
    /// message. Higher is better; the ceiling is `clients`.
    pub mean_anonymity_set: f64,
    /// Probability the adversary correctly identifies the sender, best case for them.
    pub correlation_accuracy: f64,
    /// What the adversary would achieve by guessing at random.
    pub baseline: f64,
}

impl SimResult {
    /// How many times better than chance the adversary does. 1.0 means the design held.
    pub fn advantage(&self) -> f64 {
        if self.baseline == 0.0 {
            return 0.0;
        }
        self.correlation_accuracy / self.baseline
    }

    pub fn bandwidth_overhead(&self) -> f64 {
        if self.real_messages == 0 {
            return f64::INFINITY;
        }
        self.packets_sent as f64 / self.real_messages as f64
    }
}

struct InFlight {
    origin: usize,
    is_real: bool,
    /// Tick the sender emitted it. Ground truth; the adversary never sees this.
    sent_at: u64,
    hops_left: usize,
}

fn exp_delay(rng: &mut StdRng, mean: f64) -> u64 {
    // Inverse transform. Clamped so a pathological draw cannot stall the simulation.
    let u: f64 = rng.gen_range(1e-9f64..1.0);
    let d = -mean * (1.0 - u).ln();
    d.round().clamp(1.0, mean * 20.0) as u64
}

/// Run the simulation and mount the correlation attack.
pub fn run(cfg: &SimConfig) -> SimResult {
    let mut rng = StdRng::seed_from_u64(cfg.seed);

    // arrivals[tick] = packets arriving at some node on that tick
    let mut arrivals: BTreeMap<u64, Vec<InFlight>> = BTreeMap::new();

    // Ground truth and adversary observations.
    let mut emissions_per_client = vec![0usize; cfg.clients];
    // What the adversary sees entering the network: (tick, count). With cover on, every
    // client contributes on every tick, so the set of possible senders is everyone.
    let mut emitters_at_tick: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut real_messages = 0usize;
    let mut packets_sent = 0usize;
    // (sent_at, origin) for delivered real messages, plus the tick they came out.
    let mut deliveries: Vec<(u64, usize, u64)> = Vec::new();

    for tick in 0..cfg.ticks {
        for c in 0..cfg.clients {
            let has_real = rng.gen_bool(cfg.real_rate);
            if has_real {
                real_messages += 1;
            }
            // Constant rate: emit every tick regardless. Otherwise emit only when there
            // is something to say.
            let emit = cfg.cover || has_real;
            if !emit {
                continue;
            }

            packets_sent += 1;
            emissions_per_client[c] += 1;
            emitters_at_tick.entry(tick).or_default().push(c);

            let delay = if cfg.mixing {
                exp_delay(&mut rng, cfg.mean_delay)
            } else {
                1
            };
            arrivals.entry(tick + delay).or_default().push(InFlight {
                origin: c,
                is_real: has_real,
                sent_at: tick,
                hops_left: cfg.layers,
            });
        }
    }

    // Walk the network forward, hop by hop.
    let mut tick = 0u64;
    let horizon = cfg.ticks + (cfg.mean_delay * 20.0) as u64 * cfg.layers as u64 + 16;
    while tick <= horizon {
        let Some(batch) = arrivals.remove(&tick) else {
            tick += 1;
            continue;
        };
        for mut p in batch {
            p.hops_left -= 1;
            if p.hops_left == 0 {
                if p.is_real {
                    deliveries.push((p.sent_at, p.origin, tick));
                }
                continue;
            }
            let delay = if cfg.mixing {
                exp_delay(&mut rng, cfg.mean_delay)
            } else {
                1
            };
            arrivals.entry(tick + delay).or_default().push(p);
        }
        tick += 1;
    }

    // ---- the attack ----
    //
    // The adversary sees a packet leave the network at tick `out`. It knows the path
    // length and the delay distribution, so it computes the window of ticks during which
    // the sender must have emitted, and takes every client that emitted in that window as
    // a candidate. Its best strategy is then to guess uniformly among candidates.
    //
    // The window must be a tight high quantile of the actual latency distribution, not a
    // loose bound. Total latency is the sum of `layers` exponentials, which is Erlang with
    // shape k and mean k*m, standard deviation sqrt(k)*m, so the window is mean + 4 SD.
    //
    // A loose bound makes the adversary weak enough that every configuration looks safe:
    // 20*mean*layers is a 480 tick window against a 24 tick mean latency. Overstating your
    // own defences is the failure mode this harness exists to prevent.
    let k = cfg.layers as f64;
    let (min_lat, max_lat) = if cfg.mixing {
        let mean = k * cfg.mean_delay;
        let sd = k.sqrt() * cfg.mean_delay;
        (k.floor() as u64, (mean + 4.0 * sd).ceil() as u64)
    } else {
        (k as u64, k as u64)
    };

    let mut set_sizes = Vec::with_capacity(deliveries.len());
    let mut accuracy_sum = 0.0;

    for (_sent_at, _origin, out) in &deliveries {
        let hi = out.saturating_sub(min_lat);
        let lo = out.saturating_sub(max_lat);
        let mut candidates: Vec<usize> = Vec::new();
        for (t, who) in emitters_at_tick.range(lo..=hi) {
            let _ = t;
            candidates.extend_from_slice(who);
        }
        candidates.sort_unstable();
        candidates.dedup();

        let n = candidates.len().max(1);
        set_sizes.push(n as f64);
        // The true sender is always in the window by construction, so the adversary's
        // best-case hit rate is one over the candidate count.
        accuracy_sum += 1.0 / n as f64;
    }

    let delivered = deliveries.len();
    let mean_anonymity_set = if set_sizes.is_empty() {
        0.0
    } else {
        set_sizes.iter().sum::<f64>() / set_sizes.len() as f64
    };
    let correlation_accuracy = if delivered == 0 {
        0.0
    } else {
        accuracy_sum / delivered as f64
    };

    // Volume leakage: coefficient of variation across clients.
    let mean_em =
        emissions_per_client.iter().sum::<usize>() as f64 / cfg.clients.max(1) as f64;
    let var = emissions_per_client
        .iter()
        .map(|e| {
            let d = *e as f64 - mean_em;
            d * d
        })
        .sum::<f64>()
        / cfg.clients.max(1) as f64;
    let volume_leak = if mean_em == 0.0 {
        0.0
    } else {
        var.sqrt() / mean_em
    };

    SimResult {
        label: cfg.label.clone(),
        clients: cfg.clients,
        real_messages,
        delivered,
        packets_sent,
        volume_leak,
        mean_anonymity_set,
        correlation_accuracy,
        baseline: 1.0 / cfg.clients as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_rate_cover_removes_all_volume_information() {
        let r = run(&SimConfig::karst(1));
        assert_eq!(
            r.volume_leak, 0.0,
            "with cover on, every client transmits identically and volume must leak nothing"
        );
    }

    #[test]
    fn without_cover_volume_alone_distinguishes_clients() {
        let r = run(&SimConfig::onion_routing(1));
        assert!(
            r.volume_leak > 0.0,
            "without cover, how much you sent is visible"
        );
    }

    #[test]
    fn karst_config_holds_the_adversary_to_chance() {
        let r = run(&SimConfig::karst(7));
        assert!(r.delivered > 100, "need a meaningful sample");
        assert!(
            r.mean_anonymity_set > (r.clients as f64) * 0.99,
            "anonymity set should be effectively every client, got {}",
            r.mean_anonymity_set
        );
        assert!(
            r.advantage() < 1.05,
            "adversary must do no better than guessing, got {}x",
            r.advantage()
        );
    }

    #[test]
    fn onion_routing_loses_badly_to_this_adversary() {
        let r = run(&SimConfig::onion_routing(7));
        assert!(
            r.advantage() > 5.0,
            "prompt forwarding without cover should be trivially correlated, got {}x",
            r.advantage()
        );
    }

    /// Cover traffic is the load-bearing mechanism, and mixing alone is not enough.
    ///
    /// This is the finding, and it was not the one expected. See
    /// [`poisson_delay_is_not_justified_by_this_harness`] for what it implies.
    #[test]
    fn cover_traffic_is_what_defeats_a_passive_adversary() {
        let mixing_only = run(&SimConfig::mixing_only(7));

        assert!(
            mixing_only.volume_leak > 0.0,
            "without cover, how much you sent is visible"
        );
        assert!(
            mixing_only.advantage() > 2.0,
            "delay alone leaves a real advantage, got {}x",
            mixing_only.advantage()
        );
        assert!(
            mixing_only.mean_anonymity_set < mixing_only.clients as f64 * 0.6,
            "without cover the candidate set is only whoever was actually talking"
        );
    }

    /// **An honest negative result.**
    ///
    /// Against a purely passive adversary, constant rate cover with prompt forwarding
    /// scores identically to constant rate cover with Poisson delay. Uniform cover at
    /// every tick is effectively a synchronous batch mix, and a batch mix is strong
    /// against an observer who only watches.
    ///
    /// So this harness does **not** justify the Poisson delay mechanism. Loopix's case for
    /// it rests on things not modelled here: resistance to active n-1 and flooding attacks,
    /// and not requiring the global clock synchronisation a batch mix needs. Until those
    /// are simulated, the delay layer is taken on the paper's authority rather than on our
    /// own evidence, and the whitepaper says so.
    #[test]
    fn poisson_delay_is_not_justified_by_this_harness() {
        let cover_only = run(&SimConfig::cover_only(7));
        let both = run(&SimConfig::karst(7));

        assert_eq!(cover_only.volume_leak, 0.0);
        assert!(
            (cover_only.advantage() - both.advantage()).abs() < 0.05,
            "cover alone matches cover plus delay here: {}x vs {}x",
            cover_only.advantage(),
            both.advantage()
        );
    }

    #[test]
    fn delay_widens_the_candidate_window_when_cover_is_absent() {
        // With cover on the set is already saturated at every client, so the delay knob
        // has nothing left to buy. Its effect is only measurable without cover.
        let mut low = SimConfig::mixing_only(3);
        low.mean_delay = 1.0;
        let mut high = SimConfig::mixing_only(3);
        high.mean_delay = 16.0;

        let a = run(&low);
        let b = run(&high);
        assert!(
            b.mean_anonymity_set > a.mean_anonymity_set * 1.5,
            "more delay must widen the window: {} then {}",
            a.mean_anonymity_set,
            b.mean_anonymity_set
        );
    }

    #[test]
    fn the_bandwidth_cost_is_real_and_measurable() {
        let r = run(&SimConfig::karst(1));
        // Constant rate cover costs one packet per client per tick regardless of need, so
        // at a 0.5% duty cycle the overhead is roughly 200x. This is not a rounding error
        // and it is charged continuously to everyone, including everyone who did not need
        // it. Any presentation of this design that omits this number is selling something.
        assert!(
            r.bandwidth_overhead() > 100.0,
            "cover traffic is expensive and the number must say so, got {}x",
            r.bandwidth_overhead()
        );
    }

    #[test]
    fn results_are_deterministic_for_a_given_seed() {
        let a = run(&SimConfig::karst(42));
        let b = run(&SimConfig::karst(42));
        assert_eq!(a.delivered, b.delivered);
        assert_eq!(a.correlation_accuracy, b.correlation_accuracy);
    }
}
