//! Sending traffic to yourself, to find out whether traffic gets through.
//!
//! A continuous mix has no batch boundary an adversary can force, so n-1 is not exact on
//! demand. It is not eliminated. Kesdogan, Egner and Buschkes note in their own paper that
//! random delay alone does not stop flooding, because an adversary can flood and keep flooding
//! until the real packet emerges. Loopix answers the residue with **detection** rather than
//! structure, following Danezis and Sassaman (*Heartbeat Traffic to Counter (n-1) Attacks*,
//! WPES 2003): send traffic whose disappearance you would notice, and notice.
//!
//! # Loops here are ordinary mail
//!
//! Loopix routes a mix loop back to the mix that sent it, which a strictly layered topology
//! cannot express: there is no path from layer *i* forward to layer *i* again. The client loop
//! needs no such thing. A party addresses a message **to a mailbox it owns**, and collects it
//! like any other. It traverses the same layers, sits in the same kind of box, and is
//! indistinguishable from real mail to every node it passes and to the provider holding it,
//! because it is real mail.
//!
//! Anything that can drop a party's traffic drops its loops at the same rate, which is exactly
//! the quantity being estimated.
//!
//! # What it cannot see
//!
//! An adversary who stays below the baseline is invisible to this, and no amount of sampling
//! changes that. The baseline must therefore be set out of band rather than learned from a
//! channel the adversary sits on, which is why `Baseline::Ratcheted` may fall and never rise.
//!
//! It also measures **the path a loop took**, not the path a message took. Routes are drawn
//! per packet, so a mix dropping selectively shows up in proportion to how often it is drawn,
//! and a mix dropping only non-loop traffic would not show up at all. Distinguishing loop from
//! real is what the sealing prevents: a node cannot tell them apart, so it cannot drop one and
//! not the other.

use karst_mix::loops::{Alarm, Baseline, LoopTracker};
use rand::Rng;

use crate::client::{Client, Dispatch, SendError};
use crate::directory::Directory;

/// Marks a message as a loop, inside the seal where only its sender can read it.
const LOOP_MAGIC: &[u8; 8] = b"KARSTLP1";

pub struct Sentinel {
    tracker: LoopTracker,
    timeout_ms: u64,
}

impl Sentinel {
    /// `baseline_loss` is what normal loss looks like, and must come from somewhere the
    /// adversary does not control. `timeout_ms` must exceed a round trip comfortably, since a
    /// loop counted lost because it was merely slow is a false alarm.
    pub fn new(baseline: Baseline, alpha: f64, timeout_ms: u64) -> Self {
        Sentinel {
            tracker: LoopTracker::with_baseline(baseline, alpha),
            timeout_ms,
        }
    }

    /// Build a loop and record that it is outstanding.
    pub fn dispatch(
        &mut self,
        client: &Client,
        dir: &Directory,
        now_ms: u64,
        rng: &mut impl Rng,
    ) -> Result<Vec<Dispatch>, SendError> {
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce);
        let mut body = Vec::with_capacity(LOOP_MAGIC.len() + 16);
        body.extend_from_slice(LOOP_MAGIC);
        body.extend_from_slice(&nonce);

        // Addressed to the sender's own contact, so it comes back through the ordinary path.
        let out = client.send(dir, &client.contact(), &body, rng)?;
        self.tracker.dispatch(nonce, now_ms, self.timeout_ms);
        Ok(out)
    }

    /// Offer a collected message. Returns true if it was a loop and has been consumed.
    ///
    /// A message that is not a loop is left for the application. A message shaped like a loop
    /// but carrying an unknown nonce is consumed and not counted, because it is either a
    /// replay or an attempt to inflate the return rate, and neither should reach an
    /// application or a statistic.
    pub fn absorb(&mut self, message: &[u8]) -> bool {
        if message.len() != LOOP_MAGIC.len() + 16 || &message[..8] != LOOP_MAGIC {
            return false;
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&message[8..]);
        self.tracker.observe_return(&nonce);
        true
    }

    /// Retire loops that are past their deadline. Returns how many were given up on.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        self.tracker.expire(now_ms)
    }

    pub fn samples(&self) -> usize {
        self.tracker.samples()
    }

    pub fn outstanding(&self) -> usize {
        self.tracker.outstanding()
    }

    pub fn loss_rate(&self) -> f64 {
        self.tracker.loss_rate()
    }

    /// Set when observed loss exceeds the baseline by more than chance explains.
    pub fn alarm(&self) -> Option<Alarm> {
        self.tracker.alarm()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::NodeInfo;
    use crate::provider::Provider;
    use karst_mix::packet::{MixKey, Packet};
    use karst_node::{MixNode, Outbound};

    struct Mesh {
        dir: Directory,
        nodes: Vec<MixNode>,
        provider: Provider,
        provider_id: u16,
        inflight: Vec<(usize, Packet)>,
        now: u64,
        /// Fraction of packets this mesh silently discards, applied at node 0.
        drop_rate: f64,
    }

    impl Mesh {
        fn new(layers: u8, per_layer: usize, drop_rate: f64) -> Mesh {
            let mut dir = Directory::new(15.0);
            let mut nodes = Vec::new();
            let mut id = 0u16;
            for layer in 0..layers {
                let n = if layer == layers - 1 { 1 } else { per_layer };
                for _ in 0..n {
                    let key = MixKey::from_seed([(id as u8).wrapping_add(1); 32]);
                    dir.add(NodeInfo {
                        id,
                        addr: "127.0.0.1:1".parse().unwrap(),
                        mix_public: key.public(),
                        layer,
                    });
                    nodes.push(MixNode::new(key));
                    id += 1;
                }
            }
            Mesh {
                provider_id: id - 1,
                dir,
                nodes,
                provider: Provider::new(),
                inflight: Vec::new(),
                now: 0,
                drop_rate,
            }
        }

        fn inject(&mut self, ds: Vec<Dispatch>) {
            for d in ds {
                self.inflight.push((d.via as usize, d.packet));
            }
        }

        fn run(&mut self, ms: u64, rng: &mut impl Rng) {
            for _ in 0..ms {
                self.now += 1;
                for (idx, p) in std::mem::take(&mut self.inflight) {
                    if rng.gen_bool(self.drop_rate) {
                        continue;
                    }
                    let _ = self.nodes[idx].accept(p, self.now);
                }
                for i in 0..self.nodes.len() {
                    for out in self.nodes[i].due(self.now) {
                        match out {
                            Outbound::Forward { next, packet } => {
                                self.inflight.push((next as usize, packet))
                            }
                            Outbound::Deliver { payload } => {
                                let _ = self.provider.deposit(&payload);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Run `rounds` loops through a mesh with the given drop rate and report the sentinel.
    fn observe(drop_rate: f64, rounds: usize) -> Sentinel {
        let mut mesh = Mesh::new(4, 3, drop_rate);
        let mut alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut s = Sentinel::new(Baseline::Fixed(0.05), 0.001, 1_000);
        let mut rng = rand::thread_rng();

        for _ in 0..rounds {
            let ds = s.dispatch(&alice, &mesh.dir, mesh.now, &mut rng).unwrap();
            mesh.inject(ds);
            mesh.run(1_200, &mut rng);
            for item in mesh.provider.collect(&alice.mailbox()).items {
                if let Some(m) = alice.accept(&item) {
                    s.absorb(&m);
                }
            }
            s.expire(mesh.now);
        }
        s
    }

    /// A healthy network must not raise an alarm.
    ///
    /// A detector that cries wolf is a detector operators turn off, so the false alarm rate
    /// matters as much as the detection rate.
    #[test]
    fn a_healthy_network_stays_quiet() {
        let s = observe(0.0, 120);
        assert_eq!(s.samples(), 120);
        assert_eq!(s.loss_rate(), 0.0);
        assert!(s.alarm().is_none(), "alarm on a network dropping nothing");
    }

    /// A loop must come back, which is what makes its absence meaningful.
    #[test]
    fn loops_return_through_the_ordinary_path() {
        let s = observe(0.0, 30);
        assert_eq!(s.samples(), 30);
        assert_eq!(s.outstanding(), 0);
    }

    /// Heavy dropping must be caught.
    #[test]
    fn a_mix_dropping_heavily_is_caught() {
        let s = observe(0.5, 60);
        let a = s.alarm().expect("50% loss went unnoticed");
        assert!(a.observed_rate > 0.3);
        assert!(a.p_value < 0.001);
    }

    /// Dropping below the baseline is invisible, and saying so is the point.
    ///
    /// No amount of sampling detects an adversary who stays under the noise floor. This is a
    /// property of the mechanism rather than a defect in it, and an operator who does not know
    /// it will believe silence means safety.
    #[test]
    fn dropping_below_the_baseline_is_invisible_by_construction() {
        let s = observe(0.02, 150);
        assert!(
            s.alarm().is_none(),
            "2% loss against a 5% baseline should not be distinguishable"
        );
        assert!(s.loss_rate() < 0.10, "vacuous: loss was {}", s.loss_rate());
    }

    /// A loop that is merely slow must not be counted as lost.
    #[test]
    fn a_slow_loop_is_not_a_lost_one() {
        let mut mesh = Mesh::new(4, 3, 0.0);
        let mut alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut s = Sentinel::new(Baseline::Fixed(0.05), 0.001, 5_000);
        let mut rng = rand::thread_rng();

        let ds = s.dispatch(&alice, &mesh.dir, mesh.now, &mut rng).unwrap();
        mesh.inject(ds);
        // Expire before it could possibly have returned.
        s.expire(mesh.now);
        assert_eq!(s.outstanding(), 1);

        mesh.run(1_500, &mut rng);
        for item in mesh.provider.collect(&alice.mailbox()).items {
            if let Some(m) = alice.accept(&item) {
                s.absorb(&m);
            }
        }
        assert_eq!(s.outstanding(), 0);
        assert_eq!(s.loss_rate(), 0.0);
    }

    /// A replayed loop must not be able to inflate the return rate.
    ///
    /// If it could, an adversary dropping traffic would replay one surviving loop to hide it.
    #[test]
    fn a_replayed_loop_cannot_manufacture_a_healthy_reading() {
        let mut mesh = Mesh::new(4, 3, 0.0);
        let mut alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let mut s = Sentinel::new(Baseline::Fixed(0.05), 0.001, 1_000);
        let mut rng = rand::thread_rng();

        let ds = s.dispatch(&alice, &mesh.dir, mesh.now, &mut rng).unwrap();
        mesh.inject(ds);
        mesh.run(1_200, &mut rng);
        let mut body = None;
        for item in mesh.provider.collect(&alice.mailbox()).items {
            if let Some(m) = alice.accept(&item) {
                body = Some(m.clone());
                s.absorb(&m);
            }
        }
        let body = body.expect("the loop did not return");
        assert_eq!(s.samples(), 1);

        // The same bytes, offered a thousand more times.
        for _ in 0..1_000 {
            assert!(s.absorb(&body), "shaped like a loop, so it is consumed");
        }
        assert_eq!(s.samples(), 1, "replays inflated the sample count");
    }

    /// Application traffic must not be mistaken for a loop.
    #[test]
    fn ordinary_messages_are_not_absorbed() {
        let mut s = Sentinel::new(Baseline::Fixed(0.05), 0.001, 1_000);
        assert!(!s.absorb(b""));
        assert!(!s.absorb(b"hello"));
        assert!(!s.absorb(&vec![0u8; 24]));
        // Right length, wrong magic.
        assert!(!s.absorb(&[b'X'; 24]));
        assert_eq!(s.samples(), 0);
    }

    /// A loop must be indistinguishable from real mail at the provider.
    #[test]
    fn a_loop_looks_like_mail_to_the_provider() {
        let mut mesh = Mesh::new(4, 3, 0.0);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let mut s = Sentinel::new(Baseline::Fixed(0.05), 0.001, 1_000);
        let mut rng = rand::thread_rng();

        let loops = s.dispatch(&alice, &mesh.dir, mesh.now, &mut rng).unwrap();
        mesh.inject(loops);
        mesh.run(1_200, &mut rng);
        let loop_item = mesh.provider.collect(&alice.mailbox()).items.remove(0);

        mesh.inject(alice.send(&mesh.dir, &bob.contact(), b"real", &mut rng).unwrap());
        mesh.run(1_200, &mut rng);
        let mail_item = mesh.provider.collect(&bob.mailbox()).items.remove(0);

        assert_eq!(loop_item.len(), mail_item.len());
    }
}
