//! Who is out there, and how to build a path through them.
//!
//! # Stratified, not free
//!
//! Mixes sit in layers and a route takes one node from each, which is the Loopix topology
//! (Piotrowska, Hayes, Elahi, Meiser, Danezis, USENIX Security 2017). Free selection over a
//! flat set concentrates traffic on whichever nodes advertise the most capacity, and an
//! adversary buying capacity buys path position at a known exchange rate. Layers cap what any
//! one node can be on a path, and they guarantee a fixed number of mixing stages regardless of
//! how selection goes.
//!
//! # Delays
//!
//! Exponential, per hop, chosen by the sender. Danezis (*The Traffic Analysis of
//! Continuous-Time Mixes*, PET 2004) shows by calculus of variations that for a fixed mean
//! latency the exponential maximises entropy, so it is the optimal choice rather than a
//! convenient one.
//!
//! The draw is truncated at what a node will hold, which departs from the analysis. The
//! truncation is far out in the tail and the alternative is a packet a node refuses, which is
//! worse. Katzenpost's deployed directory carries the same parameter.
//!
//! # What is not decided here
//!
//! Guards. Tor uses persistent entry guards because a client drawing a fresh entry every time
//! eventually draws a hostile one, and the guard trades a rising certainty of eventual
//! compromise for a fixed chance of immediate compromise. Whether that trade is right here is
//! open, and it is not merely a parameter: guard placement attacks defeat Counter-RAPTOR,
//! DeNASA and LASTor, with 0.216% of bandwidth reaching 18.22% of guard selections (Hanley,
//! Sun, Wagh, Mittal, PoPETs 2019). Selection is uniform within a layer until that is settled.

use karst_mix::packet::{Hop, MAX_HOPS};
use karst_node::MixNode;
use rand::Rng;
use std::net::SocketAddr;
use x25519_dalek::PublicKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    /// A layer has no nodes, so no path exists.
    EmptyLayer,
    /// More layers than a packet header holds.
    TooManyLayers,
    NoSuchNode,
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub id: u16,
    pub addr: SocketAddr,
    pub mix_public: PublicKey,
    /// Which mixing stage this node serves. Providers sit in the last layer.
    pub layer: u8,
}

#[derive(Debug, Clone, Default)]
pub struct Directory {
    nodes: Vec<NodeInfo>,
    /// Mean per-hop delay.
    mu_ms: f64,
}

impl Directory {
    pub fn new(mu_ms: f64) -> Self {
        Directory {
            nodes: Vec::new(),
            mu_ms,
        }
    }

    pub fn add(&mut self, info: NodeInfo) {
        self.nodes.push(info);
    }

    pub fn get(&self, id: u16) -> Option<&NodeInfo> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    pub fn layers(&self) -> u8 {
        self.nodes.iter().map(|n| n.layer).max().map_or(0, |m| m + 1)
    }

    fn delay(&self, rng: &mut impl Rng) -> u32 {
        let u: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
        let ms = -u.ln() * self.mu_ms;
        (ms.round() as u64).min(MixNode::MAX_DELAY_MS as u64) as u32
    }

    /// A path through every mixing layer, ending at `terminal`.
    ///
    /// The terminal node is named rather than drawn, because it is the recipient's provider and
    /// the sender does not get to choose where someone else's mail is kept.
    pub fn route_to(&self, terminal: u16, rng: &mut impl Rng) -> Result<Vec<Hop>, RouteError> {
        let terminal_node = self.get(terminal).ok_or(RouteError::NoSuchNode)?.clone();
        let mixing_layers = terminal_node.layer;
        if mixing_layers as usize + 1 > MAX_HOPS {
            return Err(RouteError::TooManyLayers);
        }

        let mut hops = Vec::with_capacity(mixing_layers as usize + 1);
        for layer in 0..mixing_layers {
            let candidates: Vec<&NodeInfo> =
                self.nodes.iter().filter(|n| n.layer == layer).collect();
            if candidates.is_empty() {
                return Err(RouteError::EmptyLayer);
            }
            let pick = candidates[rng.gen_range(0..candidates.len())];
            hops.push(Hop {
                id: pick.id,
                public: pick.mix_public,
                delay_ms: self.delay(rng),
            });
        }
        hops.push(Hop {
            id: terminal_node.id,
            public: terminal_node.mix_public,
            delay_ms: self.delay(rng),
        });
        Ok(hops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_mix::packet::MixKey;

    fn dir(per_layer: usize, layers: u8) -> (Directory, Vec<MixKey>) {
        let mut d = Directory::new(50.0);
        let mut keys = Vec::new();
        let mut id = 0u16;
        for layer in 0..layers {
            for _ in 0..per_layer {
                let k = MixKey::from_seed([(id + 1) as u8; 32]);
                d.add(NodeInfo {
                    id,
                    addr: "127.0.0.1:1".parse().unwrap(),
                    mix_public: k.public(),
                    layer,
                });
                keys.push(k);
                id += 1;
            }
        }
        (d, keys)
    }

    #[test]
    fn a_route_takes_one_node_from_every_layer_and_ends_where_asked() {
        let (d, _) = dir(4, 4);
        let mut rng = rand::thread_rng();
        // Node 12 is the first in layer 3.
        for _ in 0..200 {
            let r = d.route_to(12, &mut rng).unwrap();
            assert_eq!(r.len(), 4);
            assert_eq!(r[3].id, 12);
            for (i, h) in r.iter().enumerate().take(3) {
                let n = d.get(h.id).unwrap();
                assert_eq!(n.layer as usize, i, "hop {i} came from the wrong layer");
            }
        }
    }

    /// Selection within a layer must be uniform.
    ///
    /// A skew is a standing advantage for whoever benefits from it, and it would not
    /// necessarily be visible in a working network.
    #[test]
    fn selection_within_a_layer_is_uniform() {
        let (d, _) = dir(8, 3);
        let mut rng = rand::thread_rng();
        let mut counts = [0u32; 8];
        let trials = 40_000;
        for _ in 0..trials {
            let r = d.route_to(16, &mut rng).unwrap();
            counts[r[0].id as usize] += 1;
        }
        let expected = trials as f64 / 8.0;
        for (i, c) in counts.iter().enumerate() {
            let dev = (*c as f64 - expected).abs() / expected;
            assert!(dev < 0.1, "node {i} took {c} of {trials}, {:.1}% off", dev * 100.0);
        }
    }

    /// Delays must be exponential, since that is what the mixing analysis assumes.
    #[test]
    fn delays_are_exponential_with_the_configured_mean() {
        let (d, _) = dir(2, 2);
        let mut rng = rand::thread_rng();
        let mut all = Vec::new();
        for _ in 0..20_000 {
            all.extend(d.route_to(2, &mut rng).unwrap().iter().map(|h| h.delay_ms as f64));
        }
        let mean = all.iter().sum::<f64>() / all.len() as f64;
        let var = all.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / all.len() as f64;
        assert!((mean - 50.0).abs() < 3.0, "mean {mean}");
        assert!((var.sqrt() / mean - 1.0).abs() < 0.1, "sd/mean {}", var.sqrt() / mean);
    }

    /// No hop may exceed what a node will hold, or the packet is refused in flight.
    #[test]
    fn no_hop_asks_for_longer_than_a_node_will_hold() {
        let mut d = Directory::new(1e9);
        let k = MixKey::from_seed([1u8; 32]);
        for layer in 0..2 {
            d.add(NodeInfo {
                id: layer as u16,
                addr: "127.0.0.1:1".parse().unwrap(),
                mix_public: k.public(),
                layer,
            });
        }
        let mut rng = rand::thread_rng();
        for _ in 0..5_000 {
            for h in d.route_to(1, &mut rng).unwrap() {
                assert!(h.delay_ms <= MixNode::MAX_DELAY_MS);
            }
        }
    }

    #[test]
    fn a_missing_layer_is_an_error_rather_than_a_shorter_route() {
        let mut d = Directory::new(10.0);
        let k = MixKey::from_seed([1u8; 32]);
        d.add(NodeInfo { id: 0, addr: "127.0.0.1:1".parse().unwrap(), mix_public: k.public(), layer: 0 });
        d.add(NodeInfo { id: 9, addr: "127.0.0.1:1".parse().unwrap(), mix_public: k.public(), layer: 3 });
        let mut rng = rand::thread_rng();
        assert_eq!(d.route_to(9, &mut rng).unwrap_err(), RouteError::EmptyLayer);
    }

    #[test]
    fn a_route_longer_than_a_header_holds_is_refused() {
        let mut d = Directory::new(10.0);
        let k = MixKey::from_seed([1u8; 32]);
        for layer in 0..=(MAX_HOPS as u8) {
            d.add(NodeInfo { id: layer as u16, addr: "127.0.0.1:1".parse().unwrap(), mix_public: k.public(), layer });
        }
        let mut rng = rand::thread_rng();
        assert_eq!(
            d.route_to(MAX_HOPS as u16, &mut rng).unwrap_err(),
            RouteError::TooManyLayers
        );
    }
}
