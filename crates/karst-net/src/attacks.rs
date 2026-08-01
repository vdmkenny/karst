//! Attacks on the assembled network.
//!
//! Each component has its own adversarial tests. A network is not its components: it has
//! composition, timing, and parties who can collude, and none of those exist at the level
//! where a packet or a queue is tested.

#![cfg(test)]

use std::time::Instant;

use karst_mix::packet::{MixKey, Packet};
use karst_node::{MixNode, Outbound};
use rand::Rng;

use crate::client::{Client, Dispatch};
use crate::directory::{Directory, NodeInfo};
use crate::provider::Provider;

/// A mesh with a virtual clock, where any node can be made hostile.
struct Mesh {
    dir: Directory,
    nodes: Vec<MixNode>,
    provider: Provider,
    provider_id: u16,
    inflight: Vec<(usize, Packet)>,
    now: u64,
    /// Nodes that silently discard everything.
    dropping: Vec<u16>,
    /// What the named node observed entering it, as (arrival time, first 8 payload bytes).
    entry_log: Vec<(u16, u64)>,
    watch: Option<u16>,
}

impl Mesh {
    fn new(layers: u8, per_layer: usize) -> Mesh {
        let mut dir = Directory::new(20.0);
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
            dropping: Vec::new(),
            entry_log: Vec::new(),
            watch: None,
        }
    }

    fn inject(&mut self, ds: Vec<Dispatch>) {
        for d in ds {
            self.inflight.push((d.via as usize, d.packet));
        }
    }

    fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.now += 1;
            for (idx, p) in std::mem::take(&mut self.inflight) {
                if self.dropping.contains(&(idx as u16)) {
                    continue;
                }
                if self.watch == Some(idx as u16) {
                    self.entry_log.push((idx as u16, self.now));
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

/// A mix that drops everything must not be able to make a message arrive corrupted.
///
/// Loss is honest failure. Silent corruption would be worse, because a recipient acting on
/// altered content is worse off than a recipient who received nothing.
#[test]
fn a_dropping_mix_causes_loss_and_never_corruption() {
    let mut mesh = Mesh::new(4, 3);
    mesh.dropping.push(1);
    let alice = Client::from_seed([1u8; 32], mesh.provider_id);
    let mut bob = Client::from_seed([2u8; 32], mesh.provider_id);
    let mut rng = rand::thread_rng();

    let msg: Vec<u8> = (0..crate::frame::DATA_BYTES * 6).map(|i| (i % 251) as u8).collect();
    let mut corrupted = 0;
    for _ in 0..30 {
        mesh.inject(alice.send(&mesh.dir, &bob.contact(), &msg, &mut rng).unwrap());
        mesh.run(1_500);
        for item in mesh.provider.collect(&bob.mailbox()).items {
            if let Some(got) = bob.accept(&item) {
                if got != msg {
                    corrupted += 1;
                }
            }
        }
    }
    assert_eq!(corrupted, 0, "a dropping mix produced corrupted output");

    // Non-vacuity, proved rather than sampled. Counting arrivals through the dropping mesh
    // would be a coin flip: a six fragment message survives a one-in-three entry drop only
    // 8.8% of the time, so a run where nothing arrives is ordinary rather than informative.
    // The same message through the same mesh with nothing dropping must arrive.
    let mut clean = Mesh::new(4, 3);
    let alice2 = Client::from_seed([1u8; 32], clean.provider_id);
    let mut bob2 = Client::from_seed([2u8; 32], clean.provider_id);
    clean.inject(alice2.send(&clean.dir, &bob2.contact(), &msg, &mut rng).unwrap());
    clean.run(2_500);
    let got: Vec<Vec<u8>> = clean
        .provider
        .collect(&bob2.mailbox())
        .items
        .into_iter()
        .filter_map(|i| bob2.accept(&i))
        .collect();
    assert_eq!(got, vec![msg], "the message does not arrive even with nothing dropping");
}

/// A mix altering a packet must destroy it rather than mark it.
///
/// This is the tagging attack end to end. A single bit flipped at one hop must not survive to
/// the provider as a recognisable pattern, because that is what lets a hostile entry and a
/// hostile exit confirm they are looking at the same packet.
#[test]
fn a_bit_flipped_in_flight_does_not_survive_to_the_provider() {
    let mut rng = rand::thread_rng();
    let mut recognisable = 0;
    for trial in 0..40u8 {
        let mut mesh = Mesh::new(3, 1);
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let bob = Client::from_seed([2u8; 32], mesh.provider_id);

        let ds = alice.send(&mesh.dir, &bob.contact(), b"traceable", &mut rng).unwrap();
        // Flip a bit as the first hop would, before injecting.
        let tampered: Vec<Dispatch> = ds
            .into_iter()
            .map(|d| Dispatch {
                via: d.via,
                packet: d.packet.tamper_payload(trial as usize * 13),
            })
            .collect();
        mesh.inject(tampered);
        mesh.run(1_500);

        for item in mesh.provider.collect(&bob.mailbox()).items {
            // A tagged packet that still decodes into anything the adversary planted is a
            // successful tag. Nothing should reach here at all.
            recognisable += 1;
            let _ = item;
        }
    }
    assert_eq!(
        recognisable, 0,
        "{recognisable} tampered packets reached the provider intact enough to file"
    );
}

/// Replaying a captured packet must fail at the first hop that saw it.
#[test]
fn a_captured_packet_cannot_be_replayed_into_the_network() {
    let mut mesh = Mesh::new(3, 1);
    let alice = Client::from_seed([1u8; 32], mesh.provider_id);
    let bob = Client::from_seed([2u8; 32], mesh.provider_id);
    let mut rng = rand::thread_rng();

    let ds = alice.send(&mesh.dir, &bob.contact(), b"once", &mut rng).unwrap();
    let copy: Vec<Dispatch> = ds
        .iter()
        .map(|d| Dispatch {
            via: d.via,
            packet: d.packet.clone(),
        })
        .collect();
    mesh.inject(ds);
    mesh.run(1_500);
    assert_eq!(mesh.provider.collect(&bob.mailbox()).items.len(), 1);

    // The adversary sends the same bytes again.
    mesh.inject(copy);
    mesh.run(1_500);
    assert_eq!(
        mesh.provider.collect(&bob.mailbox()).items.len(),
        0,
        "a replayed packet was delivered a second time"
    );
}

/// How much a colluding entry and provider learn, measured rather than asserted.
///
/// This pair is the classic first-last correlation and no mixnet defeats it: the entry sees
/// the sender's address, the provider sees the mailbox. What independent per-fragment routing
/// changes is the *rate*, since the pair only links a message when the entry drawn for a
/// fragment happens to be the hostile one.
#[test]
fn colluding_entry_and_provider_link_at_the_rate_the_topology_allows() {
    let per_layer = 4;
    let mut linked = 0;
    let trials = 400;
    let mut rng = rand::thread_rng();

    for _ in 0..trials {
        let mut mesh = Mesh::new(4, per_layer);
        // The adversary runs node 0 in the entry layer, and the provider.
        let alice = Client::from_seed([1u8; 32], mesh.provider_id);
        let bob = Client::from_seed([2u8; 32], mesh.provider_id);
        let ds = alice.send(&mesh.dir, &bob.contact(), b"one fragment", &mut rng).unwrap();
        if ds.iter().any(|d| d.via == 0) {
            linked += 1;
        }
        let _ = (&mesh.provider, &bob);
        mesh.inject(ds);
    }
    let rate = linked as f64 / trials as f64;
    let expected = 1.0 / per_layer as f64;
    assert!(
        (rate - expected).abs() < 0.06,
        "linkage {rate:.3} against a topological floor of {expected:.3}"
    );
}

/// A message spanning many fragments raises the chance a hostile entry sees at least one.
///
/// Independent routing spreads exposure rather than removing it, and spreading it means a
/// longer message is *more* likely to touch a given node at least once. This states the cost
/// so it is not mistaken for a free improvement.
#[test]
fn longer_messages_touch_a_hostile_entry_more_often() {
    let per_layer = 4;
    let mut rng = rand::thread_rng();
    let mesh = Mesh::new(4, per_layer);
    let alice = Client::from_seed([1u8; 32], mesh.provider_id);
    let bob = Client::from_seed([2u8; 32], mesh.provider_id);

    let mut rates = Vec::new();
    for frags in [1usize, 4, 16] {
        let msg = vec![0u8; crate::frame::DATA_BYTES * (frags - 1) + 1];
        let mut touched = 0;
        let trials = 600;
        for _ in 0..trials {
            let ds = alice.send(&mesh.dir, &bob.contact(), &msg, &mut rng).unwrap();
            assert_eq!(ds.len(), frags);
            if ds.iter().any(|d| d.via == 0) {
                touched += 1;
            }
        }
        rates.push(touched as f64 / trials as f64);
    }
    // 1 - (3/4)^n for n = 1, 4, 16.
    for (i, n) in [1u32, 4, 16].iter().enumerate() {
        let expected = 1.0 - 0.75f64.powi(*n as i32);
        assert!(
            (rates[i] - expected).abs() < 0.07,
            "{n} fragments touched a hostile entry {:.3} of the time, expected {expected:.3}",
            rates[i]
        );
    }
    assert!(rates[2] > rates[0], "exposure did not rise with length");
}

/// Building cover lazily at emission time is a timing side channel.
///
/// The pacer decides *when* to emit without reference to the queue, which is the property that
/// matters. But if a real emission is a queue pop and a cover emission builds a Sphinx packet
/// from scratch, the two cost very different amounts of CPU, and the packet reaches the socket
/// at measurably different offsets from the scheduled instant. An observer with fine timing
/// resolution then separates real from cover without breaking anything.
///
/// The fix is to pre-build cover, so emission is a pop either way.
#[test]
fn real_and_cover_emissions_cost_the_same_to_produce() {
    let mesh = Mesh::new(4, 3);
    let alice = Client::from_seed([1u8; 32], mesh.provider_id);
    let bob = Client::from_seed([2u8; 32], mesh.provider_id);
    let mut rng = rand::thread_rng();

    let mut pool = crate::runner::CoverPool::new(64);
    pool.refill(&alice, &mesh.dir, mesh.provider_id, &mut rng);

    // Cost of taking a pre-built cover packet.
    let mut cover_ns = Vec::new();
    for _ in 0..200 {
        pool.refill(&alice, &mesh.dir, mesh.provider_id, &mut rng);
        let t = Instant::now();
        let got = pool.take();
        cover_ns.push(t.elapsed().as_nanos());
        assert!(got.is_some());
    }

    // Cost of taking a real one out of a queue.
    let mut queue: Vec<Dispatch> = Vec::new();
    for _ in 0..200 {
        queue.extend(alice.send(&mesh.dir, &bob.contact(), b"x", &mut rng).unwrap());
    }
    let mut real_ns = Vec::new();
    for _ in 0..200 {
        let t = Instant::now();
        let _ = queue.pop();
        real_ns.push(t.elapsed().as_nanos());
    }

    let med = |mut v: Vec<u128>| {
        v.sort_unstable();
        v[v.len() / 2] as f64
    };
    let (c, r) = (med(cover_ns), med(real_ns));
    // Both are a move out of a container. Building a Sphinx packet is five X25519 operations
    // and would be orders of magnitude above this.
    assert!(
        c < 20_000.0 && r < 20_000.0,
        "cover {c}ns and real {r}ns should both be a pop, not a construction"
    );
}

/// A client's emission schedule must not shift when it starts sending.
///
/// End to end version of the pacer property: the schedule is drawn from a dedicated stream, so
/// an adversary comparing a silent client to a busy one sees the same instants.
#[test]
fn a_clients_schedule_does_not_move_when_it_starts_talking() {
    use karst_wire::Pacer;
    let mesh = Mesh::new(4, 3);
    let alice = Client::from_seed([1u8; 32], mesh.provider_id);
    let bob = Client::from_seed([2u8; 32], mesh.provider_id);
    let mut rng = rand::thread_rng();

    let mut run = |talking: bool| {
        let mut p: Pacer<u8> = Pacer::seeded(30.0, 4242);
        let mut times = Vec::new();
        for t in 0..15_000u64 {
            if talking && t % 40 == 0 {
                for _ in alice.send(&mesh.dir, &bob.contact(), b"chatter", &mut rng).unwrap() {
                    let _ = p.offer(1u8);
                }
            }
            for _ in p.tick(t, || 0u8) {
                times.push(t);
            }
        }
        times
    };
    let silent = run(false);
    let busy = run(true);
    assert!(silent.len() > 300, "vacuous: {} emissions", silent.len());
    assert_eq!(silent, busy, "talking moved the schedule");
}

/// A provider must not be able to learn a mailbox is live by probing.
#[test]
fn collecting_an_unused_tag_is_indistinguishable_from_an_empty_one() {
    let mut p = Provider::new();
    let a = p.collect(&[1u8; 32]);
    let b = p.collect(&[2u8; 32]);
    assert_eq!(a, b);
}

/// Every packet a client emits must be the same size, cover or not.
#[test]
fn cover_and_real_packets_are_byte_identical_in_length() {
    let mesh = Mesh::new(4, 3);
    let alice = Client::from_seed([1u8; 32], mesh.provider_id);
    let bob = Client::from_seed([2u8; 32], mesh.provider_id);
    let mut rng = rand::thread_rng();

    let real = alice.send(&mesh.dir, &bob.contact(), b"", &mut rng).unwrap();
    let cover = alice.cover(&mesh.dir, mesh.provider_id, &mut rng).unwrap();
    assert_eq!(real[0].packet.to_bytes().len(), cover.packet.to_bytes().len());

    let full = alice
        .send(&mesh.dir, &bob.contact(), &vec![3u8; crate::frame::DATA_BYTES], &mut rng)
        .unwrap();
    assert_eq!(full[0].packet.to_bytes().len(), cover.packet.to_bytes().len());
}

/// A hostile entry must not learn the destination from what it is handed.
#[test]
fn the_entry_node_cannot_read_the_destination() {
    let mut mesh = Mesh::new(4, 2);
    let alice = Client::from_seed([1u8; 32], mesh.provider_id);
    let bob = Client::from_seed([2u8; 32], mesh.provider_id);
    let mut rng = rand::thread_rng();

    let ds = alice.send(&mesh.dir, &bob.contact(), b"m", &mut rng).unwrap();
    let entry = ds[0].via as usize;
    let bytes = ds[0].packet.to_bytes();
    let tag = bob.mailbox();
    assert!(
        !bytes.windows(32).any(|w| w == tag),
        "the mailbox tag was readable in the packet handed to the entry node"
    );

    // And peeling one layer reveals only the next hop, not the last.
    let mut seen = karst_mix::packet::SeenTags::new();
    let key = MixKey::from_seed([(entry as u8).wrapping_add(1); 32]);
    let mut p = ds.into_iter().next().unwrap().packet;
    let peeled = p.peel(&key, &mut seen).unwrap();
    match peeled {
        karst_mix::packet::Peeled::Forward { next, packet, .. } => {
            assert_ne!(next, mesh.provider_id, "the entry saw the terminal hop");
            assert!(
                !packet.to_bytes().windows(32).any(|w| w == tag),
                "the tag was readable one hop in"
            );
        }
        _ => panic!("a four layer route terminated at the entry"),
    }
    let _ = &mut mesh;
}
