//! Stand up a network and send a message across it.
//!
//! Seven mixes in four layers on real UDP sockets, one thread each, plus two clients who have
//! never met a name server. Run with `cargo run -p karst-net --bin karst-net-demo`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use karst_id::Identity;
use karst_mix::loops::Baseline;
use karst_mix::packet::MixKey;
use karst_net::client::Client;
use karst_net::directory::{Directory, NodeInfo};
use karst_net::runner::{ClientRunner, NodeRunner};
use karst_net::sentinel::Sentinel;
use karst_node::MixNode;

const LAYERS: u8 = 4;
const PER_LAYER: usize = 2;
/// Client emission rate. Every client sends this many packets a second forever, whether or not
/// it has anything to say.
const LAMBDA: f64 = 40.0;

fn rule(title: &str) {
    println!("\n\x1b[1m{}\x1b[0m", title);
    println!("{}", "-".repeat(title.len()));
}

fn note(s: &str) {
    println!("  \x1b[2m{}\x1b[0m", s);
}

fn local() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn main() -> std::io::Result<()> {
    println!("\n\x1b[1mKARST: a running network\x1b[0m");

    rule("Standing up mixes");

    // Build every node first, so sockets are bound and addresses are known.
    let mut runners = Vec::new();
    let mut infos = Vec::new();
    let mut id = 0u16;
    let mut provider_id = 0u16;
    let mut provider_collect = None;

    for layer in 0..LAYERS {
        let count = if layer == LAYERS - 1 { 1 } else { PER_LAYER };
        for _ in 0..count {
            let key = MixKey::from_seed(rand::random());
            let public = key.public();
            let node = MixNode::new(key);
            let mut r = NodeRunner::new(id, node, local())?;
            if layer == LAYERS - 1 {
                r = r.serving_mail(local())?;
                provider_id = id;
                provider_collect = r.collect_addr();
            }
            infos.push(NodeInfo {
                id,
                addr: r.addr()?,
                mix_public: public,
                layer,
            });
            runners.push(r);
            id += 1;
        }
    }

    let mut dir = Directory::new(25.0);
    for i in &infos {
        dir.add(i.clone());
    }
    for (r, i) in runners.iter_mut().zip(infos.iter()) {
        r.set_directory(dir.clone());
        let role = if i.id == provider_id {
            "provider"
        } else {
            "mix"
        };
        println!(
            "  node {:>2}  layer {}  {:<22} {}",
            i.id, i.layer, i.addr, role
        );
    }
    note(&format!(
        "{} nodes, {} mixing layers, mean per-hop delay 25ms",
        infos.len(),
        LAYERS
    ));

    // Each node runs itself. One stop flag per node, so a node can be taken down alone.
    let stop = Arc::new(AtomicBool::new(false));
    let mut kill: Vec<Arc<AtomicBool>> = Vec::new();
    let mut threads = Vec::new();
    let counts = Arc::new(std::sync::Mutex::new(Vec::new()));
    for mut r in runners {
        let stop = Arc::clone(&stop);
        let counts = Arc::clone(&counts);
        let mine = Arc::new(AtomicBool::new(false));
        kill.push(Arc::clone(&mine));
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if !mine.load(Ordering::Relaxed) {
                    r.step();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            counts.lock().unwrap().push((r.id, r.stats(), r.holding()));
        }));
    }

    rule("Two clients, who have never met a name server");

    let collect_at = provider_collect.expect("the last layer serves mail");
    let alice_c = Client::new(Identity::generate(), provider_id);
    let bob_c = Client::new(Identity::generate(), provider_id);
    let bob_contact = bob_c.contact();
    let alice_contact = alice_c.contact();

    println!("  alice  {}", alice_c.address().short());
    println!("  bob    {}", bob_c.address().short());
    note("A contact is a mailbox tag, a sealing key and a provider. No name, no location.");

    // Loops are sent to a mailbox the client owns, so their absence is measurable. The
    // baseline is set here rather than learned, because a baseline learned from a channel the
    // adversary sits on can be walked upward until nothing looks wrong.
    let mut alice = ClientRunner::new(alice_c, local(), dir.clone(), collect_at, LAMBDA)?
        .watching(Sentinel::new(Baseline::Fixed(0.05), 0.001, 4_000));
    let mut bob = ClientRunner::new(bob_c, local(), dir.clone(), collect_at, LAMBDA)?;

    rule("Both clients emit at a constant rate before anything is said");

    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_millis(600) {
        alice.step();
        bob.step();
        std::thread::sleep(Duration::from_millis(1));
    }
    println!(
        "  alice sent {} packets, {} of them cover",
        alice.stats().real + alice.stats().cover,
        alice.stats().cover
    );
    note("An observer on alice's link has now seen a full stream and learned nothing.");

    rule("Alice sends");

    let message = b"There is no operator of this network. That is the point.";
    alice.send(&bob_contact, message).unwrap();
    println!("  {} bytes handed to the link", message.len());
    note("It leaves on the link's schedule, mixed into the same stream as the cover.");

    let deadline = Instant::now() + Duration::from_secs(12);
    let mut delivered_at = None;
    while Instant::now() < deadline && delivered_at.is_none() {
        alice.step();
        bob.step();
        bob.poll_mail();
        if !bob.received.is_empty() {
            delivered_at = Some(Instant::now());
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    rule("Bob collects");

    match bob.received.first() {
        Some(m) => {
            println!("  \x1b[32m{}\x1b[0m", String::from_utf8_lossy(m));
            assert_eq!(m, message, "what arrived was not what was sent");
        }
        None => {
            println!("  \x1b[31mnothing arrived\x1b[0m");
        }
    }

    rule("Bob replies");

    bob.send(
        &alice_contact,
        b"Received. Nothing in between knew either of us.",
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline && alice.received.is_empty() {
        alice.step();
        bob.step();
        alice.poll_mail();
        std::thread::sleep(Duration::from_millis(2));
    }
    match alice.received.first() {
        Some(m) => println!("  \x1b[32m{}\x1b[0m", String::from_utf8_lossy(m)),
        None => println!("  \x1b[31mno reply\x1b[0m"),
    }

    rule("Alice keeps sending loops to herself, and the network is healthy");

    let spin = |a: &mut ClientRunner, b: &mut ClientRunner, ms: u64, loops: u64| {
        let t = Instant::now();
        let mut sent = 0;
        while t.elapsed() < Duration::from_millis(ms) {
            if sent < loops && t.elapsed().as_millis() as u64 > sent * (ms / loops.max(1)) {
                a.dispatch_loop();
                sent += 1;
            }
            a.step();
            b.step();
            a.poll_mail();
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    spin(&mut alice, &mut bob, 6_000, 30);
    if let Some(s) = alice.sentinel() {
        println!(
            "  {} loops accounted for, loss {:.1}%",
            s.samples(),
            s.loss_rate() * 100.0
        );
        match s.alarm() {
            None => println!("  \x1b[32mno alarm\x1b[0m"),
            Some(a) => println!(
                "  \x1b[31malarm: {:.1}% loss, p={:.2e}\x1b[0m",
                a.observed_rate * 100.0,
                a.p_value
            ),
        }
    }
    note("Loops are ordinary mail addressed to a mailbox alice owns. No node can tell one from");
    note("real traffic, so no node can drop one and not the other.");

    rule("Now a mix stops forwarding");

    kill[0].store(true, Ordering::Relaxed);
    println!("  node 0 is down. Half of alice's routes enter through it.");
    spin(&mut alice, &mut bob, 12_000, 60);
    if let Some(s) = alice.sentinel() {
        println!(
            "  {} loops accounted for, loss {:.1}%",
            s.samples(),
            s.loss_rate() * 100.0
        );
        match s.alarm() {
            None => println!("  \x1b[33mno alarm yet\x1b[0m"),
            Some(a) => println!(
                "  \x1b[31malarm: {:.1}% loss against a {:.0}% baseline, p={:.2e}\x1b[0m",
                a.observed_rate * 100.0,
                a.baseline_rate * 100.0,
                a.p_value
            ),
        }
    }
    note("An adversary who stays under the baseline is invisible to this, and no amount of");
    note("sampling changes that. Detection is not prevention.");

    rule("What each node saw");

    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    let counts = counts.lock().unwrap();
    let mut rows: Vec<_> = counts.iter().collect();
    rows.sort_by_key(|(id, _, _)| *id);
    println!(
        "  {:>4}  {:>9} {:>9} {:>9} {:>7}",
        "node", "accepted", "forwarded", "cover", "held"
    );
    for (id, s, held) in rows {
        println!(
            "  {:>4}  {:>9} {:>9} {:>9} {:>7}",
            id, s.accepted, s.forwarded, s.cover_absorbed, held
        );
    }

    let total_cover: u64 = counts.iter().map(|(_, s, _)| s.cover_absorbed).sum();
    let total_real: u64 = counts.iter().map(|(_, s, _)| s.delivered).sum();
    println!();
    note(&format!(
        "{total_cover} cover packets carried and discarded, {total_real} real ones delivered."
    ));
    note("No node on any path saw both ends. The provider held mail it could not read.");

    println!();
    Ok(())
}
