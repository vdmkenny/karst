//! Global passive adversary simulation.
//!
//! `cargo run -p karst-mix --bin karst-mixsim`

use karst_mix::active::{batch_under_skew, drain_cost, n_minus_one, ActiveConfig, Discipline};
use karst_mix::sim::{run, SimConfig};
use karst_mix::{Hop, MixKey, Packet, Peeled, SeenTags, PACKET_BYTES};

fn main() {
    println!("\n\x1b[1mKARST L4: mixing against a global passive adversary\x1b[0m");
    println!("The adversary observes every link in the network simultaneously.");
    println!("It sees packet counts per link per tick, and nothing else, because");
    println!("packets are one fixed size and unlinkable between hops.\n");

    // -------------------------------------------------- packet properties
    println!("\x1b[1mPacket\x1b[0m");
    println!("{}", "-".repeat(70));
    let keys: Vec<MixKey> = (0..3).map(|i| MixKey::from_seed([i + 1; 32])).collect();
    let route: Vec<Hop> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| Hop {
            id: i as u16,
            public: k.public(),
            delay_ms: 100 * (i as u32 + 1),
        })
        .collect();

    let p = Packet::wrap(&route, b"meet me at the usual place", [42u8; 32]).unwrap();
    let mut seen: Vec<SeenTags> = (0..3).map(|_| SeenTags::new()).collect();
    let mut wire = vec![p.to_bytes()];
    let mut cur = p;
    for (i, k) in keys.iter().take(2).enumerate() {
        let Peeled::Forward { packet, next, delay_ms } = cur.peel(k, &mut seen[i]).unwrap() else {
            unreachable!()
        };
        println!("  hop -> {next}, hold {delay_ms}ms, still {PACKET_BYTES} bytes");
        wire.push(packet.to_bytes());
        cur = packet;
    }
    match cur.peel(&keys[2], &mut seen[2]).unwrap() {
        Peeled::Deliver { payload, .. } => {
            println!("  delivered: {:?}", String::from_utf8_lossy(&payload))
        }
        _ => unreachable!(),
    }

    for i in 0..wire.len() - 1 {
        let same = wire[i]
            .iter()
            .zip(wire[i + 1].iter())
            .filter(|(a, b)| a == b)
            .count();
        println!(
            "  bytes shared between hop {i} and hop {}: {same} of {PACKET_BYTES} ({:.1}%)",
            i + 1,
            100.0 * same as f64 / PACKET_BYTES as f64
        );
    }
    println!("  \x1b[2mA relay cannot recognise a packet it has already seen.\x1b[0m\n");

    // -------------------------------------------------- the attack
    let base = SimConfig::karst(7);
    println!(
        "\x1b[1mCorrelation attack: {} clients, {} mix layers, {} ticks, {:.1}% duty cycle\x1b[0m",
        base.clients,
        base.layers,
        base.ticks,
        base.real_rate * 100.0
    );
    println!("{}", "-".repeat(70));
    println!(
        "  {:<34} {:>7} {:>8} {:>9} {:>8}",
        "configuration", "vol.leak", "anon.set", "adv.gain", "overhead"
    );

    let configs = [
        SimConfig::onion_routing(7),
        SimConfig::mixing_only(7),
        SimConfig::cover_only(7),
        SimConfig::karst(7),
    ];

    for cfg in &configs {
        let r = run(cfg);
        let flag = if r.advantage() < 1.05 { "\x1b[32m" } else { "\x1b[31m" };
        println!(
            "  {:<34} {:>7.3} {:>8.1} {}{:>8.1}x\x1b[0m {:>7.0}x",
            r.label,
            r.volume_leak,
            r.mean_anonymity_set,
            flag,
            r.advantage(),
            r.bandwidth_overhead()
        );
    }

    println!("\n  \x1b[2mvol.leak  coefficient of variation in how much each client sent.\x1b[0m");
    println!("  \x1b[2m          0.000 means an observer learns nothing from volume.\x1b[0m");
    println!(
        "  \x1b[2manon.set  clients the adversary cannot rule out. Ceiling is {}.\x1b[0m",
        base.clients
    );
    println!("  \x1b[2madv.gain  how much better than guessing. 1.0x means the design held.\x1b[0m");
    println!("  \x1b[2moverhead  packets sent per real message. This is what it costs.\x1b[0m");

    // -------------------------------------------------- delay tradeoff
    println!("\n\x1b[1mThe delay knob, with cover off\x1b[0m");
    println!("{}", "-".repeat(70));
    println!("  \x1b[2mWith cover on the candidate set is already every client, so delay has\x1b[0m");
    println!("  \x1b[2mnothing left to buy. Its effect is only measurable without cover.\x1b[0m");
    println!("  {:<12} {:>10} {:>10}", "mean delay", "anon.set", "adv.gain");
    for d in [1.0, 2.0, 4.0, 8.0, 16.0, 32.0] {
        let mut cfg = SimConfig::mixing_only(7);
        cfg.mean_delay = d;
        let r = run(&cfg);
        println!(
            "  {:<12} {:>10.1} {:>9.2}x",
            format!("{d} ticks"),
            r.mean_anonymity_set,
            r.advantage()
        );
    }

    // -------------------------------------------------- active adversary
    println!("\n\x1b[1mActive adversary: the n-1 attack\x1b[0m");
    println!("{}", "-".repeat(70));
    println!("  \x1b[2mSuppress every other honest packet entering a mix, inject packets you\x1b[0m");
    println!("  \x1b[2mcan recognise, and anything else leaving is the target.\x1b[0m");
    println!(
        "  {:<24} {:>10} {:>11} {:>12} {:>10}",
        "discipline", "anon.set", "isolated", "suppressed", "detected"
    );

    for d in [Discipline::Batch { round_ticks: 1 }, Discipline::Poisson] {
        let r = n_minus_one(&ActiveConfig {
            discipline: d,
            ..ActiveConfig::default()
        });
        let flag = if r.isolation_rate > 0.1 { "\x1b[31m" } else { "\x1b[32m" };
        println!(
            "  {:<24} {:>10.1} {}{:>10.1}%\x1b[0m {:>12.0} {:>9.1}%",
            r.label,
            r.mean_anonymity_set,
            flag,
            r.isolation_rate * 100.0,
            r.mean_suppressed,
            r.detection_probability * 100.0
        );
    }

    let (ticks, packets) = drain_cost(10.0, 8.0, 1.0);
    println!(
        "\n  \x1b[2mDraining a Poisson mix from steady state to one packet takes {ticks:.0} ticks\x1b[0m"
    );
    println!("  \x1b[2mand costs {packets:.0} suppressed packets. A batch mix needs one flush.\x1b[0m");
    println!("  \x1b[2mExponential residuals are memoryless, so waiting does not help the\x1b[0m");
    println!("  \x1b[2madversary: the backlog never ages out, it only drains.\x1b[0m");

    // -------------------------------------------------- clock skew
    println!("\n\x1b[1mBatching needs a clock. Continuous time does not.\x1b[0m");
    println!("{}", "-".repeat(70));
    println!(
        "  {:<16} {:>12} {:>12} {:>14}",
        "clock skew", "mean batch", "worst batch", "batches < 3"
    );
    for skew in [0.0, 0.25, 0.5, 1.0, 2.0] {
        let s = batch_under_skew(10.0, 1.0, skew, 800, 5);
        println!(
            "  {:<16} {:>12.1} {:>12} {:>13.1}%",
            format!("{skew} ticks"),
            s.mean_batch,
            s.min_batch,
            s.degenerate_fraction * 100.0
        );
    }
    println!("  \x1b[2mA Poisson mix has no row here, because it has no round boundary for\x1b[0m");
    println!("  \x1b[2manyone to disagree about. A mechanism you cannot misconfigure is worth\x1b[0m");
    println!("  \x1b[2msomething that does not show up in a passive measurement.\x1b[0m");

    println!("\n\x1b[1mWhat this shows\x1b[0m");
    println!("{}", "-".repeat(70));
    println!("  Onion routing is trivially broken by a whole-network observer, which is");
    println!("  not news: Tor says so itself. Volume alone identifies who was talking.");
    println!();
    println!("  \x1b[1mAgainst a passive adversary, cover traffic does all the work.\x1b[0m Poisson");
    println!("  delay alone still leaves a real advantage, and cover alone scores exactly");
    println!("  as well as cover plus delay. Passive evidence alone does not justify the");
    println!("  delay layer.");
    println!();
    println!("  \x1b[1mThe active adversary does.\x1b[0m Uniform cover with prompt forwarding");
    println!("  is a synchronous batch mix, and a batch mix has a moment when it is empty");
    println!("  but for the target. Suppress one round of arrivals, 10 packets, and the");
    println!("  target walks out alone half the time. A Poisson mix has no such moment:");
    println!("  exponential residuals are memoryless, so the backlog never ages out, it");
    println!("  only drains, and draining it costs hundreds of suppressed packets that");
    println!("  loop traffic detects with certainty.");
    println!();
    println!("  \x1b[1mBatching also needs a clock.\x1b[0m At one tick of skew, a third of batches");
    println!("  hold fewer than three packets and the worst holds none. Continuous time");
    println!("  has no round boundary to disagree about.");
    println!();
    println!("  So the delay layer earns its place, and not for the reason the passive");
    println!("  measurement suggested. Both mechanisms are load bearing, against different");
    println!("  adversaries.");
    println!();
    println!("  Still not modelled: node compromise, long-run intersection attacks across");
    println!("  sessions, packet loss, and a real implementation's bugs.");
    println!();
    println!("  \x1b[1mThe cost is the honest headline.\x1b[0m Constant rate cover means every client");
    println!("  transmits every tick forever, which at this duty cycle is roughly 200x the");
    println!("  bandwidth, charged continuously to everyone including everyone who did not");
    println!("  need it. Any presentation of this design that omits that number is selling");
    println!("  something.\n");
}
