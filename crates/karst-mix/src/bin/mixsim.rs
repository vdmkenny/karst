//! Global passive adversary simulation.
//!
//! `cargo run -p karst-mix --bin karst-mixsim`

use karst_mix::sim::{run, SimConfig};
use karst_mix::{Hop, MixKey, Packet, Peeled, PACKET_BYTES};

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
    let mut wire = vec![p.to_bytes()];
    let mut cur = p;
    for k in keys.iter().take(2) {
        let Peeled::Forward { packet, next, delay_ms } = cur.peel(k).unwrap() else {
            unreachable!()
        };
        println!("  hop -> {next}, hold {delay_ms}ms, still {PACKET_BYTES} bytes");
        wire.push(packet.to_bytes());
        cur = packet;
    }
    match cur.peel(&keys[2]).unwrap() {
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

    println!("\n\x1b[1mWhat this shows, including the part we did not expect\x1b[0m");
    println!("{}", "-".repeat(70));
    println!("  Onion routing is trivially broken by this adversary, which is not news:");
    println!("  Tor says so itself. Volume alone identifies who was talking.");
    println!();
    println!("  \x1b[1mConstant rate cover is the mechanism doing the work.\x1b[0m Poisson delay");
    println!("  alone still leaves the adversary a real advantage, and cover alone scores");
    println!("  identically to cover plus delay. Uniform cover at every tick is effectively");
    println!("  a synchronous batch mix, and a batch mix is strong against an observer who");
    println!("  only watches.");
    println!();
    println!("  \x1b[1mSo this harness does not justify the delay layer.\x1b[0m Loopix's case for it");
    println!("  rests on resistance to active n-1 and flooding attacks, and on not needing");
    println!("  the global clock synchronisation a batch mix requires. Neither is modelled");
    println!("  here. Until they are, the delay mechanism is taken on the paper's authority");
    println!("  rather than on our own evidence. Tracked as an open issue.");
    println!();
    println!("  Not modelled: active adversaries, node compromise, long-run intersection");
    println!("  attacks across sessions, packet loss, or a real implementation's bugs.");
    println!();
    println!("  \x1b[1mThe cost is the honest headline.\x1b[0m Constant rate cover means every client");
    println!("  transmits every tick forever, which at this duty cycle is roughly 200x the");
    println!("  bandwidth, charged continuously to everyone including everyone who did not");
    println!("  need it. Any presentation of this design that omits that number is selling");
    println!("  something.\n");
}
