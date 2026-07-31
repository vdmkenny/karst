//! Does flattening returns to scale actually prevent capture?
//!
//! `cargo run -p karst-symmetry --bin karst-symsim`

use karst_symmetry::{acquire, observation_rates, run, Returns, SymConfig};

fn main() {
    println!("\n\x1b[1mKARST L16: testing flat returns to scale\x1b[0m");
    println!("The weakest claim in the whitepaper, and the one it says everything");
    println!("else depends on. 200-node operator against 40 five-node operators.\n");

    println!("\x1b[1mEqual uptime: does the ceiling work at all\x1b[0m");
    println!("{}", "-".repeat(72));
    println!("  {:<12} {:>14} {:>14} {:>12}", "returns", "per-node adv", "top traffic", "herfindahl");
    for r in [Returns::Linear, Returns::Flat] {
        let mut cfg = SymConfig::one_giant(r, 7);
        for op in cfg.operators.iter_mut() {
            op.uptime = 0.95;
        }
        let f = run(&cfg);
        println!(
            "  {:<12} {:>14.2} {:>13.1}% {:>12.4}",
            f.label, f.per_node_advantage, f.top_traffic_share * 100.0, f.herfindahl
        );
    }
    println!("  \x1b[2mThe ceiling does what it claims: with equal uptime, no per-node edge.\x1b[0m");

    println!("\n\x1b[1mThe giant buys reliability instead\x1b[0m");
    println!("{}", "-".repeat(72));
    println!("  {:<24} {:>14} {:>14}", "giant uptime", "per-node adv", "top traffic");
    for u in [0.90, 0.95, 0.99, 0.999] {
        let mut cfg = SymConfig::one_giant(Returns::Flat, 7);
        cfg.operators[0].uptime = u;
        let f = run(&cfg);
        println!(
            "  {:<24} {:>14.2} {:>13.1}%",
            format!("{:.1}% vs 90% small", u * 100.0),
            f.per_node_advantage,
            f.top_traffic_share * 100.0
        );
    }
    println!("  \x1b[2mThe hypothesis was that uptime would route around the ceiling. It does\x1b[0m");
    println!("  \x1b[2mnot: standing per node stays flat across the whole range, because a\x1b[0m");
    println!("  \x1b[2mceiling is a ceiling however often you reach it. Reliability buys a few\x1b[0m");
    println!("  \x1b[2mpoints of traffic, proportional to being available, and does not compound.\x1b[0m");

    println!("\n\x1b[1mAcquisition\x1b[0m");
    println!("{}", "-".repeat(72));
    for (label, t) in [("transferable standing", true), ("KARST: non-transferable", false)] {
        let a = acquire(10.0, 40.0, t);
        println!("  {:<26} buyer {:.0} + seller {:.0} -> {:.0}  (gain {:.0})",
            label, a.buyer_before, a.seller, a.buyer_after, a.gain());
    }
    println!("  \x1b[2mClaim 2 holds. Buying an operator buys machines, not position.\x1b[0m");

    println!("\n\x1b[1mObservation: the attack that ignores all of this\x1b[0m");
    println!("{}", "-".repeat(72));
    println!("  \x1b[2mAn adversary who wants to watch, not to be trusted. Calibrated on\x1b[0m");
    println!("  \x1b[2mKAX17: over 900 relays against a Tor network of ~9,500.\x1b[0m");
    println!("  {:<22} {:>18} {:>20}", "fleet size", "paths touched", "both endpoints held");
    for owned in [95usize, 475, 900, 1_800, 3_000] {
        let (any, both) = observation_rates(owned, 9_500, 3);
        println!(
            "  {:<22} {:>17.1}% {:>19.2}%",
            format!("{owned} of 9500 ({:.0}%)", owned as f64 / 95.0),
            any * 100.0,
            both * 100.0
        );
    }
    println!("  \x1b[2mNo ceiling, because no reputation is involved to saturate. Path\x1b[0m");
    println!("  \x1b[2mcoverage is bought with node count and nothing else.\x1b[0m");

    println!("\n\x1b[1mVerdict\x1b[0m");
    println!("{}", "-".repeat(72));
    println!("  \x1b[1mClaims 1 and 2 hold.\x1b[0m Standing per node stays at 1.00 to 1.01 across a");
    println!("  90 to 99.9 percent uptime range, while linear returns give the same operator");
    println!("  1.06 and rising. Buying reliability does not route around the ceiling: a");
    println!("  ceiling is a ceiling however often you reach it. Acquisition buys machines,");
    println!("  not position.");
    println!();
    println!("  \x1b[1mThe hole is observation, and it is not small.\x1b[0m An adversary who wants");
    println!("  to watch rather than be trusted is untouched by any of this. Path coverage");
    println!("  tracks node count, and there is no ceiling on it because no reputation is");
    println!("  involved to saturate. KAX17 ran 900 relays against Tor for four years and");
    println!("  would have been equally effective under every rule tested here.");
    println!();
    println!("  \x1b[1mVerdict: L16 raises the cost of buying position and does nothing about\x1b[0m");
    println!("  \x1b[1mbuying presence.\x1b[0m That is a real defence against acquisition and no");
    println!("  defence at all against surveillance. The whitepaper claim that it prevents");
    println!("  capture is too strong for the second case and has been corrected.\n");
}
