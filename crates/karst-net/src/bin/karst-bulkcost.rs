//! What the mix network can carry, and what it cannot.
//!
//! `cargo run --release -p karst-net --bin karst-bulkcost`
//!
//! Anonymity at L4 is bought with constant-rate emission: a client sends the same number of
//! fixed-size packets whether it has anything to say or not. That is what makes its traffic
//! unreadable, and it is also a hard ceiling on how much it can say. This measures the
//! ceiling, because a design that quietly assumes bulk transfer works is a design that will
//! be discovered not to work by whoever tries to watch a video.

use karst_net::frame::DATA_BYTES;

/// Client emission rates, in packets per second.
const RATES: [f64; 4] = [20.0, 60.0, 250.0, 1000.0];

fn human_bytes(n: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1}{}", UNITS[u])
}

fn human_time(secs: f64) -> String {
    if secs < 90.0 {
        format!("{secs:.0}s")
    } else if secs < 5_400.0 {
        format!("{:.1}min", secs / 60.0)
    } else if secs < 172_800.0 {
        format!("{:.1}h", secs / 3_600.0)
    } else {
        format!("{:.1}d", secs / 86_400.0)
    }
}

fn rule(t: &str) {
    println!("\n\x1b[1m{}\x1b[0m", t);
    println!("{}", "-".repeat(t.len()));
}

fn note(s: &str) {
    println!("  \x1b[2m{}\x1b[0m", s);
}

fn main() {
    println!("\n\x1b[1mWhat the mix network can carry\x1b[0m");
    note(&format!(
        "Each packet carries {DATA_BYTES} bytes of message inside a 1024 byte datagram."
    ));

    rule("Goodput per client, and what it costs the link");

    println!(
        "  {:>10}  {:>12}  {:>14}  {:>16}",
        "packets/s", "goodput", "link bandwidth", "overhead"
    );
    println!("  {}", "-".repeat(58));
    for r in RATES {
        let goodput = r * DATA_BYTES as f64;
        let wire = r * 1024.0;
        println!(
            "  {:>10.0}  {:>10}/s  {:>12}/s  {:>15.1}x",
            r,
            human_bytes(goodput),
            human_bytes(wire),
            wire / goodput
        );
    }
    note("The overhead column is only framing. The real cost is that this rate is paid");
    note("constantly, whether or not there is anything to send, which is the point.");

    rule("How long one client takes to publish something");

    let sizes: [(&str, f64); 5] = [
        ("a short document", 4.0 * 1024.0),
        ("a photograph", 4.0 * 1024.0 * 1024.0),
        ("a podcast episode", 60.0 * 1024.0 * 1024.0),
        ("an hour of video", 1.5 * 1024.0 * 1024.0 * 1024.0),
        ("a film", 8.0 * 1024.0 * 1024.0 * 1024.0),
    ];
    print!("  {:<20}", "");
    for r in RATES {
        print!("{:>13}", format!("{r:.0}/s"));
    }
    println!();
    println!("  {}", "-".repeat(20 + 13 * RATES.len()));
    for (name, bytes) in sizes {
        print!("  {name:<20}");
        for r in RATES {
            let secs = bytes / (r * DATA_BYTES as f64);
            print!("{:>13}", human_time(secs));
        }
        println!();
    }

    rule("The verdict, stated rather than implied");

    note("At any rate that keeps cover traffic affordable, bulk media does not fit. A client");
    note("emitting 60 packets a second sends 41KB/s, and an hour of video takes over ten");
    note("hours. Raising the rate to make video work multiplies every client's constant cost");
    note("by the same factor, including the clients who only send text.");
    println!();
    note("This is not an implementation problem and no amount of engineering removes it.");
    note("Das, Meiser, Mohammadi and Kate (S&P 2018) prove the shape of it: strong anonymity,");
    note("low bandwidth overhead and low latency are not simultaneously achievable. Constant");
    note("rate emission is the design choosing the first two and paying in the third.");
    println!();
    note("So the honest split is that the mix network carries what is small and sensitive,");
    note("and bulk moves another way with its exposure written down rather than hoped away.");
    println!();
}
