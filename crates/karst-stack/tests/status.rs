//! The paper's summary table must agree with the paper.
//!
//! §8 exists to tell a reader what is built. It went stale while the per-layer status lines
//! were kept current, so for a stretch the one section a reader consults for status said ten
//! of seventeen layers had no code, while the layers themselves said otherwise (#102).
//!
//! Drift is the default for a hand-maintained summary of anything. This makes it fail.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn whitepaper() -> String {
    std::fs::read_to_string(root().join("WHITEPAPER.md")).expect("WHITEPAPER.md")
}

/// Every crate a status line names must exist, and every crate must be named somewhere.
///
/// A status line claiming a crate that is not there is the failure this catches directly. The
/// converse catches the quieter one: code that landed without the paper being told.
#[test]
fn every_crate_the_paper_names_exists_and_every_crate_is_named() {
    let text = whitepaper();
    let named: BTreeSet<String> = text
        .split('`')
        .filter(|t| t.starts_with("karst-") && !t.contains(' '))
        // `karst-mix::intersection` names a module in a crate, not a crate.
        .map(|t| t.split("::").next().unwrap().trim_end_matches('/').to_string())
        .collect();

    let on_disk: BTreeSet<String> = std::fs::read_dir(root().join("crates"))
        .expect("crates/")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("Cargo.toml").exists())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    for c in &named {
        assert!(on_disk.contains(c), "the paper names {c}, which does not exist");
    }

    // Harnesses and demos are tooling, not layers, so the paper owes them nothing.
    let tooling: BTreeSet<String> = ["karst-fuzz", "karst-demo", "karst-stack"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for c in on_disk.difference(&tooling) {
        assert!(named.contains(c), "{c} exists and the paper does not mention it");
    }
}

/// A layer the summary table calls unbuilt must not have a status line calling it built.
///
/// This is the exact shape of #102: `| L4 Mixing | specified, unbuilt | none |` sitting under a
/// layer body reading `Status: **built and running**`.
#[test]
fn the_summary_table_does_not_contradict_the_layer_it_summarises() {
    let text = whitepaper();
    let (body, table) = text.split_at(text.find("| Layer | Status | Crate |").expect("§8 table"));

    for line in table.lines().filter(|l| l.starts_with('|')) {
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() < 4 {
            continue;
        }
        let (layer, status) = (cols[1], cols[2]);
        if !status.contains("unbuilt") && !status.contains("sketched") {
            continue;
        }
        // The layer heading is "### L4 Mixing"; its section ends at the next heading.
        let Some(at) = body.find(&format!("### {layer}\n")) else {
            continue;
        };
        let rest = &body[at + 4..];
        let end = rest.find("\n### ").unwrap_or(rest.len());
        assert!(
            !rest[..end].contains("Status: **built"),
            "the table calls {layer} \"{status}\" and the layer says it is built"
        );
    }
}

/// The authorship-agency table must agree with the code that implements it.
///
/// It said `Autonomous` was verifiable "as to operator" while `karst-attest` returned false
/// from `is_verifiable` and documented that the signer can name anyone (#103). L15 curation
/// policy is built on this table, so a wrong cell is an admission rule.
#[test]
fn the_agency_table_agrees_with_karst_attest() {
    let text = whitepaper();
    let at = text.find("| Class | Meaning | Verifiable |").expect("agency table");
    let table = &text[at..text[at..].find("\n\n").map_or(text.len(), |e| at + e)];

    for line in table.lines().filter(|l| l.starts_with("| `")) {
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        let class = cols[1].trim_matches('`');
        let verifiable = !cols[3].contains("No");
        assert_eq!(
            verifiable,
            class == "Delegated",
            "the paper calls {class} \"{}\"; karst_attest::Agency::is_verifiable is true for \
             Delegated alone",
            cols[3]
        );
    }
}
