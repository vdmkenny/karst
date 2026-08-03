//! The paper's summary table must agree with the paper.
//!
//! §8 exists to tell a reader what is built. It went stale while the per-layer status lines
//! were kept current, so for a stretch the one section a reader consults for status said ten
//! of seventeen layers had no code, while the layers themselves said otherwise (#102).
//!
//! Drift is the default for a hand-maintained summary of anything. This makes it fail.

use std::collections::{BTreeMap, BTreeSet};
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

    let mut on_disk: BTreeSet<String> = std::fs::read_dir(root().join("crates"))
        .expect("crates/")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("Cargo.toml").exists())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    // Binaries are nameable too. `karst-net-demo` is a target inside `karst-net`, and the
    // paper referring to it by the name you type is right rather than wrong.
    let mut runnable: BTreeSet<String> = BTreeSet::new();
    for c in &on_disk {
        let manifest = std::fs::read_to_string(root().join("crates").join(c).join("Cargo.toml"))
            .unwrap_or_default();
        for line in manifest.lines() {
            if let Some(n) = line.strip_prefix("name = \"") {
                runnable.insert(n.trim_end_matches('"').to_string());
            }
        }
        let bins = root().join("crates").join(c).join("src/bin");
        if let Ok(entries) = std::fs::read_dir(&bins) {
            for e in entries.filter_map(|e| e.ok()) {
                if let Some(stem) = e.path().file_stem() {
                    runnable.insert(stem.to_string_lossy().to_string());
                }
            }
        }
    }
    on_disk.extend(runnable.iter().cloned());

    for c in &named {
        assert!(
            on_disk.contains(c),
            "the paper names {c}, which is neither a crate nor a binary"
        );
    }

    // Harnesses and demos are tooling, not layers, so the paper owes them nothing.
    let tooling: BTreeSet<String> = ["karst-fuzz", "karst-demo", "karst-stack"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    // Every crate must be named. Binaries are allowed to go unmentioned; they are how you
    // run the thing, not part of what it is.
    let crates_only: BTreeSet<String> = std::fs::read_dir(root().join("crates"))
        .expect("crates/")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("Cargo.toml").exists())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    for c in crates_only.difference(&tooling) {
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

/// The build-order table in §8.1 must match the crate manifests.
///
/// It exists so an implementer can derive what to build first, which makes it exactly the kind
/// of hand-maintained summary that goes stale silently. §8 already did that once (#102).
#[test]
fn the_dependency_table_matches_the_manifests() {
    let text = whitepaper();
    let at = text
        .find("| Layer | Crate | Depends on | Provides upward |")
        .expect("the 8.1 dependency table");
    let table = &text[at..at + text[at..].find("\n\n").unwrap_or(0)];

    // Layer label -> the crates that layer names.
    let mut crates_of: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut rows: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();

    for line in table.lines().filter(|l| l.starts_with("| L")) {
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() < 5 {
            continue;
        }
        let layer = cols[1].split_whitespace().next().unwrap_or("").to_string();
        let crates: Vec<String> = cols[2]
            .split('`')
            .filter(|t| t.starts_with("karst-"))
            .map(str::to_string)
            .collect();
        let deps: Vec<String> = cols[3]
            .split(&[',', ' '][..])
            .filter(|t| t.starts_with('L'))
            .map(str::to_string)
            .collect();
        crates_of.insert(layer.clone(), crates.clone());
        rows.push((layer, crates, deps));
    }
    assert!(rows.len() > 10, "parsed only {} rows", rows.len());

    for (layer, crates, deps) in &rows {
        // Everything the declared dependency layers make available, plus this layer's own.
        let mut allowed: BTreeSet<String> = crates.iter().cloned().collect();
        for d in deps {
            for c in crates_of.get(d).into_iter().flatten() {
                allowed.insert(c.clone());
            }
        }
        for c in crates {
            let manifest =
                std::fs::read_to_string(root().join("crates").join(c).join("Cargo.toml"))
                    .unwrap_or_else(|_| panic!("{layer} names {c}, which has no manifest"));
            for line in manifest.lines() {
                let Some(dep) = line.split(['.', ' ', '=']).next() else {
                    continue;
                };
                if !dep.starts_with("karst-") || dep == c {
                    continue;
                }
                assert!(
                    allowed.contains(dep),
                    "{layer} ({c}) depends on {dep}, which none of its declared \
                     dependency layers {deps:?} provide"
                );
            }
        }
    }
}

/// The prose count in 8.1 must match the graph it describes.
///
/// A number written into a sentence is the part of a document that drifts first, and this one
/// is load bearing: it is the evidence for the claim that the layer numbering is conceptual.
#[test]
fn the_foundational_layer_count_is_the_one_the_manifests_show() {
    let text = whitepaper();
    let at = text.find("of the remaining layers depend on L6 directly").expect("the claim");
    let before = &text[..at];
    let stated_total = before.split_whitespace().last().unwrap();
    let after = &text[at..];
    let stated_below = after
        .split("including ")
        .nth(1)
        .and_then(|t| t.split_whitespace().next())
        .expect("the second number");

    // Which layer each crate implements, for the crates the paper calls layers.
    let layer_of: BTreeMap<&str, u32> = [
        ("karst-path", 1),
        ("karst-mix", 4),
        ("karst-net", 4),
        ("karst-witness", 8),
        ("karst-cap", 9),
        ("karst-doc", 10),
        ("karst-afford", 11),
        ("karst-agency", 12),
        ("karst-attest", 13),
        ("karst-value", 14),
        ("karst-index", 15),
    ]
    .into_iter()
    .collect();

    let mut layers: BTreeSet<u32> = BTreeSet::new();
    for (c, n) in &layer_of {
        let manifest =
            std::fs::read_to_string(root().join("crates").join(c).join("Cargo.toml")).unwrap();
        if manifest.lines().any(|l| l.starts_with("karst-object")) {
            layers.insert(*n);
        }
    }
    let below = layers.iter().filter(|n| **n < 6).count();

    let word = |n: usize| match n {
        1 => "One",
        2 => "Two",
        3 => "Three",
        4 => "four",
        9 => "Nine",
        10 => "Ten",
        _ => "?",
    };
    assert_eq!(
        stated_total,
        word(layers.len()),
        "the paper says {stated_total} layers depend on L6; the manifests say {}",
        layers.len()
    );
    assert_eq!(
        stated_below,
        match below {
            1 => "one",
            2 => "two",
            3 => "three",
            _ => "?",
        },
        "the paper says {stated_below} are numbered below L6; the manifests say {below}"
    );
}
