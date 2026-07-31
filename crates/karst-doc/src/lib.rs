//! KARST L10 Document.
//!
//! **There is no markup language here.** A document is not text with tags in it. It is
//! a merkle DAG of typed nodes, each one content-addressed and independently
//! referenceable.
//!
//! Markup is a 1990s answer to a 1980s problem: how do you get structure through a
//! byte-oriented pipe that only understands text. That constraint is gone, and
//! everything it forced on us is still here:
//!
//! | HTML's problem | What it causes | What we do |
//! |---|---|---|
//! | Text format with recovery-based parsing | Parser differentials, an enormous spec, XSS via markup confusion | One canonical binary encoding. Malformed input is rejected, never recovered. |
//! | Stringly typed | Everything is a string you hope somebody parses right; agents scrape and guess | Typed values. A price is `Money`, an instant is an `Instant`, a link is a `Cid`. |
//! | Structure entangled with presentation | You write `<div class>` for styling, not meaning | Zero presentation in the document. No classes, no styles, no hooks. |
//! | Only the document is addressable | Anchors are hand-placed strings that rot | Every node has a `Cid`. Any paragraph is quotable forever. |
//! | Links point at a location | Link rot | Links are content identifiers. They cannot rot. |
//! | Behaviour inline | One injected script owns the page | No behaviour in documents at all. See L9. |
//!
//! The vocabulary below is intentionally tiny and closed. A format one person can
//! implement completely in a season is a format that cannot become a two-engine
//! duopoly, which is error 03 defended structurally rather than by good intentions.

use std::collections::BTreeMap;

use karst_object::{Cid, Enc};

/// A typed scalar. This is what makes the document machine-readable without scraping:
/// an agent reads a value, it does not parse a string and hope.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Text(String),
    Int(i64),
    Bool(bool),
    /// Minor units plus an ISO currency code. Never a float, never a formatted string.
    Money { minor: i64, currency: String },
    /// Logical instant. Rendering into a human calendar is the client's business.
    Instant(u64),
    /// A reference to another node or object. Not a location.
    Ref(Cid),
}

impl Value {
    pub fn encode(&self, e: &mut Enc) {
        match self {
            Value::Text(s) => {
                e.u8(0).str(s);
            }
            Value::Int(v) => {
                e.u8(1).i64(*v);
            }
            Value::Bool(v) => {
                e.u8(2).bool(*v);
            }
            Value::Money { minor, currency } => {
                e.u8(3).i64(*minor).str(currency);
            }
            Value::Instant(v) => {
                e.u8(4).u64(*v);
            }
            Value::Ref(c) => {
                e.u8(5).cid(c);
            }
        }
    }

    /// Plain rendering, for a text client. Any other client may do something else
    /// entirely, which is the point of L12.
    pub fn render(&self) -> String {
        match self {
            Value::Text(s) => s.clone(),
            Value::Int(v) => v.to_string(),
            Value::Bool(v) => (if *v { "yes" } else { "no" }).to_string(),
            Value::Money { minor, currency } => {
                format!("{}.{:02} {}", minor / 100, (minor % 100).abs(), currency)
            }
            Value::Instant(v) => format!("t{v}"),
            Value::Ref(c) => c.short(),
        }
    }
}

/// Inline emphasis. Six options, closed set, no extension point. Presentation of these
/// is entirely the client's decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emphasis {
    Plain,
    Strong,
    Stress,
    Literal,
}

/// A run of text with one emphasis and an optional outbound reference.
///
/// Note that a link is a `Cid`, not a string. It identifies content, so it can be
/// resolved by anyone holding that content and it cannot break when a server moves.
#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    pub text: String,
    pub emphasis: Emphasis,
    pub link: Option<Cid>,
}

impl Run {
    pub fn plain(text: &str) -> Self {
        Run {
            text: text.to_string(),
            emphasis: Emphasis::Plain,
            link: None,
        }
    }
    pub fn strong(text: &str) -> Self {
        Run {
            text: text.to_string(),
            emphasis: Emphasis::Strong,
            link: None,
        }
    }
    pub fn link(text: &str, to: Cid) -> Self {
        Run {
            text: text.to_string(),
            emphasis: Emphasis::Plain,
            link: Some(to),
        }
    }

    pub fn encode(&self, e: &mut Enc) {
        e.str(&self.text).u8(self.emphasis as u8);
        match self.link {
            Some(c) => {
                e.u8(1).cid(&c);
            }
            None => {
                e.u8(0);
            }
        }
    }
}

/// The complete node vocabulary. Closed on purpose.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    /// A paragraph of styled runs.
    Prose { runs: Vec<Run> },
    /// A heading. `rank` is structural depth, not a font size.
    Heading { rank: u8, text: String },
    /// An ordered or unordered list of child nodes.
    List { ordered: bool, items: Vec<Cid> },
    /// Named typed fields. This is what an agent or a device reads.
    Record {
        schema: String,
        fields: BTreeMap<String, Value>,
    },
    /// A reference to media held as its own object or stream (L6, L7).
    Media {
        mime: String,
        source: Cid,
        description: String,
        duration_ms: Option<u64>,
    },
    /// A quotation. Holds a reference to the exact version quoted, never a copy, so it
    /// verifies against the source and cannot silently drift. This is L13 in the
    /// document model.
    Quote { source: Cid, comment: String },
    /// A container with an ordered list of children.
    Section { title: String, children: Vec<Cid> },
}

impl Node {
    /// Canonical encoding. Deterministic, so the same node always has the same name.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.str("karst.node.v1");
        match self {
            Node::Prose { runs } => {
                e.u8(0).u64(runs.len() as u64);
                for r in runs {
                    r.encode(&mut e);
                }
            }
            Node::Heading { rank, text } => {
                e.u8(1).u8(*rank).str(text);
            }
            Node::List { ordered, items } => {
                e.u8(2).bool(*ordered).u64(items.len() as u64);
                for c in items {
                    e.cid(c);
                }
            }
            Node::Record { schema, fields } => {
                // BTreeMap iterates in key order, so the encoding is canonical.
                e.u8(3).str(schema).u64(fields.len() as u64);
                for (k, v) in fields {
                    e.str(k);
                    v.encode(&mut e);
                }
            }
            Node::Media {
                mime,
                source,
                description,
                duration_ms,
            } => {
                e.u8(4).str(mime).cid(source).str(description);
                match duration_ms {
                    Some(d) => {
                        e.u8(1).u64(*d);
                    }
                    None => {
                        e.u8(0);
                    }
                }
            }
            Node::Quote { source, comment } => {
                e.u8(5).cid(source).str(comment);
            }
            Node::Section { title, children } => {
                e.u8(6).str(title).u64(children.len() as u64);
                for c in children {
                    e.cid(c);
                }
            }
        }
        e.finish()
    }

    /// A node's name is the hash of its content, so every paragraph in every document
    /// is permanently and independently quotable.
    pub fn cid(&self) -> Cid {
        Cid::of(&self.encode())
    }

    /// **Structural containment only.** The nodes that are part of this document.
    ///
    /// Kept strictly separate from [`Node::links`]. Conflating the two is how a quoted or
    /// linked third-party node ends up inside your document as far as a machine reader is
    /// concerned, while a human reader never sees it: the two views then describe
    /// different documents, which is an injection vector against anything at L11 that acts
    /// on what it reads.
    pub fn contained(&self) -> Vec<Cid> {
        match self {
            Node::List { items, .. } => items.clone(),
            Node::Section { children, .. } => children.clone(),
            _ => Vec::new(),
        }
    }

    /// **Outbound references to content that is not part of this document.** Quotations,
    /// media sources, inline links, and typed reference fields.
    ///
    /// Following these is always a deliberate act by the reader, never automatic.
    pub fn links(&self) -> Vec<Cid> {
        match self {
            Node::Prose { runs } => runs.iter().filter_map(|r| r.link).collect(),
            Node::Quote { source, .. } => vec![*source],
            Node::Media { source, .. } => vec![*source],
            Node::Record { fields, .. } => fields
                .values()
                .filter_map(|v| match v {
                    Value::Ref(c) => Some(*c),
                    _ => None,
                })
                .collect(),
            Node::Heading { .. } | Node::List { .. } | Node::Section { .. } => Vec::new(),
        }
    }

    /// Every outbound edge, containment and links together. This is the right set for
    /// building backlinks (L13), where the question is "who points at this at all", and
    /// the wrong set for deciding what a document contains.
    pub fn refs(&self) -> Vec<Cid> {
        let mut out = self.contained();
        out.extend(self.links());
        out
    }
}

/// A content-addressed store of nodes. A "document" is a root `Cid` plus whatever is
/// reachable from it, and any node may be shared by any number of documents.
#[derive(Default)]
pub struct Doc {
    nodes: BTreeMap<Cid, Node>,
}

impl Doc {
    pub fn new() -> Self {
        Doc::default()
    }

    /// Insert a node and return its name. Inserting the same node twice is a no-op that
    /// returns the same name, which is deduplication for free.
    pub fn add(&mut self, node: Node) -> Cid {
        let cid = node.cid();
        self.nodes.insert(cid, node);
        cid
    }

    pub fn get(&self, cid: &Cid) -> Option<&Node> {
        self.nodes.get(cid)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// One of many possible presentations. A text client renders like this; a screen
    /// reader, a watch, or a terminal may render the identical bytes completely
    /// differently, and none of them is privileged. The document has no opinion.
    pub fn render_text(&self, root: &Cid) -> String {
        let mut out = String::new();
        self.render_into(root, 0, &mut out);
        out
    }

    fn render_into(&self, cid: &Cid, depth: usize, out: &mut String) {
        let pad = "  ".repeat(depth);
        let Some(node) = self.nodes.get(cid) else {
            out.push_str(&format!("{pad}[missing {}]\n", cid.short()));
            return;
        };
        match node {
            Node::Heading { rank, text } => {
                out.push_str(&format!("{pad}{} {}\n", "#".repeat(*rank as usize), text));
            }
            Node::Prose { runs } => {
                let line: String = runs
                    .iter()
                    .map(|r| match r.emphasis {
                        Emphasis::Strong => format!("*{}*", r.text),
                        Emphasis::Stress => format!("_{}_", r.text),
                        Emphasis::Literal => format!("`{}`", r.text),
                        Emphasis::Plain => r.text.clone(),
                    })
                    .collect();
                out.push_str(&format!("{pad}{line}\n"));
            }
            Node::List { ordered, items } => {
                for (i, item) in items.iter().enumerate() {
                    let bullet = if *ordered {
                        format!("{}.", i + 1)
                    } else {
                        "-".to_string()
                    };
                    out.push_str(&format!("{pad}{bullet} "));
                    let mut sub = String::new();
                    self.render_into(item, 0, &mut sub);
                    out.push_str(sub.trim_start());
                }
            }
            Node::Record { schema, fields } => {
                out.push_str(&format!("{pad}[{schema}]\n"));
                for (k, v) in fields {
                    out.push_str(&format!("{pad}  {k}: {}\n", v.render()));
                }
            }
            Node::Media {
                mime,
                description,
                duration_ms,
                ..
            } => {
                let dur = duration_ms
                    .map(|d| format!(", {}s", d / 1000))
                    .unwrap_or_default();
                out.push_str(&format!("{pad}[{mime}{dur}] {description}\n"));
            }
            Node::Quote { source, comment } => {
                out.push_str(&format!("{pad}> quoting {}\n", source.short()));
                if !comment.is_empty() {
                    out.push_str(&format!("{pad}> {comment}\n"));
                }
            }
            Node::Section { title, children } => {
                if !title.is_empty() {
                    out.push_str(&format!("{pad}{title}\n"));
                }
                for c in children {
                    self.render_into(c, depth, out);
                }
            }
        }
    }

    /// What an agent or a device reads: typed records, no parsing, no scraping, no
    /// guessing which `<span>` held the price.
    ///
    /// Descends **containment only**, exactly as [`Doc::render_text`] does, so the machine
    /// view and the human view describe the same document. A quoted or linked third-party
    /// node cannot inject records here: following a link is a separate and deliberate act.
    /// See [`Doc::linked_records`].
    pub fn records(&self, root: &Cid) -> Vec<(String, BTreeMap<String, Value>)> {
        let mut out = Vec::new();
        self.collect_records(root, &mut out);
        out
    }

    fn collect_records(&self, cid: &Cid, out: &mut Vec<(String, BTreeMap<String, Value>)>) {
        let Some(node) = self.nodes.get(cid) else {
            return;
        };
        if let Node::Record { schema, fields } = node {
            out.push((schema.clone(), fields.clone()));
        }
        for r in node.contained() {
            if self.nodes.contains_key(&r) {
                self.collect_records(&r, out);
            }
        }
    }

    /// Records reachable by *following links out of* this document, tagged with the node
    /// that pointed at them.
    ///
    /// Separate from [`Doc::records`] on purpose. An agent that wants to act on quoted or
    /// linked material has to ask for it explicitly and knows it is looking at somebody
    /// else's content, rather than receiving it silently mixed in with the document's own.
    pub fn linked_records(
        &self,
        root: &Cid,
    ) -> Vec<(Cid, String, BTreeMap<String, Value>)> {
        let mut out = Vec::new();
        // Walk this document's containment, and at each node take one step outward.
        let mut frontier = vec![*root];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(cid) = frontier.pop() {
            if !seen.insert(cid) {
                continue;
            }
            let Some(node) = self.nodes.get(&cid) else {
                continue;
            };
            for target in node.links() {
                for (schema, fields) in self.records(&target) {
                    out.push((target, schema, fields));
                }
            }
            frontier.extend(node.contained());
        }
        out
    }

    /// Backlinks: given the nodes we hold, who points at `target`. This is the feature
    /// the web dropped in 1990, and the reason discussion boards need a host today.
    pub fn backlinks(&self, target: &Cid) -> Vec<Cid> {
        self.nodes
            .iter()
            .filter(|(_, n)| n.refs().contains(target))
            .map(|(c, _)| *c)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn money(minor: i64) -> Value {
        Value::Money {
            minor,
            currency: "EUR".into(),
        }
    }

    #[test]
    fn every_node_is_independently_addressable() {
        let a = Node::Prose {
            runs: vec![Run::plain("first paragraph")],
        };
        let b = Node::Prose {
            runs: vec![Run::plain("second paragraph")],
        };
        assert_ne!(a.cid(), b.cid());
        // and stable across constructions
        assert_eq!(a.cid(), a.clone().cid());
    }

    #[test]
    fn identical_nodes_deduplicate() {
        let mut doc = Doc::new();
        let a = doc.add(Node::Heading {
            rank: 1,
            text: "Notice".into(),
        });
        let b = doc.add(Node::Heading {
            rank: 1,
            text: "Notice".into(),
        });
        assert_eq!(a, b);
        assert_eq!(doc.len(), 1);
    }

    #[test]
    fn record_encoding_is_order_independent() {
        // Same fields inserted in different orders must produce the same name,
        // otherwise content addressing leaks insertion order.
        let mut f1 = BTreeMap::new();
        f1.insert("price".to_string(), money(4500));
        f1.insert("seats".to_string(), Value::Int(2));

        let mut f2 = BTreeMap::new();
        f2.insert("seats".to_string(), Value::Int(2));
        f2.insert("price".to_string(), money(4500));

        let n1 = Node::Record {
            schema: "booking".into(),
            fields: f1,
        };
        let n2 = Node::Record {
            schema: "booking".into(),
            fields: f2,
        };
        assert_eq!(n1.cid(), n2.cid());
    }

    #[test]
    fn one_document_serves_a_human_and_a_machine() {
        let mut doc = Doc::new();
        let mut fields = BTreeMap::new();
        fields.insert("price".to_string(), money(4500));
        fields.insert("duration_min".to_string(), Value::Int(30));

        let rec = doc.add(Node::Record {
            schema: "consultation".into(),
            fields,
        });
        let head = doc.add(Node::Heading {
            rank: 1,
            text: "Booking".into(),
        });
        let root = doc.add(Node::Section {
            title: String::new(),
            children: vec![head, rec],
        });

        // Human path
        let text = doc.render_text(&root);
        assert!(text.contains("Booking"));
        assert!(text.contains("45.00 EUR"));

        // Machine path, over the identical bytes, with no parsing
        let records = doc.records(&root);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "consultation");
        assert_eq!(records[0].1["price"], money(4500));
    }

    #[test]
    fn quotes_reference_an_exact_version_rather_than_copying() {
        let mut doc = Doc::new();
        let original = doc.add(Node::Prose {
            runs: vec![Run::plain("the original claim")],
        });
        let quote = doc.add(Node::Quote {
            source: original,
            comment: "this is wrong because".into(),
        });

        // The quote points at content, so the quoted text cannot be edited underneath it.
        assert_eq!(doc.get(&quote).unwrap().refs(), vec![original]);
        assert_eq!(doc.backlinks(&original), vec![quote]);
    }

    /// Regression for issue #33, reported by @matthiasantierens.
    ///
    /// `records()` used to follow every outbound edge including quotations, so quoting a
    /// hostile document silently pulled its typed records into yours. A human reading
    /// `render_text` never saw them. The two views disagreed about what the document said,
    /// and an L11 agent acting on the machine view would act on somebody else's content.
    #[test]
    fn a_quoted_document_cannot_inject_records_into_the_quoting_one() {
        let mut doc = Doc::new();

        // Somebody else's document, with a record in it.
        let mut hostile_fields = BTreeMap::new();
        hostile_fields.insert("price".to_string(), money(1));
        hostile_fields.insert("recipient".to_string(), Value::Text("attacker".into()));
        let hostile_rec = doc.add(Node::Record {
            schema: "payment".into(),
            fields: hostile_fields,
        });
        let hostile_root = doc.add(Node::Section {
            title: "their document".into(),
            children: vec![hostile_rec],
        });

        // Our document merely quotes it.
        let quote = doc.add(Node::Quote {
            source: hostile_root,
            comment: "as they claim".into(),
        });
        let ours = doc.add(Node::Section {
            title: String::new(),
            children: vec![quote],
        });

        // The machine view of our document contains none of their records.
        assert!(
            doc.records(&ours).is_empty(),
            "quoted records leaked into the quoting document"
        );

        // The human view does not render them either. The two views agree.
        let text = doc.render_text(&ours);
        assert!(!text.contains("attacker"));

        // Following the link is available, explicit, and attributed to its source.
        let linked = doc.linked_records(&ours);
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].0, hostile_root);
        assert_eq!(linked[0].1, "payment");
    }

    #[test]
    fn containment_and_links_are_distinct_edge_kinds() {
        let target = Cid::of(b"elsewhere");
        let sec = Node::Section {
            title: "s".into(),
            children: vec![target],
        };
        let q = Node::Quote {
            source: target,
            comment: String::new(),
        };

        assert_eq!(sec.contained(), vec![target]);
        assert!(sec.links().is_empty());

        assert!(q.contained().is_empty());
        assert_eq!(q.links(), vec![target]);

        // Backlinks still want both, because "who points at this at all" is a different
        // question from "what does this document contain".
        assert_eq!(q.refs(), vec![target]);
        assert_eq!(sec.refs(), vec![target]);
    }

    #[test]
    fn backlinks_exist_which_is_what_makes_threads_hostless() {
        let mut doc = Doc::new();
        let root = doc.add(Node::Prose {
            runs: vec![Run::plain("original post")],
        });
        let r1 = doc.add(Node::Quote {
            source: root,
            comment: "reply one".into(),
        });
        let r2 = doc.add(Node::Quote {
            source: root,
            comment: "reply two".into(),
        });

        let mut back = doc.backlinks(&root);
        back.sort();
        let mut expected = vec![r1, r2];
        expected.sort();
        assert_eq!(back, expected);
    }
}
