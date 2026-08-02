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

use karst_object::{Cid, Dec, DecodeError, Enc};

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

    pub fn decode(d: &mut Dec<'_>) -> Result<Value, DecodeError> {
        match d.u8()? {
            0 => Ok(Value::Text(d.str()?)),
            1 => Ok(Value::Int(d.i64()?)),
            2 => Ok(Value::Bool(d.bool()?)),
            3 => Ok(Value::Money {
                minor: d.i64()?,
                currency: d.str()?,
            }),
            4 => Ok(Value::Instant(d.u64()?)),
            5 => Ok(Value::Ref(d.cid()?)),
            t => Err(DecodeError::UnknownTag(t)),
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
                // Formatting from the signed value loses the sign entirely between -100 and
                // 0: the division truncates to zero and `.abs()` strips the remainder, so
                // minus fifty cents printed as a credit of fifty.
                let m = minor.unsigned_abs();
                let sign = if *minor < 0 { "-" } else { "" };
                format!("{sign}{}.{:02} {}", m / 100, m % 100, currency)
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

impl Emphasis {
    /// Reject any tag outside the closed set. A permissive mapping would make several byte
    /// strings decode to the same node, which is the parser differential this format exists
    /// to avoid.
    pub fn from_tag(t: u8) -> Result<Emphasis, DecodeError> {
        match t {
            0 => Ok(Emphasis::Plain),
            1 => Ok(Emphasis::Strong),
            2 => Ok(Emphasis::Stress),
            3 => Ok(Emphasis::Literal),
            t => Err(DecodeError::UnknownTag(t)),
        }
    }
}

/// A run of text with one emphasis and an optional outbound reference.
///
/// Note that a link is a `Cid`, not a string. It identifies content, so it can be
/// resolved by anyone holding that content and it cannot break when a server moves.
/// What a link means.
///
/// A URL names a location and resolves to whatever is there now. That single behaviour produces
/// both link rot and silent substitution, because the reference cannot say whether it meant
/// *these bytes* or *whatever this becomes*. It always means the second, and a reader cannot
/// tell which the author intended.
///
/// Both exist here and they are different types, so an author picks and a reader is told.
///
/// | | Resolves to | Verifies | Changes under the reader |
/// |---|---|---|---|
/// | `Pinned` | exact bytes | by construction | never |
/// | `Tracking` | current head of the chain | against the lineage | yes, and visibly |
///
/// `Pinned` is what a citation means. `Tracking` is what a menu entry means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Link {
    /// These bytes, forever.
    Pinned(Cid),
    /// Whatever supersedes this, resolved forward from what the author saw.
    ///
    /// Carrying what the author saw rather than the start of the chain costs the same 66 bytes
    /// and buys two things. A reader holding nothing newer degrades to exactly the pinned
    /// behaviour instead of failing, and a reader holding something newer can **diff what the
    /// author linked against what they are being shown**, which detects substitution rather
    /// than merely permitting it.
    Tracking { seen: Cid },
}

impl Link {
    /// What to show when nothing newer is held. Always safe, never wrong, possibly stale.
    pub fn fallback(&self) -> Cid {
        match self {
            Link::Pinned(c) => *c,
            Link::Tracking { seen } => *seen,
        }
    }

    pub fn encode(&self, e: &mut Enc) {
        match self {
            Link::Pinned(c) => {
                e.u8(1).cid(c);
            }
            Link::Tracking { seen } => {
                e.u8(2).cid(seen);
            }
        }
    }

    pub fn decode_tagged(d: &mut Dec<'_>, tag: u8) -> Result<Link, DecodeError> {
        match tag {
            1 => Ok(Link::Pinned(d.cid()?)),
            2 => Ok(Link::Tracking { seen: d.cid()? }),
            t => Err(DecodeError::UnknownTag(t)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    pub text: String,
    pub emphasis: Emphasis,
    pub link: Option<Link>,
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
    /// A citation: these bytes, whatever happens later.
    pub fn link(text: &str, to: Cid) -> Self {
        Run {
            text: text.to_string(),
            emphasis: Emphasis::Plain,
            link: Some(Link::Pinned(to)),
        }
    }

    /// A reference that follows its target forward.
    pub fn tracking_link(text: &str, seen: Cid) -> Self {
        Run {
            text: text.to_string(),
            emphasis: Emphasis::Plain,
            link: Some(Link::Tracking { seen }),
        }
    }

    pub fn encode(&self, e: &mut Enc) {
        e.str(&self.text).u8(self.emphasis as u8);
        match &self.link {
            Some(l) => l.encode(e),
            None => {
                e.u8(0);
            }
        }
    }

    pub fn decode(d: &mut Dec<'_>) -> Result<Run, DecodeError> {
        let text = d.str()?;
        let emphasis = Emphasis::from_tag(d.u8()?)?;
        let link = match d.u8()? {
            0 => None,
            t => Some(Link::decode_tagged(d, t)?),
        };
        Ok(Run {
            text,
            emphasis,
            link,
        })
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

    /// Upper bound on any repeated element, so an attacker-supplied count cannot make a
    /// decoder allocate. The length prefix is read before the elements exist, so without a
    /// cap a four byte count reserves gigabytes.
    pub const MAX_ELEMENTS: usize = 4096;

    /// Decode a node, rejecting anything that is not the exact canonical encoding.
    ///
    /// Three rules make this stricter than "parses successfully", and all three exist to
    /// guarantee **one byte string per value**:
    ///
    /// 1. Unknown tags are refused rather than skipped, for node kinds, value kinds,
    ///    emphasis, and option discriminants.
    /// 2. `Record` keys must be **strictly increasing**. A permissive decoder would accept
    ///    reordered or duplicated keys and build the same `BTreeMap`, so several byte strings
    ///    would name one value and the content address would stop being a function of it.
    /// 3. Trailing bytes are an error, enforced by the caller through [`Dec::end`].
    ///
    /// Together these mean `decode(encode(v)) == v` and `encode(decode(b)) == b`, which is
    /// what makes a parser differential impossible rather than merely unlikely.
    pub fn decode(d: &mut Dec<'_>) -> Result<Node, DecodeError> {
        if d.str()? != "karst.node.v1" {
            return Err(DecodeError::UnknownTag(0));
        }

        fn count(d: &mut Dec<'_>) -> Result<usize, DecodeError> {
            let n = d.u64()?;
            if n > Node::MAX_ELEMENTS as u64 {
                return Err(DecodeError::Truncated);
            }
            Ok(n as usize)
        }

        match d.u8()? {
            0 => {
                let n = count(d)?;
                let mut runs = Vec::with_capacity(n);
                for _ in 0..n {
                    runs.push(Run::decode(d)?);
                }
                Ok(Node::Prose { runs })
            }
            1 => Ok(Node::Heading {
                rank: d.u8()?,
                text: d.str()?,
            }),
            2 => {
                let ordered = d.bool()?;
                let n = count(d)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(d.cid()?);
                }
                Ok(Node::List { ordered, items })
            }
            3 => {
                let schema = d.str()?;
                let n = count(d)?;
                let mut fields = BTreeMap::new();
                let mut previous: Option<String> = None;
                for _ in 0..n {
                    let k = d.str()?;
                    // Strictly increasing. Equal or descending keys would let two encodings
                    // produce one map.
                    if let Some(prev) = &previous {
                        if &k <= prev {
                            return Err(DecodeError::TrailingBytes);
                        }
                    }
                    previous = Some(k.clone());
                    fields.insert(k, Value::decode(d)?);
                }
                Ok(Node::Record { schema, fields })
            }
            4 => {
                let mime = d.str()?;
                let source = d.cid()?;
                let description = d.str()?;
                let duration_ms = match d.u8()? {
                    0 => None,
                    1 => Some(d.u64()?),
                    t => return Err(DecodeError::UnknownTag(t)),
                };
                Ok(Node::Media {
                    mime,
                    source,
                    description,
                    duration_ms,
                })
            }
            5 => Ok(Node::Quote {
                source: d.cid()?,
                comment: d.str()?,
            }),
            6 => {
                let title = d.str()?;
                let n = count(d)?;
                let mut children = Vec::with_capacity(n);
                for _ in 0..n {
                    children.push(d.cid()?);
                }
                Ok(Node::Section { title, children })
            }
            t => Err(DecodeError::UnknownTag(t)),
        }
    }

    /// Decode from a complete byte string, rejecting trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Node, DecodeError> {
        let mut d = Dec::new(bytes);
        let node = Node::decode(&mut d)?;
        d.end()?;
        Ok(node)
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
            Node::Prose { runs } => runs.iter().filter_map(|r| r.link.map(|l| l.fallback())).collect(),
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

/// A bound on how much work an untrusted document may cost the reader.
///
/// Containment is a DAG, not a tree: nothing stops a `Section` listing the same child twice,
/// and nothing should, because including one node in two places is a legitimate thing to do
/// with content-addressed nodes. But a chain of sixty-four such nodes doubles the work per
/// level, so roughly six kilobytes of correctly signed, correctly verified objects cost 2^64
/// visits. A cycle detector does not help here; the hostile shape has no cycle.
///
/// So the bound is on total visits rather than on repetition, plus a depth cap so a long
/// linear chain cannot overflow the stack instead. Honest documents are nowhere near either.
/// A document that exceeds them is truncated visibly, because a reader silently shown less
/// than a publisher wrote is worse off than one told the document is hostile.
struct Budget {
    visits: usize,
    depth: usize,
    /// Bytes committed to the caller's output.
    ///
    /// The visit cap alone bounds how many nodes are entered and says nothing about how much
    /// each one appends. A doubling chain re-renders the same node up to `MAX_VISITS` times,
    /// so a document of a hundred kilobytes with a fat leaf produced a multi-gigabyte string
    /// while staying inside every other bound. What an adversary is buying is the reader's
    /// memory, so that is what has to be metered.
    bytes: usize,
    exhausted: bool,
}

impl Budget {
    /// A rendered document larger than this is past any screen and any reader's patience.
    const MAX_VISITS: usize = 1 << 16;
    /// Deeper than this is a chain, not a structure. Also keeps the recursion off the stack
    /// limit: the walk is depth-first and native frames are not free.
    const MAX_DEPTH: usize = 64;
    /// Output one walk may produce. Larger than any document a person reads, far smaller
    /// than what a doubling chain will ask for.
    const MAX_BYTES: usize = 4 << 20;

    fn new() -> Self {
        Budget {
            visits: 0,
            depth: 0,
            bytes: 0,
            exhausted: false,
        }
    }

    /// Charge output. Returns false once the walk has produced all it is going to.
    fn spend(&mut self, n: usize) -> bool {
        if self.bytes.saturating_add(n) > Self::MAX_BYTES {
            self.exhausted = true;
            return false;
        }
        self.bytes += n;
        true
    }

    /// Enter one node. The caller must [`Budget::leave`] on every path out.
    fn enter(&mut self) -> bool {
        if self.depth >= Self::MAX_DEPTH
            || self.visits >= Self::MAX_VISITS
            || self.bytes >= Self::MAX_BYTES
        {
            self.exhausted = true;
            return false;
        }
        self.visits += 1;
        self.depth += 1;
        true
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }
}

/// What a machine reader gets, and whether it got all of it.
///
/// `records()` used to return a bare vector. A document nested past `MAX_DEPTH` returned an
/// empty one, byte-identical to the answer for a document that genuinely holds no records, so
/// an agent could not tell "nothing here" from "I stopped looking". An agent acting on a
/// silently truncated record set is the failure this type exists to prevent.
#[derive(Debug, Clone, PartialEq)]
pub struct Records {
    pub items: Vec<(String, BTreeMap<String, Value>)>,
    /// The walk hit a bound. What is here is a prefix, not the whole.
    pub truncated: bool,
}

impl Records {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The records, on the caller's explicit acknowledgement that a prefix will do.
    pub fn partial(self) -> Vec<(String, BTreeMap<String, Value>)> {
        self.items
    }

    /// The records only if they are all of them.
    pub fn complete(self) -> Option<Vec<(String, BTreeMap<String, Value>)>> {
        (!self.truncated).then_some(self.items)
    }
}

/// Records reached by following links, and whether all of them were reached.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkedRecords {
    pub items: Vec<(Cid, String, BTreeMap<String, Value>)>,
    pub truncated: bool,
}

impl LinkedRecords {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Append to the output, charging the budget.
///
/// Every write to a caller's buffer goes through here. A walk that appends anywhere else is
/// a walk an adversary can size, which is the whole defect this exists to close.
fn emit(out: &mut String, budget: &mut Budget, text: &str) {
    if budget.spend(text.len()) {
        out.push_str(text);
    }
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

    /// Every node this document holds.
    ///
    /// Deterministic order, because a document published twice must produce the same set of
    /// objects in the same sequence or it would look like a different document to anyone
    /// diffing what a publisher emitted.
    pub fn cids(&self) -> Vec<Cid> {
        self.nodes.keys().copied().collect()
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
        let mut budget = Budget::new();
        self.render_into(root, 0, &mut out, &mut budget);
        if budget.exhausted {
            out.push_str("[truncated: document exceeds the rendering budget]\n");
        }
        out
    }

    fn render_into(&self, cid: &Cid, depth: usize, out: &mut String, budget: &mut Budget) {
        if !budget.enter() {
            return;
        }
        self.render_node(cid, depth, out, budget);
        budget.leave();
    }

    fn render_node(&self, cid: &Cid, depth: usize, out: &mut String, budget: &mut Budget) {
        let pad = "  ".repeat(depth);
        let Some(node) = self.nodes.get(cid) else {
            emit(out, budget, &format!("{pad}[missing {}]\n", cid.short()));
            return;
        };
        match node {
            Node::Heading { rank, text } => {
                emit(out, budget, &format!("{pad}{} {}\n", "#".repeat(*rank as usize), text));
            }
            Node::Prose { runs } => {
                let line: String = runs
                    .iter()
                    .map(|r| {
                        let body = match r.emphasis {
                            Emphasis::Strong => format!("*{}*", r.text),
                            Emphasis::Stress => format!("_{}_", r.text),
                            Emphasis::Literal => format!("`{}`", r.text),
                            Emphasis::Plain => r.text.clone(),
                        };
                        // The kind of link is rendered, not just the target. A reader who
                        // cannot tell a citation from a reference that follows its target is
                        // in exactly the position a URL leaves them in.
                        match &r.link {
                            None => body,
                            Some(Link::Pinned(c)) => format!("{body}[pinned {}]", c.short()),
                            Some(Link::Tracking { seen }) => {
                                format!("{body}[tracking {}]", seen.short())
                            }
                        }
                    })
                    .collect();
                emit(out, budget, &format!("{pad}{line}\n"));
            }
            Node::List { ordered, items } => {
                for (i, item) in items.iter().enumerate() {
                    let bullet = if *ordered {
                        format!("{}.", i + 1)
                    } else {
                        "-".to_string()
                    };
                    emit(out, budget, &format!("{pad}{bullet} "));
                    let mut sub = String::new();
                    self.render_into(item, depth + 1, &mut sub, budget);
                    emit(out, budget, sub.trim_start());
                }
            }
            Node::Record { schema, fields } => {
                emit(out, budget, &format!("{pad}[{schema}]\n"));
                for (k, v) in fields {
                    emit(out, budget, &format!("{pad}  {k}: {}\n", v.render()));
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
                emit(out, budget, &format!("{pad}[{mime}{dur}] {description}\n"));
            }
            Node::Quote { source, comment } => {
                emit(out, budget, &format!("{pad}> quoting {}\n", source.short()));
                if !comment.is_empty() {
                    emit(out, budget, &format!("{pad}> {comment}\n"));
                }
            }
            Node::Section { title, children } => {
                if !title.is_empty() {
                    emit(out, budget, &format!("{pad}{title}\n"));
                }
                for c in children {
                    self.render_into(c, depth + 1, out, budget);
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
    pub fn records(&self, root: &Cid) -> Records {
        let mut items = Vec::new();
        let mut budget = Budget::new();
        self.collect_records(root, &mut items, &mut budget);
        Records {
            items,
            truncated: budget.exhausted,
        }
    }

    fn collect_records(
        &self,
        cid: &Cid,
        out: &mut Vec<(String, BTreeMap<String, Value>)>,
        budget: &mut Budget,
    ) {
        if !budget.enter() {
            return;
        }
        if let Some(node) = self.nodes.get(cid) {
            if let Node::Record { schema, fields } = node {
                let size = schema.len()
                    + fields
                        .iter()
                        .map(|(k, v)| k.len() + v.render().len())
                        .sum::<usize>();
                if budget.spend(size) {
                    out.push((schema.clone(), fields.clone()));
                }
            }
            // No `contains_key` guard. The human walk spends a visit on an unresolvable
            // child and prints `[missing]`; if this one skipped those, the two walks would
            // exhaust at different points on the same document and an agent would see
            // records the reader never sees.
            for r in node.contained() {
                self.collect_records(&r, out, budget);
            }
        }
        budget.leave();
    }

    /// Records reachable by *following links out of* this document, tagged with the node
    /// that pointed at them.
    ///
    /// Separate from [`Doc::records`] on purpose. An agent that wants to act on quoted or
    /// linked material has to ask for it explicitly and knows it is looking at somebody
    /// else's content, rather than receiving it silently mixed in with the document's own.
    /// One budget for the whole call, not one per edge.
    ///
    /// This used to call `records()` per link target, and each of those built a fresh budget.
    /// The `seen` set bounds distinct nodes and not link edges, so a single `Prose` node
    /// carrying `MAX_ELEMENTS` runs bought that many full allowances: the ceiling was
    /// edges times `MAX_VISITS`, which is not a ceiling. A bound that resets is not a bound.
    pub fn linked_records(&self, root: &Cid) -> LinkedRecords {
        let mut items = Vec::new();
        let mut budget = Budget::new();
        // Walk this document's containment, and at each node take one step outward.
        let mut frontier = vec![*root];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(cid) = frontier.pop() {
            if !seen.insert(cid) {
                continue;
            }
            if budget.exhausted {
                break;
            }
            let Some(node) = self.nodes.get(&cid) else {
                continue;
            };
            for target in node.links() {
                let mut found = Vec::new();
                self.collect_records(&target, &mut found, &mut budget);
                for (schema, fields) in found {
                    items.push((target, schema, fields));
                }
            }
            frontier.extend(node.contained());
        }
        LinkedRecords {
            items,
            truncated: budget.exhausted,
        }
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

    /// A document whose containment DAG doubles at every level.
    ///
    /// Each section lists the same child twice. Nothing rejects that and nothing should: one
    /// node in two places is a legitimate use of content addressing. But `k` levels means
    /// `2^k` visits for a walk that does not count, so the objects stay tiny while the work
    /// does not. Returns the root.
    fn doubling_chain(doc: &mut Doc, levels: usize) -> Cid {
        let mut cur = doc.add(Node::Prose {
            runs: vec![Run::plain("leaf")],
        });
        for i in 0..levels {
            cur = doc.add(Node::Section {
                title: format!("level {i}"),
                children: vec![cur, cur],
            });
        }
        cur
    }

    /// A hostile document costs the reader a bounded amount and says so.
    ///
    /// Sixty-four doubling levels is roughly six kilobytes of correctly signed, correctly
    /// verified nodes and 2^64 visits for an uncounted walk. Both entry points are read paths
    /// for material chosen by whoever the reader chose to read, and `records` is what an agent
    /// calls, so an agent is hit too.
    #[test]
    fn a_doubling_document_does_not_cost_the_reader_the_world() {
        let mut doc = Doc::new();
        let root = doubling_chain(&mut doc, 64);

        let text = doc.render_text(&root);
        assert!(
            text.contains("[truncated"),
            "a truncated render must say so rather than look complete"
        );
        assert!(
            text.len() <= Budget::MAX_BYTES + 128,
            "render produced {} bytes against a {} byte budget",
            text.len(),
            Budget::MAX_BYTES
        );
        let recs = doc.records(&root);
        assert!(recs.truncated, "a truncated record set must say so");
    }

    /// A visit cap does not bound output, and output is what the reader pays in.
    ///
    /// The doubling chain re-renders the same leaf up to `MAX_VISITS` times. With a fat leaf
    /// that is a multi-gigabyte string from a document of a hundred kilobytes, every other
    /// bound satisfied. What an adversary buys is the reader's memory, so memory is metered.
    #[test]
    fn a_fat_leaf_in_a_doubling_chain_does_not_buy_gigabytes() {
        let mut doc = Doc::new();
        let fat = doc.add(Node::Prose {
            runs: vec![Run::plain(&"x".repeat(60_000))],
        });
        let mut cur = fat;
        for i in 0..40 {
            cur = doc.add(Node::Section {
                title: format!("{i}"),
                children: vec![cur, cur],
            });
        }
        let text = doc.render_text(&cur);
        assert!(
            text.len() <= Budget::MAX_BYTES + 128,
            "{} bytes from a document whose only text is 60 kB",
            text.len()
        );
        assert!(text.contains("[truncated"));
    }

    /// Both walks must stop on the same document, or an agent acts on what nobody can read.
    ///
    /// The human walk spends a visit on an unresolvable child and prints `[missing]`; the
    /// machine walk used to skip those without charge. The two then exhausted at different
    /// points on the same document, contradicting the promise that `records` descends
    /// containment exactly as `render_text` does.
    ///
    /// The document is built so that **the only thing that can exhaust either walk is the
    /// charge for an unresolvable child**: no records, so nothing spends record bytes, and
    /// the rendered text stays well inside the byte budget, so visits are what bind. An
    /// earlier version of this test nested the missing children under a doubling chain, and
    /// passed with the defect restored because both walks stopped for unrelated reasons.
    #[test]
    fn the_machine_view_and_the_human_view_stop_together() {
        let mut doc = Doc::new();
        let mut sections = Vec::new();
        for s in 0..20u32 {
            let absent: Vec<Cid> = (0..4096u32)
                .map(|i| Cid::of(&(s * 10_000 + i).to_le_bytes()))
                .collect();
            sections.push(doc.add(Node::Section {
                title: String::new(),
                children: absent,
            }));
        }
        let root = doc.add(Node::Section {
            title: String::new(),
            children: sections,
        });

        let text = doc.render_text(&root);
        assert!(
            text.len() < Budget::MAX_BYTES,
            "the byte budget bound first, so this tests the wrong thing"
        );
        assert!(
            text.contains("[truncated"),
            "the human walk should have run out of visits"
        );
        assert!(
            doc.records(&root).truncated,
            "the human walk stopped and the machine walk kept going on the same document"
        );
    }

    /// A bound that resets per edge is not a bound.
    ///
    /// `linked_records` built a fresh budget for every link target, and one `Prose` node may
    /// carry thousands of runs each with its own link, so the real ceiling was edges times
    /// `MAX_VISITS`.
    #[test]
    fn following_links_shares_one_budget_across_every_edge() {
        let mut doc = Doc::new();
        let rec = doc.add(Node::Record {
            schema: "payment".into(),
            fields: [("amount".to_string(), money(100))].into_iter().collect(),
        });
        let mut deep = rec;
        for i in 0..30 {
            deep = doc.add(Node::Section {
                title: format!("{i}"),
                children: vec![deep, deep],
            });
        }
        let runs: Vec<Run> = (0..512).map(|_| Run::tracking_link("see", deep)).collect();
        let root = doc.add(Node::Prose { runs });

        let start = std::time::Instant::now();
        let linked = doc.linked_records(&root);
        assert!(
            start.elapsed().as_secs() < 10,
            "took {:?}",
            start.elapsed()
        );
        assert!(linked.truncated, "the walk stopped and did not say so");
    }

    /// An agent must be able to tell "nothing here" from "I stopped looking".
    #[test]
    fn a_truncated_record_set_is_distinguishable_from_an_empty_one() {
        let mut doc = Doc::new();
        let empty = doc.add(Node::Prose {
            runs: vec![Run::plain("no records here")],
        });
        let honest = doc.records(&empty);
        assert!(honest.is_empty() && !honest.truncated);
        assert!(honest.clone().complete().is_some());

        // The same empty answer, for the opposite reason.
        let mut cur = doc.add(Node::Record {
            schema: "buried".into(),
            fields: BTreeMap::new(),
        });
        for i in 0..(Budget::MAX_DEPTH + 8) {
            cur = doc.add(Node::Section {
                title: format!("{i}"),
                children: vec![cur],
            });
        }
        let cut = doc.records(&cur);
        assert!(cut.is_empty(), "the record should be out of reach");
        assert!(cut.truncated, "and the caller must be told why");
        assert!(cut.complete().is_none());
    }

    /// Minus fifty cents is not a credit of fifty cents.
    #[test]
    fn a_small_negative_amount_keeps_its_sign() {
        assert_eq!(money(-50).render(), "-0.50 EUR");
        assert_eq!(money(-5).render(), "-0.05 EUR");
        assert_eq!(money(-99).render(), "-0.99 EUR");
        assert_eq!(money(-4500).render(), "-45.00 EUR");
        assert_eq!(money(0).render(), "0.00 EUR");
        assert_eq!(money(50).render(), "0.50 EUR");
        // The one value whose magnitude does not fit back into i64.
        assert!(money(i64::MIN).render().starts_with('-'));
    }

    /// Nesting must be visible, or the rendered structure is not the document's structure.
    #[test]
    fn a_nested_paragraph_renders_further_right_than_its_parent() {
        let mut doc = Doc::new();
        let p = doc.add(Node::Prose {
            runs: vec![Run::plain("innermost")],
        });
        let mut cur = p;
        for i in 0..3 {
            cur = doc.add(Node::Section {
                title: format!("level {i}"),
                children: vec![cur],
            });
        }
        let text = doc.render_text(&cur);
        let indent = |needle: &str| {
            text.lines()
                .find(|l| l.trim() == needle)
                .map(|l| l.len() - l.trim_start().len())
                .unwrap_or_else(|| panic!("{needle} not rendered"))
        };
        assert!(
            indent("innermost") > indent("level 2"),
            "nesting rendered flat:\n{text}"
        );
    }

    /// A chain long enough to overflow the stack is refused rather than survived by luck.
    #[test]
    fn a_deep_chain_does_not_overflow_the_stack() {
        let mut doc = Doc::new();
        let mut cur = doc.add(Node::Prose {
            runs: vec![Run::plain("leaf")],
        });
        for i in 0..50_000 {
            cur = doc.add(Node::Section {
                title: format!("{i}"),
                children: vec![cur],
            });
        }
        assert!(doc.render_text(&cur).contains("[truncated"));
        assert!(doc.records(&cur).is_empty());
    }

    /// The bound must not truncate anything a publisher would actually write.
    #[test]
    fn an_ordinary_document_is_not_truncated() {
        let mut doc = Doc::new();
        let mut sections = Vec::new();
        for i in 0..200 {
            let p = doc.add(Node::Prose {
                runs: vec![Run::plain(&format!("paragraph {i}"))],
            });
            sections.push(doc.add(Node::Section {
                title: format!("section {i}"),
                children: vec![p],
            }));
        }
        let root = doc.add(Node::Section {
            title: "book".into(),
            children: sections,
        });
        let text = doc.render_text(&root);
        assert!(!text.contains("[truncated"));
        assert!(text.contains("paragraph 199"));
    }

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
        assert_eq!(records.items.len(), 1);
        assert_eq!(records.items[0].0, "consultation");
        assert_eq!(records.items[0].1["price"], money(4500));
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
        assert_eq!(linked.items.len(), 1);
        assert_eq!(linked.items[0].0, hostile_root);
        assert_eq!(linked.items[0].1, "payment");
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

/// Following a link forward.
pub mod resolve {
    //! What a `Tracking` link resolves to, and what it refuses to resolve to.
    //!
    //! Resolution walks forward from what the author saw, through `supersedes` edges the
    //! lineage has verified. Three things make this different from following a URL.
    //!
    //! A reader holding nothing newer gets **exactly what the author saw**, rather than an
    //! error or a guess. Staleness degrades to the pinned behaviour.
    //!
    //! A reader holding something newer is told **how far it moved**, so the difference between
    //! the author's reference and the reader's view is visible rather than assumed away.
    //!
    //! A chain that **forks** is refused rather than resolved. Two valid successors mean the
    //! publisher signed two conflicting continuations, and any rule for picking one lets that
    //! publisher show different readers different content while both verify. Refusing is the
    //! only answer that does not quietly pick a side.

    use karst_object::{Cid, Lineage};

    use super::Link;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Resolved {
        /// A pinned link. Nothing to follow.
        Pinned(Cid),
        /// Tracking, and nothing has superseded what the author saw.
        Current(Cid),
        /// Tracking, and the chain has moved on.
        Superseded {
            head: Cid,
            /// What the author saw, kept so a reader can compare.
            seen: Cid,
            steps: usize,
        },
        /// The chain forks. Resolution refuses rather than choosing.
        Forked { at: Cid, candidates: Vec<Cid> },
        /// Tracking a target the reader holds nothing about, so the author's view stands.
        Unknown(Cid),
    }

    impl Resolved {
        /// The content to show. `None` only when the chain forks, which needs a reader's
        /// decision rather than a default.
        pub fn target(&self) -> Option<Cid> {
            match self {
                Resolved::Pinned(c) | Resolved::Current(c) | Resolved::Unknown(c) => Some(*c),
                Resolved::Superseded { head, .. } => Some(*head),
                Resolved::Forked { .. } => None,
            }
        }

        /// Whether a reader is seeing something other than what the author linked.
        pub fn moved(&self) -> bool {
            matches!(self, Resolved::Superseded { .. } | Resolved::Forked { .. })
        }
    }

    /// The most steps resolution will walk.
    ///
    /// A chain is publisher-controlled, so an unbounded walk is an unbounded amount of a
    /// reader's time bought by whoever publishes the chain.
    pub const MAX_STEPS: usize = 4096;

    pub fn resolve(link: &Link, lineage: &Lineage) -> Resolved {
        let seen = match link {
            Link::Pinned(c) => return Resolved::Pinned(*c),
            Link::Tracking { seen } => *seen,
        };

        let mut cursor = seen;
        let mut steps = 0;
        loop {
            let next = lineage.successors(&cursor);
            match next.len() {
                0 => break,
                1 => {
                    cursor = next[0];
                    steps += 1;
                    if steps >= MAX_STEPS {
                        break;
                    }
                }
                _ => {
                    return Resolved::Forked {
                        at: cursor,
                        candidates: next,
                    }
                }
            }
        }

        if steps > 0 {
            Resolved::Superseded {
                head: cursor,
                seen,
                steps,
            }
        } else if lineage.successors(&seen).is_empty() && lineage_holds(lineage, &seen) {
            Resolved::Current(seen)
        } else {
            Resolved::Unknown(seen)
        }
    }

    fn lineage_holds(lineage: &Lineage, cid: &Cid) -> bool {
        lineage.get(cid).is_some()
    }
}

#[cfg(test)]
mod link_tests {
    use super::resolve::{resolve, Resolved, MAX_STEPS};
    use super::*;
    use karst_id::Identity;
    use karst_object::{Lineage, Object};

    /// Publish a chain of `n` versions by one author, returning their cids in order.
    fn chain(id: &Identity, n: usize, lineage: &mut Lineage) -> Vec<Cid> {
        let mut cids = Vec::new();
        let mut prev = None;
        for i in 0..n {
            let o = Object::create(id, "page", i as u64, format!("v{i}").into_bytes(), prev);
            let c = lineage.insert(o).unwrap();
            cids.push(c);
            prev = Some(c);
        }
        cids
    }

    /// A pinned link never moves, whatever the publisher does afterwards.
    ///
    /// This is what a citation needs and what a URL cannot promise.
    #[test]
    fn a_pinned_link_does_not_move_when_the_target_is_superseded() {
        let id = Identity::from_seed([1u8; 32]);
        let mut lin = Lineage::new();
        let cids = chain(&id, 5, &mut lin);

        let l = Link::Pinned(cids[0]);
        assert_eq!(resolve(&l, &lin), Resolved::Pinned(cids[0]));
        assert!(!resolve(&l, &lin).moved());
        assert_eq!(resolve(&l, &lin).target(), Some(cids[0]));
    }

    /// A tracking link follows the chain, and reports that it did.
    #[test]
    fn a_tracking_link_follows_and_says_how_far() {
        let id = Identity::from_seed([1u8; 32]);
        let mut lin = Lineage::new();
        let cids = chain(&id, 5, &mut lin);

        let l = Link::Tracking { seen: cids[0] };
        match resolve(&l, &lin) {
            Resolved::Superseded { head, seen, steps } => {
                assert_eq!(head, cids[4]);
                assert_eq!(seen, cids[0]);
                assert_eq!(steps, 4);
            }
            other => panic!("expected Superseded, got {other:?}"),
        }
        assert!(resolve(&l, &lin).moved(), "the reader was not told it moved");
    }

    /// A tracking link at the head reports current rather than superseded.
    #[test]
    fn a_tracking_link_at_the_head_is_current() {
        let id = Identity::from_seed([1u8; 32]);
        let mut lin = Lineage::new();
        let cids = chain(&id, 3, &mut lin);
        let l = Link::Tracking { seen: cids[2] };
        assert_eq!(resolve(&l, &lin), Resolved::Current(cids[2]));
        assert!(!resolve(&l, &lin).moved());
    }

    /// A reader holding nothing gets what the author saw, not an error.
    ///
    /// Staleness must degrade to the pinned behaviour. Anything else makes a tracking link
    /// worse than a pinned one for a reader who is merely behind.
    #[test]
    fn a_reader_holding_nothing_sees_what_the_author_saw() {
        let id = Identity::from_seed([1u8; 32]);
        let mut full = Lineage::new();
        let cids = chain(&id, 4, &mut full);

        let empty = Lineage::new();
        let l = Link::Tracking { seen: cids[0] };
        assert_eq!(resolve(&l, &empty), Resolved::Unknown(cids[0]));
        assert_eq!(resolve(&l, &empty).target(), Some(cids[0]));
    }

    /// A forked chain must refuse rather than pick.
    ///
    /// Two valid successors mean the publisher signed two conflicting continuations. Any rule
    /// for choosing lets that publisher show different readers different content while both
    /// verify, which is exactly the substitution this layer exists to prevent.
    #[test]
    fn a_forked_chain_is_refused_rather_than_resolved() {
        let id = Identity::from_seed([1u8; 32]);
        let mut lin = Lineage::new();
        let base = lin
            .insert(Object::create(&id, "page", 0, b"v0".to_vec(), None))
            .unwrap();
        let a = lin
            .insert(Object::create(&id, "page", 1, b"left".to_vec(), Some(base)))
            .unwrap();
        let b = lin
            .insert(Object::create(&id, "page", 1, b"right".to_vec(), Some(base)))
            .unwrap();

        let l = Link::Tracking { seen: base };
        match resolve(&l, &lin) {
            Resolved::Forked { at, candidates } => {
                assert_eq!(at, base);
                assert_eq!(candidates.len(), 2);
                assert!(candidates.contains(&a) && candidates.contains(&b));
            }
            other => panic!("a fork resolved to {other:?}"),
        }
        assert_eq!(resolve(&l, &lin).target(), None, "a fork was given a default");
    }

    /// Somebody else's successor must not capture a tracking link.
    ///
    /// If it could, anyone could publish an object claiming to supersede a popular page and
    /// every tracking link to it would follow them. The lineage already refuses the edge; this
    /// asserts resolution inherits that refusal.
    #[test]
    fn a_stranger_cannot_capture_a_tracking_link() {
        let author = Identity::from_seed([1u8; 32]);
        let stranger = Identity::from_seed([2u8; 32]);
        let mut lin = Lineage::new();
        let base = lin
            .insert(Object::create(&author, "page", 0, b"mine".to_vec(), None))
            .unwrap();
        let _ = lin.insert(Object::create(
            &stranger,
            "page",
            1,
            b"hijacked".to_vec(),
            Some(base),
        ));

        let l = Link::Tracking { seen: base };
        assert_eq!(
            resolve(&l, &lin),
            Resolved::Current(base),
            "a stranger's object captured the link"
        );
    }

    /// Resolution must stop at the cap, and the test must actually reach it.
    ///
    /// The previous version built a chain of 64 against a cap of 4096 and asserted
    /// `steps < MAX_STEPS`, which compares two constants and holds however `resolve` behaves.
    /// Deleting the cap entirely would have passed it, leaving a publisher able to buy
    /// unbounded reader time on every tracking link.
    #[test]
    fn resolution_stops_at_the_cap() {
        let id = Identity::from_seed([9u8; 32]);
        let mut lin = Lineage::new();
        let cids = chain(&id, MAX_STEPS + 2, &mut lin);

        match resolve(&Link::Tracking { seen: cids[0] }, &lin) {
            Resolved::Superseded { head, steps, .. } => {
                assert_eq!(steps, MAX_STEPS, "the walk did not stop at the cap");
                assert_ne!(
                    head,
                    *cids.last().unwrap(),
                    "the walk reached the true head, so the cap was not binding"
                );
            }
            other => panic!("expected a capped walk, got {other:?}"),
        }
    }

    /// Both link kinds must survive a document round trip and stay distinguishable.
    ///
    /// If the encoding lost the distinction, every citation would silently become a tracking
    /// link, which is the failure this whole type exists to prevent.
    #[test]
    fn the_two_link_kinds_survive_encoding_and_stay_distinct() {
        let c = Cid::of(b"target");
        let node = Node::Prose {
            runs: vec![
                Run::plain("see "),
                Run::link("the citation", c),
                Run::plain(" and "),
                Run::tracking_link("the current version", c),
            ],
        };
        let back = Node::from_bytes(&node.encode()).unwrap();
        assert_eq!(back, node);

        let Node::Prose { runs } = back else {
            panic!("shape changed")
        };
        assert_eq!(runs[1].link, Some(Link::Pinned(c)));
        assert_eq!(runs[3].link, Some(Link::Tracking { seen: c }));
        assert_ne!(runs[1].link, runs[3].link, "the kinds collapsed into one");
    }

    /// Every unassigned link tag must be refused, at the position that actually holds it.
    ///
    /// The previous version overwrote **every** byte equal to 1 and asserted only that some
    /// mutation was refused. At least three unrelated positions in this encoding are 1: a run
    /// count, a string length, and the hash algorithm byte, each of which fails decoding on its
    /// own. So the aggregate held regardless of what the link tag did, and a fallthrough that
    /// silently decoded tag 9 as a pinned link would have passed: two byte strings naming one
    /// node, which is the parser differential the format exists to prevent.
    #[test]
    fn every_unassigned_link_tag_is_refused() {
        let c = Cid::of(b"t");
        let good = Node::Prose {
            runs: vec![Run::link("x", c)],
        }
        .encode();

        // Find the tag deterministically: it is the byte whose value is 1 and which, when set
        // to 2, still decodes, since 2 is the other assigned tag.
        let mut tag_at = None;
        for i in 0..good.len() {
            if good[i] != 1 {
                continue;
            }
            let mut probe = good.clone();
            probe[i] = 2;
            if let Ok(Node::Prose { runs }) = Node::from_bytes(&probe) {
                if runs.len() == 1 && matches!(runs[0].link, Some(Link::Tracking { .. })) {
                    tag_at = Some(i);
                    break;
                }
            }
        }
        let tag_at = tag_at.expect("the link tag position was not found");

        let mut refused = 0;
        for t in 3u8..=255 {
            let mut bad = good.clone();
            bad[tag_at] = t;
            assert!(
                Node::from_bytes(&bad).is_err(),
                "link tag {t} was accepted rather than refused"
            );
            refused += 1;
        }
        assert_eq!(refused, 253);
        // And the two assigned values still work, so the sweep is not refusing everything.
        for t in [1u8, 2] {
            let mut ok = good.clone();
            ok[tag_at] = t;
            assert!(Node::from_bytes(&ok).is_ok(), "assigned tag {t} was refused");
        }
    }
    /// A reader must be able to see which kind of link they are following.
    ///
    /// A link whose kind is invisible is a URL again: the reader cannot tell whether what they
    /// are about to follow is fixed or will change under them.
    #[test]
    fn rendering_distinguishes_the_two_kinds_of_link() {
        let c = Cid::of(b"target");
        let mut doc = Doc::new();
        let root = doc.add(Node::Prose {
            runs: vec![
                Run::link("a citation", c),
                Run::plain(" and "),
                Run::tracking_link("a menu", c),
            ],
        });
        let text = doc.render_text(&root);
        assert!(text.contains("pinned"), "a pinned link rendered without saying so: {text}");
        assert!(text.contains("tracking"), "a tracking link rendered without saying so: {text}");
    }

}
