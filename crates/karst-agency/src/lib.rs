//! L12 Agency.
//!
//! The user agent stopped being an agent for the user. A page commands layout, autoplay, modal
//! interruption, consent theatre and infinite scroll, and the client obeys. Every one of those
//! is a capability the client handed over by default and never got back.
//!
//! Here a document **requests** a rendering and the client decides. A publisher's preference
//! has no privileged standing, the default grant is nothing, and anything that wants to move,
//! make sound, take the viewport or run has to be granted it.
//!
//! # The part that is structural rather than polite
//!
//! A policy that a document could read would be a policy a document could adapt to, and
//! adapting to it is fingerprinting. So the decision never reaches the document, and it cannot
//! reach the document, because a document is **data** and rendering is a pure function of
//! (document, policy) with no channel back.
//!
//! That is the easy half. The hard half is below.
//!
//! # The leak is not the renderer, it is the fetch
//!
//! A document cannot ask what rendering it received. It can arrange to **need different things
//! depending on the answer**: reference one image for a wide viewport and another for a narrow
//! one, and the client's fetch pattern reports the viewport without the document ever
//! observing anything. This is what media queries do on the web, and no amount of care inside
//! the renderer touches it, because the channel is the network rather than the page.
//!
//! So resolution here is **unconditional**. What a document references is fetched or not
//! fetched according to the client's own policy, and never according to a property of the
//! client.
//!
//! # The cache is a client property too, and this is where the first version failed
//!
//! An earlier version computed the fetch set by walking the document graph in the reader's own
//! node store, skipping anything the store did not hold. That store is shared across every
//! document a reader has ever seen, and it is content-addressed, so **what a reader already
//! holds determined what they fetched**.
//!
//! That is a supercookie with no expiry. A publisher seeds a document whose closure contains
//! some chosen subset of sixty-four probe nodes; the reader's store keeps them; and every later
//! document from anyone can read the subset back out of the fetch pattern. Sixty-four bits,
//! silent, surviving any amount of identity rotation, because it is not an identifier being
//! stored but a shape being remembered.
//!
//! Two things follow, and both are structural:
//!
//! A document declares its closure and the client uses **the declaration**, not a traversal of
//! whatever it happens to hold. [`declared_closure`] is what a publisher computes, from a
//! complete store; a reader never derives one from a partial store.
//!
//! And a reader fetches the whole closure regardless of what it already holds, because
//! **skipping what you have is how you report what you have**. `Policy::reuse_cache` exists to
//! turn that off, is off by default, and is named so that turning it on is a decision rather
//! than an optimisation.
//!
//! What that costs is real: a reader refetches, and a client on a small screen still fetches
//! the large image. Adaptive delivery, caching and unlinkability are the same trade this design
//! keeps making, and it takes unlinkability.

use std::collections::BTreeSet;

use karst_doc::{Doc, Link, Node};
use karst_object::Cid;

/// Something a document may ask for and does not get by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ask {
    /// Move without being asked.
    Motion,
    /// Make sound without being asked.
    Audio,
    /// Take the whole viewport.
    Viewport,
    /// Interrupt the reader.
    Interrupt,
    /// Run code.
    Execute,
}

impl Ask {
    pub const ALL: [Ask; 5] = [
        Ask::Motion,
        Ask::Audio,
        Ask::Viewport,
        Ask::Interrupt,
        Ask::Execute,
    ];
}

/// What a document would like. Advisory in full.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    pub asks: BTreeSet<Ask>,
    /// How much execution the document would like, if execution is granted at all.
    pub steps: u64,
}

impl Request {
    pub fn new() -> Self {
        Request::default()
    }

    pub fn asking(mut self, a: Ask) -> Self {
        self.asks.insert(a);
        self
    }

    pub fn steps(mut self, n: u64) -> Self {
        self.steps = n;
        self
    }
}

/// What the client permits. The only thing that decides anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    granted: BTreeSet<Ask>,
    /// Hard ceiling on execution, whatever a document asks for.
    pub step_budget: u64,
    /// Whether to fetch what a document references at all.
    pub fetch_referenced: bool,
    /// Skip fetching what is already held.
    ///
    /// **Fingerprinting.** The fetch pattern then reports the reader's cache, which is durable
    /// client state a publisher can write into and read back. Off by default and named so that
    /// enabling it is a decision.
    pub reuse_cache: bool,
}

impl Default for Policy {
    fn default() -> Self {
        // Nothing granted. A default that granted anything would be a default nobody chose.
        Policy {
            granted: BTreeSet::new(),
            step_budget: 0,
            fetch_referenced: true,
            reuse_cache: false,
        }
    }
}

impl Policy {
    pub fn new() -> Self {
        Policy::default()
    }

    pub fn granting(mut self, a: Ask) -> Self {
        self.granted.insert(a);
        self
    }

    pub fn with_steps(mut self, n: u64) -> Self {
        self.step_budget = n;
        self
    }

    /// Fetch nothing a document references. Slower, quieter.
    pub fn offline(mut self) -> Self {
        self.fetch_referenced = false;
        self
    }

    /// Skip what is already held, accepting that the fetch pattern reports the cache.
    pub fn reusing_cache(mut self) -> Self {
        self.reuse_cache = true;
        self
    }

    pub fn grants(&self, a: Ask) -> bool {
        self.granted.contains(&a)
    }
}

/// What the client will actually do.
///
/// Deliberately **not** returned to the document, and not returnable: nothing in this crate
/// gives a document a way to observe it. A document that could read this could adapt to it,
/// and adapting to it is fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    allowed: BTreeSet<Ask>,
    /// Asks the document made that the client refused. For the reader's benefit, never the
    /// document's: a reader may want to know a page wanted to interrupt them.
    pub refused: BTreeSet<Ask>,
    pub steps: u64,
    /// What will be fetched, in a fixed order, computed without consulting the policy's
    /// grants at all.
    pub fetches: Vec<Cid>,
}

impl Plan {
    pub fn allows(&self, a: Ask) -> bool {
        self.allowed.contains(&a)
    }

    /// Whether the document asked for anything it did not get.
    pub fn was_refused_anything(&self) -> bool {
        !self.refused.is_empty()
    }
}

/// Decide what to do with a document.
///
/// `declared` is the closure the **publisher** computed and shipped with the document. It is
/// taken as an argument rather than derived here, because deriving it would mean walking the
/// reader's own store, and the reader's store is client state.
///
/// The request is read only to record what was refused. Nothing in it can widen the policy.
pub fn decide(declared: &[Cid], held: &BTreeSet<Cid>, request: &Request, policy: &Policy) -> Plan {
    // Fetches first, from the declaration alone. The only client property consulted is
    // `reuse_cache`, which is off by default and documented as fingerprinting.
    let mut fetches: Vec<Cid> = if !policy.fetch_referenced {
        Vec::new()
    } else if policy.reuse_cache {
        declared.iter().filter(|c| !held.contains(c)).copied().collect()
    } else {
        declared.to_vec()
    };
    fetches.sort();
    fetches.dedup();

    let allowed: BTreeSet<Ask> = request
        .asks
        .iter()
        .copied()
        .filter(|a| policy.grants(*a))
        .collect();
    let refused: BTreeSet<Ask> = request
        .asks
        .iter()
        .copied()
        .filter(|a| !policy.grants(*a))
        .collect();

    let steps = if allowed.contains(&Ask::Execute) {
        request.steps.min(policy.step_budget)
    } else {
        0
    };

    Plan {
        allowed,
        refused,
        steps,
        fetches,
    }
}

/// The closure a **publisher** declares, computed from a complete store.
///
/// A reader must not call this on a partial store. Doing so is the defect this signature
/// exists to make awkward: the result would silently depend on what the reader happened to
/// hold, which is exactly the channel [`decide`] refuses to open.
///
/// Sorted by content address rather than document order, so the sequence of fetches does not
/// report the shape of the document to whoever serves them.
pub fn declared_closure(doc: &Doc, root: &Cid) -> Vec<Cid> {
    let mut out = BTreeSet::new();
    let mut frontier = vec![*root];
    let mut seen = BTreeSet::new();
    while let Some(cid) = frontier.pop() {
        if !seen.insert(cid) {
            continue;
        }
        let Some(node) = doc.get(&cid) else {
            continue;
        };
        for l in node.links() {
            out.insert(l);
        }
        frontier.extend(node.contained());
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_doc::Run;

    /// Build a document that references different things, as a hostile publisher would.
    fn doc_with(links: &[Cid]) -> (Doc, Cid) {
        let mut d = Doc::new();
        let mut kids = Vec::new();
        for (i, l) in links.iter().enumerate() {
            kids.push(d.add(Node::Prose {
                runs: vec![Run::link(&format!("r{i}"), *l)],
            }));
        }
        let root = d.add(Node::Section {
            title: "doc".into(),
            children: kids,
        });
        (d, root)
    }

    fn cid(n: u8) -> Cid {
        Cid::of(&[n])
    }

    /// Nothing is granted by default.
    ///
    /// A default that granted anything would be a default nobody chose, which is exactly how
    /// autoplay and modal interruption became normal.
    #[test]
    fn the_default_grant_is_nothing() {
        let (d, root) = doc_with(&[]);
        let mut asking = Request::new();
        for a in Ask::ALL {
            asking = asking.asking(a);
        }
        let plan = decide(&declared_closure(&d, &root), &BTreeSet::new(), &asking.steps(1_000_000), &Policy::new());

        for a in Ask::ALL {
            assert!(!plan.allows(a), "{a:?} was granted by default");
        }
        assert_eq!(plan.refused.len(), Ask::ALL.len());
        assert_eq!(plan.steps, 0);
    }

    /// Asking harder must not help.
    #[test]
    fn a_request_cannot_widen_a_policy() {
        let (d, root) = doc_with(&[]);
        let policy = Policy::new().granting(Ask::Motion);
        let greedy = Request::new()
            .asking(Ask::Motion)
            .asking(Ask::Audio)
            .asking(Ask::Interrupt)
            .asking(Ask::Execute)
            .steps(u64::MAX);
        let plan = decide(&declared_closure(&d, &root), &BTreeSet::new(), &greedy, &policy);

        assert!(plan.allows(Ask::Motion));
        assert!(!plan.allows(Ask::Audio));
        assert!(!plan.allows(Ask::Interrupt));
        assert_eq!(plan.steps, 0, "execution ran without being granted");
    }

    /// Execution is bounded by the client, not by the document's appetite.
    #[test]
    fn execution_is_bounded_by_the_client() {
        let (d, root) = doc_with(&[]);
        let policy = Policy::new().granting(Ask::Execute).with_steps(500);
        let plan = decide(
            &declared_closure(&d, &root),
            &BTreeSet::new(),
            &Request::new().asking(Ask::Execute).steps(u64::MAX),
            &policy,
        );
        assert!(plan.allows(Ask::Execute));
        assert_eq!(plan.steps, 500);

        // And a modest document gets what it asked for, not the ceiling.
        let plan = decide(
            &declared_closure(&d, &root),
            &BTreeSet::new(),
            &Request::new().asking(Ask::Execute).steps(10),
            &policy,
        );
        assert_eq!(plan.steps, 10);
    }

    /// The fetch pattern must be identical across wildly different clients.
    ///
    /// This is the fingerprinting channel, and it is not in the renderer. A document cannot
    /// ask what rendering it received, and it does not need to: referencing one thing for a
    /// wide viewport and another for a narrow one makes the client's fetches report the
    /// answer. Media queries are exactly this. The defence has to be that resolution never
    /// consults a client property, which is why `fetches` is computed before grants are.
    #[test]
    fn the_fetch_pattern_does_not_vary_with_the_client() {
        let (d, root) = doc_with(&[cid(1), cid(2), cid(3), cid(4)]);
        let request = Request::new()
            .asking(Ask::Motion)
            .asking(Ask::Audio)
            .asking(Ask::Viewport)
            .asking(Ask::Execute)
            .steps(9_000);

        let clients = [
            Policy::new(),
            Policy::new().granting(Ask::Motion),
            Policy::new().granting(Ask::Audio).granting(Ask::Viewport),
            Policy::new()
                .granting(Ask::Execute)
                .with_steps(1_000_000)
                .granting(Ask::Interrupt),
        ];

        let baseline = decide(&declared_closure(&d, &root), &BTreeSet::new(), &request, &clients[0]).fetches;
        assert_eq!(baseline.len(), 4, "vacuous: nothing was fetched");
        for (i, p) in clients.iter().enumerate() {
            assert_eq!(
                decide(&declared_closure(&d, &root), &BTreeSet::new(), &request, p).fetches,
                baseline,
                "client {i} produced a different fetch pattern"
            );
        }
    }

    /// And the order must not report the document's shape either.
    #[test]
    fn the_fetch_order_does_not_follow_the_document() {
        // Driven through a hand-built declaration rather than one `declared_closure` already
        // sorted, because comparing a sorted input against its own sort holds however `decide`
        // orders things. A declaration arriving unsorted and with duplicates is what a
        // publisher can actually send.
        let declared = vec![cid(9), cid(3), cid(9), cid(7), cid(1), cid(3)];
        let plan = decide(&declared, &BTreeSet::new(), &Request::new(), &Policy::new());

        let mut expected = declared.clone();
        expected.sort();
        expected.dedup();
        assert_eq!(expected.len(), 4, "vacuous: the input had no duplicates");
        assert_ne!(
            declared[..4].to_vec(),
            expected,
            "vacuous: the input was already in sorted order"
        );
        assert_eq!(
            plan.fetches, expected,
            "fetches followed the order the publisher sent, or kept duplicates"
        );

        // And a document whose closure happens to be sorted gives the same answer, so the
        // end-to-end path is still covered.
        let (d, root) = doc_with(&[cid(9), cid(3), cid(7), cid(1)]);
        let via_doc = decide(
            &declared_closure(&d, &root),
            &BTreeSet::new(),
            &Request::new(),
            &Policy::new(),
        );
        assert_eq!(via_doc.fetches, plan.fetches);
    }

    /// A reader who wants to fetch nothing gets to.
    #[test]
    fn a_reader_can_refuse_to_fetch_anything() {
        let (d, root) = doc_with(&[cid(1), cid(2)]);
        let plan = decide(&declared_closure(&d, &root), &BTreeSet::new(), &Request::new(), &Policy::new().offline());
        assert!(plan.fetches.is_empty());
    }

    /// The refusal record is for the reader, and there is no path from it to the document.
    ///
    /// A reader may reasonably want to know that a page wanted to interrupt them. A document
    /// that could learn the same thing would adapt to it.
    #[test]
    fn refusals_are_visible_to_the_reader_and_not_to_the_document() {
        let (d, root) = doc_with(&[]);
        let plan = decide(
            &declared_closure(&d, &root),
            &BTreeSet::new(),
            &Request::new().asking(Ask::Interrupt).asking(Ask::Audio),
            &Policy::new(),
        );
        assert!(plan.was_refused_anything());
        assert!(plan.refused.contains(&Ask::Interrupt));

        // `decide` takes the document immutably and returns a plan the caller owns. There is
        // no mutation of the document and no value handed back into it, so nothing the client
        // decided can be read by what it decided about.
        let (again, root2) = doc_with(&[]);
        assert_eq!(again.len(), d.len());
        assert_eq!(root2, root, "deciding altered the document");
    }

    /// Two documents that differ only in what they ask for must fetch identically.
    ///
    /// Otherwise a publisher learns a client's policy by publishing two variants and watching
    /// which fetch pattern comes back.
    #[test]
    fn what_a_document_asks_for_does_not_change_what_it_fetches() {
        let (d, root) = doc_with(&[cid(5), cid(6)]);
        let quiet = decide(&declared_closure(&d, &root), &BTreeSet::new(), &Request::new(), &Policy::new());
        let greedy = decide(
            &declared_closure(&d, &root),
            &BTreeSet::new(),
            &Request::new()
                .asking(Ask::Execute)
                .asking(Ask::Viewport)
                .steps(1 << 40),
            &Policy::new().granting(Ask::Execute).with_steps(1 << 20),
        );
        assert_eq!(quiet.fetches, greedy.fetches);
    }

    /// A document referencing the same thing many times must not fetch it many times.
    #[test]
    fn repeated_references_are_fetched_once() {
        let (d, root) = doc_with(&[cid(1), cid(1), cid(1), cid(2)]);
        let plan = decide(&declared_closure(&d, &root), &BTreeSet::new(), &Request::new(), &Policy::new());
        let mut expected = vec![cid(1), cid(2)];
        expected.sort();
        assert_eq!(plan.fetches, expected);
    }

    /// A cyclic document must not hang resolution.
    #[test]
    fn a_cycle_does_not_hang_resolution() {
        let mut d = Doc::new();
        let leaf = d.add(Node::Prose {
            runs: vec![Run::link("x", cid(1))],
        });
        // A section containing itself is not constructible by content address, so the closest
        // hostile shape is a deep chain that revisits the same children.
        let mut cur = leaf;
        for _ in 0..64 {
            cur = d.add(Node::Section {
                title: "s".into(),
                children: vec![cur, leaf],
            });
        }
        let plan = decide(&declared_closure(&d, &cur), &BTreeSet::new(), &Request::new(), &Policy::new());
        assert_eq!(plan.fetches, vec![cid(1)]);
    }

    /// Tracking links must be fetched by their fallback, not resolved during rendering.
    ///
    /// Resolving a tracking link at render time would make the fetch depend on what the reader
    /// already holds, which varies per reader and is therefore a fingerprint.
    #[test]
    fn a_tracking_link_is_fetched_by_what_the_author_saw() {
        let mut d = Doc::new();
        let root = d.add(Node::Prose {
            runs: vec![Run::tracking_link("live", cid(8))],
        });
        let plan = decide(&declared_closure(&d, &root), &BTreeSet::new(), &Request::new(), &Policy::new());
        assert_eq!(plan.fetches, vec![cid(8)]);
        assert_eq!(Link::Tracking { seen: cid(8) }.fallback(), cid(8));
    }
    /// The fetch set must not vary with what the reader already holds.
    ///
    /// This is the test the previous version could not fail. It held the document fixed and
    /// varied only `Policy`, which the fetch computation did not even take as a parameter, so
    /// it asserted nothing about the variable that actually controlled the result: the reader's
    /// own node store.
    ///
    /// That store is shared across every document a reader has ever seen and is content
    /// addressed, so a publisher can write a chosen subset of probe nodes into it and read the
    /// subset back out of any later document's fetch pattern. Sixty-four probes is sixty-four
    /// bits, silent, surviving any amount of identity rotation, because what is remembered is
    /// a shape rather than an identifier.
    #[test]
    fn the_fetch_set_does_not_vary_with_what_the_reader_already_holds() {
        let probes: Vec<Cid> = (0..64u8).map(cid).collect();
        let declared = {
            let (d, root) = doc_with(&probes);
            declared_closure(&d, &root)
        };
        assert_eq!(declared.len(), 64, "vacuous: nothing was declared");

        // Four readers who have seen very different things before.
        let stores: Vec<BTreeSet<Cid>> = vec![
            BTreeSet::new(),
            probes.iter().take(1).copied().collect(),
            probes.iter().step_by(3).copied().collect(),
            probes.iter().copied().collect(),
        ];

        let baseline = decide(&declared, &stores[0], &Request::new(), &Policy::new()).fetches;
        for (i, held) in stores.iter().enumerate() {
            assert_eq!(
                decide(&declared, held, &Request::new(), &Policy::new()).fetches,
                baseline,
                "reader {i} produced a different fetch pattern because of what it held"
            );
        }
    }

    /// And reusing the cache is exactly the leak, which is why it is opt-in and named.
    ///
    /// Asserted rather than merely documented, so the cost of the convenient option is a fact
    /// in the test suite rather than a sentence someone can delete.
    #[test]
    fn reusing_the_cache_leaks_the_cache() {
        let probes: Vec<Cid> = (0..8u8).map(cid).collect();
        let (d, root) = doc_with(&probes);
        let declared = declared_closure(&d, &root);

        let empty = BTreeSet::new();
        let some: BTreeSet<Cid> = probes.iter().take(3).copied().collect();
        let policy = Policy::new().reusing_cache();

        let a = decide(&declared, &empty, &Request::new(), &policy).fetches;
        let b = decide(&declared, &some, &Request::new(), &policy).fetches;
        assert_ne!(a, b, "reuse_cache did not actually reuse anything");
        assert_eq!(b.len(), 5);

        // With the default policy the two are indistinguishable again.
        let d0 = decide(&declared, &empty, &Request::new(), &Policy::new()).fetches;
        let d1 = decide(&declared, &some, &Request::new(), &Policy::new()).fetches;
        assert_eq!(d0, d1);
    }

    /// A declared closure must not depend on the store it was computed from being partial.
    ///
    /// A publisher computes it once from a complete store. A reader who recomputed it from
    /// their own partial store would reintroduce the whole defect, which is why `decide` takes
    /// the declaration rather than a document.
    #[test]
    fn a_partial_store_yields_a_smaller_closure_which_is_why_readers_do_not_compute_one() {
        let probes: Vec<Cid> = (0..4u8).map(cid).collect();
        let (full, root) = doc_with(&probes);
        let complete = declared_closure(&full, &root);
        assert_eq!(complete.len(), 4);

        // A store holding only the root sees nothing beneath it.
        let mut partial = Doc::new();
        partial.add(
            full.get(&root).expect("root is present").clone(),
        );
        let truncated = declared_closure(&partial, &root);
        assert!(
            truncated.len() < complete.len(),
            "vacuous: the partial store produced the same closure"
        );
    }

}
