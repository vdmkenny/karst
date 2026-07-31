//! Messaging and discussion boards, with no host.
//!
//! Forums are centralised today for one missing feature: a link points one way. Given a
//! post, there is no way to find what replied to it, so somebody has to keep the list,
//! and whoever keeps the list owns the community.
//!
//! Once backlinks exist (L13), a thread assembles itself from signed objects and nobody
//! hosts it. What follows from that:
//!
//! - **A board is a view, not a place.** It is an index over posts, so anyone may
//!   publish a competing board over the identical posts.
//! - **Moderation is subtractive and plural.** A curator publishes labels; you subscribe
//!   to whichever you trust. Two people reading "the same board" with different
//!   subscriptions see different boards, and both are correct.
//! - **Nothing is ever deleted.** Labelling something hidden removes it from *that view*.
//!   The object still exists and still verifies. This is the honest cost, and
//!   [`Board::render`] shows a hidden post's tombstone rather than pretending otherwise.
//!
//! Every post also declares its [`Agency`]: whether a person wrote it, or a machine did,
//! and under whose authority. Machine delegation is cryptographically checkable; a claim
//! of human authorship is not, permanently. See `docs/07-authorship.md`.
//!
//! A direct message is the same object with one recipient instead of a board. The hard
//! part of messaging is metadata, not storage, and that is L4's job rather than this
//! crate's.

use std::collections::BTreeMap;

use karst_attest::{Agency, AttestError, Policy};
use karst_id::{Address, Identity};
use karst_object::{Cid, Dec, DecodeError, Enc, Object, ObjectError};

pub const POST_KIND: &str = "karst.post.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadError {
    Object(ObjectError),
    Decode(DecodeError),
    Attest(AttestError),
    WrongKind(String),
}

impl core::fmt::Display for ThreadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ThreadError::Object(e) => write!(f, "{e}"),
            ThreadError::Decode(e) => write!(f, "{e}"),
            ThreadError::Attest(e) => write!(f, "authorship claim invalid: {e}"),
            ThreadError::WrongKind(k) => write!(f, "not a post: kind '{k}'"),
        }
    }
}

impl std::error::Error for ThreadError {}

/// A post. Ordinary signed object, plus a structural reference to what it answers and a
/// declaration of who or what wrote it.
#[derive(Clone, Debug)]
pub struct Post {
    pub cid: Cid,
    /// The key that signed it.
    pub author: Address,
    pub body: String,
    pub reply_to: Option<Cid>,
    pub seq: u64,
    pub agency: Agency,
}

impl Post {
    /// Who is answerable for this post. For a delegated act that is the principal rather
    /// than the agent, which is the entire reason the chain is carried.
    pub fn accountable(&self) -> Address {
        self.agency.accountable(self.author)
    }
}

fn encode_payload(body: &str, reply_to: Option<&Cid>, agency: &Agency) -> Vec<u8> {
    let mut e = Enc::new();
    e.str(body).opt_cid(reply_to);
    agency.encode(&mut e);
    e.finish()
}

impl Post {
    /// Write a post. Publishing is signing; there is nowhere to submit it to.
    pub fn create(
        author: &Identity,
        seq: u64,
        body: &str,
        reply_to: Option<Cid>,
        agency: Agency,
    ) -> Object {
        Object::create(
            author,
            POST_KIND,
            seq,
            encode_payload(body, reply_to.as_ref(), &agency),
            None,
        )
    }

    /// Convenience for the common case of a person posting for themselves.
    pub fn by_person(author: &Identity, seq: u64, body: &str, reply_to: Option<Cid>) -> Object {
        Post::create(author, seq, body, reply_to, Agency::Direct)
    }

    /// Verify and decode an object received from anyone at all.
    ///
    /// Two independent checks: the signature proves which key signed it, and the agency
    /// claim is checked as far as it can be. A forged delegation is rejected here. A
    /// false claim of human authorship is not, and cannot be.
    pub fn from_object(obj: &Object) -> Result<Post, ThreadError> {
        if obj.kind != POST_KIND {
            return Err(ThreadError::WrongKind(obj.kind.clone()));
        }
        let author = obj.verify().map_err(ThreadError::Object)?;

        let mut d = Dec::new(&obj.payload);
        let body = d.str().map_err(ThreadError::Decode)?;
        let reply_to = d.opt_cid().map_err(ThreadError::Decode)?;
        let agency = Agency::decode(&mut d).map_err(ThreadError::Decode)?;
        d.end().map_err(ThreadError::Decode)?;

        agency.verify(author).map_err(ThreadError::Attest)?;

        Ok(Post {
            cid: obj.cid(),
            author,
            body,
            reply_to,
            seq: obj.seq,
            agency,
        })
    }
}

/// Everything we happen to hold. Not a server, not authoritative, just a local cache
/// that any peer might have a different subset of.
#[derive(Default)]
pub struct Graph {
    posts: BTreeMap<Cid, Post>,
}

impl Graph {
    pub fn new() -> Self {
        Graph::default()
    }

    /// Accept a post from anyone. Verification is intrinsic: the object carries its
    /// author's key, so there is no server whose word we are taking.
    pub fn insert(&mut self, obj: &Object) -> Result<Cid, ThreadError> {
        let post = Post::from_object(obj)?;
        let cid = post.cid;
        self.posts.insert(cid, post);
        Ok(cid)
    }

    pub fn get(&self, cid: &Cid) -> Option<&Post> {
        self.posts.get(cid)
    }

    pub fn len(&self) -> usize {
        self.posts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.posts.is_empty()
    }

    /// The backlink query. This is the whole trick: a local computation over objects we
    /// hold, not a request to whoever owns the thread.
    pub fn replies(&self, cid: &Cid) -> Vec<Cid> {
        let mut out: Vec<Cid> = self
            .posts
            .values()
            .filter(|p| p.reply_to.as_ref() == Some(cid))
            .map(|p| p.cid)
            .collect();
        out.sort_by_key(|c| self.posts[c].seq);
        out
    }

    /// Posts that answer nothing.
    pub fn roots(&self) -> Vec<Cid> {
        let mut out: Vec<Cid> = self
            .posts
            .values()
            .filter(|p| p.reply_to.is_none())
            .map(|p| p.cid)
            .collect();
        out.sort_by_key(|c| self.posts[c].seq);
        out
    }

    /// Assemble a thread depth-first. Returns `(depth, cid)` pairs.
    pub fn thread(&self, root: &Cid) -> Vec<(usize, Cid)> {
        let mut out = Vec::new();
        self.walk(root, 0, &mut out);
        out
    }

    fn walk(&self, cid: &Cid, depth: usize, out: &mut Vec<(usize, Cid)>) {
        if !self.posts.contains_key(cid) {
            return;
        }
        out.push((depth, *cid));
        for r in self.replies(cid) {
            self.walk(&r, depth + 1, out);
        }
    }
}

/// A curator's opinion about a post. Never a deletion, because deletion is not available
/// and pretending otherwise would be a lie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Label {
    Hide,
    Warn(String),
}

/// A board: a name, a curator, an authorship policy, and a set of opinions. That is all a
/// forum ever was.
#[derive(Clone, Debug)]
pub struct Board {
    pub name: String,
    pub curator: Address,
    pub policy: Policy,
    labels: BTreeMap<Cid, Label>,
}

impl Board {
    pub fn new(name: &str, curator: Address, policy: Policy) -> Self {
        Board {
            name: name.into(),
            curator,
            policy,
            labels: BTreeMap::new(),
        }
    }

    pub fn label(&mut self, cid: Cid, label: Label) -> &mut Self {
        self.labels.insert(cid, label);
        self
    }

    pub fn label_of(&self, cid: &Cid) -> Option<&Label> {
        self.labels.get(cid)
    }

    /// Render a thread through this board's policy and labels. The same [`Graph`]
    /// rendered through a different board is a different board, over identical posts.
    pub fn render(&self, g: &Graph, root: &Cid) -> String {
        let mut out = format!(
            "== {} (curated by {}, {})\n",
            self.name,
            self.curator.short(),
            self.policy.describe()
        );
        for (depth, cid) in g.thread(root) {
            let pad = "  ".repeat(depth);
            let Some(post) = g.get(&cid) else { continue };

            if !self.policy.admits(&post.agency) {
                out.push_str(&format!(
                    "{pad}[excluded by policy: {}]\n",
                    post.agency.describe()
                ));
                continue;
            }

            match self.labels.get(&cid) {
                Some(Label::Hide) => {
                    // The post still exists and still verifies. It is simply not shown
                    // here. Another board shows it.
                    out.push_str(&format!(
                        "{pad}[hidden by curator, object {} still exists]\n",
                        cid.short()
                    ));
                }
                Some(Label::Warn(reason)) => {
                    out.push_str(&format!("{pad}[!] {reason}\n"));
                    out.push_str(&format!("{pad}{}\n", self.line(post)));
                }
                None => {
                    out.push_str(&format!("{pad}{}\n", self.line(post)));
                }
            }
        }
        out
    }

    fn line(&self, post: &Post) -> String {
        let mark = match &post.agency {
            Agency::Direct => String::new(),
            Agency::Assisted { tool } => format!(" [assisted: {tool}]"),
            Agency::Delegated { principal, .. } => {
                format!(" [agent for {}]", principal.short())
            }
            Agency::Autonomous { .. } => " [autonomous agent]".to_string(),
        };
        format!("{}{} {}", post.author.short(), mark, post.body)
    }

    /// How many posts in this thread this board is hiding.
    pub fn hidden_count(&self, g: &Graph, root: &Cid) -> usize {
        g.thread(root)
            .iter()
            .filter(|(_, c)| matches!(self.labels.get(c), Some(Label::Hide)))
            .count()
    }

    /// How many posts this board's authorship policy excludes.
    pub fn excluded_count(&self, g: &Graph, root: &Cid) -> usize {
        g.thread(root)
            .iter()
            .filter_map(|(_, c)| g.get(c))
            .filter(|p| !self.policy.admits(&p.agency))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_cap::{Capability, Caveat};
    use karst_object::Cid as ObjCid;

    #[test]
    fn a_post_verifies_without_asking_anyone() {
        let author = Identity::generate();
        let obj = Post::by_person(&author, 0, "first", None);
        let post = Post::from_object(&obj).unwrap();
        assert_eq!(post.author, author.address());
        assert_eq!(post.body, "first");
        assert_eq!(post.agency, Agency::Direct);
    }

    #[test]
    fn a_tampered_post_is_rejected_on_receipt() {
        let author = Identity::generate();
        let obj = Post::by_person(&author, 0, "the real text", None);
        let evil = obj.tamper(encode_payload("the fake text", None, &Agency::Direct));
        assert!(matches!(
            Post::from_object(&evil),
            Err(ThreadError::Object(ObjectError::BadSignature))
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected_rather_than_ignored() {
        let author = Identity::generate();
        let mut payload = encode_payload("hello", None, &Agency::Direct);
        payload.push(0);
        let obj = Object::create(&author, POST_KIND, 0, payload, None);
        assert!(matches!(
            Post::from_object(&obj),
            Err(ThreadError::Decode(DecodeError::TrailingBytes))
        ));
    }

    #[test]
    fn an_agent_post_carries_a_chain_that_verifies_to_its_principal() {
        let owner = Identity::generate();
        let person = Identity::generate();
        let agent = Identity::generate();

        let root = Capability::issue(&owner, ObjCid::of(b"board"), person.address(), vec![]);
        let scoped = root
            .attenuate(&person, agent.address(), vec![Caveat::MaxUses(4)])
            .unwrap();
        let agency = Agency::from_capability(&scoped, owner.address()).unwrap();

        let obj = Post::create(&agent, 0, "summarised the thread", None, agency);
        let post = Post::from_object(&obj).unwrap();

        assert!(post.agency.is_machine());
        assert_eq!(post.accountable(), owner.address());
    }

    #[test]
    fn a_forged_delegation_is_rejected_at_the_boundary() {
        let victim = Identity::generate();
        let liar = Identity::generate();

        let obj = Post::create(
            &liar,
            0,
            "acting on behalf of someone who never said so",
            None,
            Agency::Delegated {
                principal: victim.address(),
                chain: vec![(liar.address(), liar.address())],
            },
        );
        assert!(matches!(
            Post::from_object(&obj),
            Err(ThreadError::Attest(_))
        ));
    }

    #[test]
    fn a_bot_claiming_to_be_human_is_not_caught_and_this_is_documented() {
        // The known limit. Nothing at the protocol layer detects this.
        let bot = Identity::generate();
        let obj = Post::by_person(&bot, 0, "as a human, I love this product", None);
        let post = Post::from_object(&obj).unwrap();
        assert_eq!(post.agency, Agency::Direct);
        assert!(!post.agency.is_verifiable());
    }

    fn sample() -> (Graph, Cid, Cid, Address, Address, Address) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let troll = Identity::generate();
        let botop = Identity::generate();

        let mut g = Graph::new();
        let root = g
            .insert(&Post::by_person(&alice, 0, "Is L16 actually workable?", None))
            .unwrap();
        let _r1 = g
            .insert(&Post::by_person(
                &bob,
                1,
                "Flat returns need a proof nobody has.",
                Some(root),
            ))
            .unwrap();
        let r2 = g
            .insert(&Post::by_person(&troll, 2, "read the whitepaper sheeple", Some(root)))
            .unwrap();
        let _r3 = g
            .insert(&Post::create(
                &botop,
                3,
                "Related prior work: Loopix, Sphinx, SCION.",
                Some(root),
                Agency::Autonomous {
                    operator: botop.address(),
                },
            ))
            .unwrap();

        (g, root, r2, alice.address(), bob.address(), botop.address())
    }

    #[test]
    fn threads_assemble_from_backlinks_with_no_host() {
        let (g, root, _, _, _, _) = sample();
        assert_eq!(g.thread(&root).len(), 4);
        assert_eq!(g.replies(&root).len(), 3);
        assert_eq!(g.roots(), vec![root]);
    }

    #[test]
    fn two_boards_over_identical_posts_show_different_things() {
        let (g, root, r2, alice, bob, _) = sample();

        let mut strict = Board::new("karst-design", alice, Policy::Everything);
        strict.label(r2, Label::Hide);

        let mut loose = Board::new("karst-unmoderated", bob, Policy::Everything);
        loose.label(r2, Label::Warn("low quality".into()));

        let a = strict.render(&g, &root);
        let b = loose.render(&g, &root);

        assert!(a.contains("hidden by curator") && !a.contains("sheeple"));
        assert!(b.contains("sheeple") && b.contains("low quality"));
        assert_eq!(strict.hidden_count(&g, &root), 1);
        assert_eq!(loose.hidden_count(&g, &root), 0);
        assert!(g.get(&r2).is_some(), "the post itself is untouched");
    }

    #[test]
    fn authorship_policy_changes_what_a_board_contains() {
        let (g, root, _, alice, bob, _) = sample();

        let humans = Board::new("humans-only", alice, Policy::HumanClaimedOnly);
        let everyone = Board::new("everyone", bob, Policy::Everything);
        let agents = Board::new("agents", bob, Policy::MachineOnly);

        assert_eq!(humans.excluded_count(&g, &root), 1);
        assert_eq!(everyone.excluded_count(&g, &root), 0);
        assert_eq!(agents.excluded_count(&g, &root), 3);

        assert!(humans.render(&g, &root).contains("excluded by policy"));
        assert!(everyone.render(&g, &root).contains("[autonomous agent]"));
    }

    #[test]
    fn a_hostile_curator_costs_a_subscription_change_and_nothing_else() {
        let (g, root, r2, alice, bob, _) = sample();

        let mut captured = Board::new("official", alice, Policy::Everything);
        captured.label(r2, Label::Hide);
        captured.label(g.replies(&root)[0], Label::Hide);
        assert_eq!(captured.hidden_count(&g, &root), 2);

        // Anyone republishes a board over the same posts. No data moved.
        let fork = Board::new("official-fork", bob, Policy::Everything);
        assert_eq!(fork.hidden_count(&g, &root), 0);
    }

    #[test]
    fn posts_from_strangers_are_accepted_on_their_own_evidence() {
        let stranger = Identity::generate();
        let mut g = Graph::new();
        let cid = g
            .insert(&Post::by_person(&stranger, 0, "hello from nowhere", None))
            .unwrap();
        assert_eq!(g.get(&cid).unwrap().author, stranger.address());
    }
}
