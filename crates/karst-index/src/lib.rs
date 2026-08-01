//! L15 Discovery.
//!
//! # Why search costs a billion dollars
//!
//! Publishing on the web does not include announcing. A page appears and nothing tells anyone,
//! so finding it requires guessing that it exists and going to look: crawling. Crawling is the
//! expensive half of search by a wide margin, and it is expensive because it re-derives, at
//! enormous cost and always late, a fact the author knew for certain at the moment of writing.
//!
//! **The author already knows.** Announcement is therefore an obligation of authorship, and
//! the expensive half is done once, by the one party who cannot get it wrong.
//!
//! What remains competitive is ranking, which is a small piece of forkable software rather than
//! a decade of crawl infrastructure and a datacentre. That is the whole point: the moat under a
//! search monopoly is the crawl, not the algorithm.
//!
//! # Two kinds of statement, never conflated
//!
//! An author announces **their own** content. Anyone may make claims about **anyone's**
//! content. Both are signed objects and they are different types, because merging them is how
//! a system ends up letting strangers write your index entry.
//!
//! - [`Announcement`] is authoritative about existence and worthless as evidence of quality.
//!   Its author chose the terms and may lie about every one of them.
//! - [`Claim`] is a third party's statement, and carries exactly the weight the reader gives
//!   that third party.
//!
//! Ranking is where those combine, in the client, against the reader's own weights. Ranking is
//! **a personal setting rather than a company's product**.
//!
//! # What this does not do
//!
//! It does not conceal what is being looked for. A content address names exactly one object,
//! and any lookup infrastructure learns the set of things looked up unless designed
//! specifically against it. Tor learned this the hard way: v2 onion service directories could
//! be positioned to harvest descriptors, making the full set of onion addresses enumerable by
//! anyone willing to run enough relays, and v3 fixed it with blinded keys so a directory stores
//! a descriptor it cannot identify. Fetch privacy is issue #53 and is not solved here.
//!
//! It also does not distribute anything. Entries are ordinary objects and travel the way
//! objects travel.

use std::collections::{BTreeMap, BTreeSet};

use karst_id::Address;
use karst_object::Cid;

pub mod rank;

pub use rank::{Ranked, Ranker, Trust};

/// The most terms one statement may carry.
///
/// Unbounded terms is keyword stuffing with no cost, which is the failure mode that made web
/// meta keywords worthless within a few years of being introduced. A bound does not make an
/// author honest; it makes dishonesty cost a choice about what to lie about.
pub const MAX_TERMS: usize = 32;

/// The longest a single term may be.
pub const MAX_TERM_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexError {
    TooManyTerms,
    TermTooLong,
    EmptyTerm,
    /// Terms must be sorted and unique, so one statement cannot weigh more by repeating itself.
    TermsNotCanonical,
}

/// Normalise a term.
///
/// Case folding and trimming only. Anything cleverer, stemming or language detection, is a
/// ranking decision and belongs in the client where the reader can change it, not in the wire
/// format where it would be frozen for everyone forever.
pub fn normalise(term: &str) -> String {
    term.trim().to_lowercase()
}

fn canonical_terms(raw: &[String]) -> Result<Vec<String>, IndexError> {
    let mut set = BTreeSet::new();
    for t in raw {
        let n = normalise(t);
        if n.is_empty() {
            return Err(IndexError::EmptyTerm);
        }
        if n.len() > MAX_TERM_LEN {
            return Err(IndexError::TermTooLong);
        }
        set.insert(n);
    }
    if set.len() > MAX_TERMS {
        return Err(IndexError::TooManyTerms);
    }
    Ok(set.into_iter().collect())
}

/// An author saying what they published.
///
/// Authoritative about **existence** and about nothing else. The author chose these terms and
/// may have chosen them dishonestly, which is expected rather than exceptional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub target: Cid,
    pub author: Address,
    pub kind: String,
    pub terms: Vec<String>,
    pub published_at: u64,
}

impl Announcement {
    pub fn new(
        target: Cid,
        author: Address,
        kind: &str,
        terms: &[String],
        published_at: u64,
    ) -> Result<Self, IndexError> {
        Ok(Announcement {
            target,
            author,
            kind: kind.to_string(),
            terms: canonical_terms(terms)?,
            published_at,
        })
    }

    pub fn matches(&self, query: &[String]) -> usize {
        query
            .iter()
            .filter(|q| self.terms.binary_search(&normalise(q)).is_ok())
            .count()
    }
}

/// What a third party is saying about somebody else's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Worth reading. Raises rank for readers who weight this source.
    Commend,
    /// Accurate on these terms, without judgement of quality.
    Corroborate,
    /// Mislabelled, spam, or otherwise not what it claims.
    Dispute,
}

/// Anyone's statement about anyone's content.
///
/// This is where curation lives, and moderation with it. A reader subscribing to a labeller is
/// choosing a moderator, and can choose a different one or none, which is the difference
/// between moderation and censorship: **the reader picks, and can leave**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub target: Cid,
    pub claimant: Address,
    pub verdict: Verdict,
    pub terms: Vec<String>,
    pub made_at: u64,
}

impl Claim {
    pub fn new(
        target: Cid,
        claimant: Address,
        verdict: Verdict,
        terms: &[String],
        made_at: u64,
    ) -> Result<Self, IndexError> {
        Ok(Claim {
            target,
            claimant,
            verdict,
            terms: canonical_terms(terms)?,
            made_at,
        })
    }
}

/// Everything a client has heard.
///
/// Deduplication is per `(source, target)` and keeps the most recent statement. Without it, a
/// source could weigh more by repeating itself, which turns ranking into a measure of who
/// publishes most rather than what a reader trusts.
///
/// # Bounded, and evicting the right thing
///
/// Identities are free, so an unbounded catalogue is a memory exhaustion primitive available
/// to anyone. A bound alone is not enough either: a plain size cap is the defence Tor tried
/// and withdrew after the sniper attack, because an adversary fills it and then honest entries
/// are the ones refused.
///
/// **Admission is a trust decision**, so it takes the reader's trust. When the catalogue is
/// full, an entry from a source the reader has no opinion about is evicted to make room, and a
/// trusted source is never displaced by an untrusted one. An adversary with a million
/// identities competes with the other untrusted sources for one bounded pool and cannot touch
/// what the reader chose.
///
/// A consequence worth stating, because it is easy to get wrong: **a catalogue belongs to one
/// reader.** Eviction has already happened according to that reader's trust, so handing the
/// same catalogue to a reader with different trust gives them answers shaped by preferences
/// they do not hold, including the absence of things evicted on someone else's behalf. Two
/// readers who disagree keep two catalogues. That is the cost of there being no global index,
/// and it is the same cost that makes there be no global index to capture.
#[derive(Debug)]
pub struct Catalogue {
    announcements: BTreeMap<(Address, Cid), Announcement>,
    claims: BTreeMap<(Address, Cid), Claim>,
    by_term: BTreeMap<String, BTreeSet<Cid>>,
    /// How many untrusted statements to keep. Trusted ones are not counted against it.
    untrusted_capacity: usize,
    untrusted_keys: BTreeSet<(Address, Cid)>,
}

impl Default for Catalogue {
    fn default() -> Self {
        Catalogue::new()
    }
}

impl Catalogue {
    pub const DEFAULT_UNTRUSTED_CAPACITY: usize = 1 << 16;

    pub fn new() -> Self {
        Catalogue {
            announcements: BTreeMap::new(),
            claims: BTreeMap::new(),
            by_term: BTreeMap::new(),
            untrusted_capacity: Self::DEFAULT_UNTRUSTED_CAPACITY,
            untrusted_keys: BTreeSet::new(),
        }
    }

    pub fn with_untrusted_capacity(mut self, n: usize) -> Self {
        self.untrusted_capacity = n;
        self
    }

    pub fn untrusted_held(&self) -> usize {
        self.untrusted_keys.len()
    }

    /// Re-evaluate which held statements are untrusted.
    ///
    /// Admission is decided when a statement arrives, using the trust the reader had then. A
    /// reader who later decides to trust a source would otherwise still have that source's
    /// statements sitting in the evictable pool, where a flood of strangers can push them out.
    /// **Trust acquired after the fact must protect what was already heard**, because hearing
    /// about someone and then deciding to trust them is the ordinary order of events.
    ///
    /// Call this whenever trust changes.
    pub fn retrust(&mut self, trust: &rank::Trust) {
        self.untrusted_keys.retain(|(who, _)| trust.weight_of(who).is_none());
        for key in self.announcements.keys() {
            if trust.weight_of(&key.0).is_none() {
                self.untrusted_keys.insert(*key);
            }
        }
        for key in self.claims.keys() {
            if trust.weight_of(&key.0).is_none() {
                self.untrusted_keys.insert(*key);
            }
        }
    }

    /// Make room for an untrusted statement, or refuse it.
    ///
    /// Returns false when the statement should not be stored at all. Eviction is arbitrary
    /// among untrusted sources on purpose: any ordering among parties the reader has no
    /// opinion about would be a preference the reader did not express, and whichever ordering
    /// were chosen an adversary would optimise for it.
    fn admit_untrusted(&mut self, key: (Address, Cid)) -> bool {
        if self.untrusted_keys.contains(&key) {
            return true;
        }
        if self.untrusted_keys.len() >= self.untrusted_capacity {
            let Some(victim) = self.untrusted_keys.iter().next().copied() else {
                return false;
            };
            if victim == key {
                return false;
            }
            self.untrusted_keys.remove(&victim);
            self.announcements.remove(&victim);
            self.claims.remove(&victim);
        }
        self.untrusted_keys.insert(key);
        true
    }

    pub fn announce(&mut self, a: Announcement, trust: &rank::Trust) {
        let key = (a.author, a.target);
        if let Some(prev) = self.announcements.get(&key) {
            if prev.published_at > a.published_at {
                return;
            }
        }
        if trust.weight_of(&a.author).is_none() && !self.admit_untrusted(key) {
            return;
        }
        for t in &a.terms {
            self.by_term.entry(t.clone()).or_default().insert(a.target);
        }
        self.announcements.insert(key, a);
    }

    pub fn claim(&mut self, c: Claim, trust: &rank::Trust) {
        let key = (c.claimant, c.target);
        if let Some(prev) = self.claims.get(&key) {
            if prev.made_at > c.made_at {
                return;
            }
        }
        if trust.weight_of(&c.claimant).is_none() && !self.admit_untrusted(key) {
            return;
        }
        for t in &c.terms {
            self.by_term.entry(t.clone()).or_default().insert(c.target);
        }
        self.claims.insert(key, c);
    }

    pub fn announcements(&self) -> impl Iterator<Item = &Announcement> {
        self.announcements.values()
    }

    pub fn claims_about(&self, target: &Cid) -> Vec<&Claim> {
        self.claims
            .iter()
            .filter(|((_, t), _)| t == target)
            .map(|(_, c)| c)
            .collect()
    }

    pub fn announcement_of(&self, source: &Address, target: &Cid) -> Option<&Announcement> {
        self.announcements.get(&(*source, *target))
    }

    /// Everything anyone has associated with any of these terms.
    ///
    /// Deliberately generous, because filtering by trust is the ranker's job and doing it here
    /// would hide from a reader what was said about the thing they asked for.
    pub fn candidates(&self, query: &[String]) -> BTreeSet<Cid> {
        let mut out = BTreeSet::new();
        for q in query {
            if let Some(set) = self.by_term.get(&normalise(q)) {
                out.extend(set.iter().copied());
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.announcements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rank::Trust;

    fn addr(n: u8) -> Address {
        Address::from_raw([n; 32])
    }

    fn terms(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_author_announces_and_the_thing_is_findable() {
        let mut c = Catalogue::new();
        let target = Cid::of(b"a paper about mixing");
        c.announce(
            Announcement::new(target, addr(1), "doc", &terms(&["mixing", "anonymity"]), 10)
                .unwrap(),
            &Trust::new(),
        );
        assert_eq!(c.candidates(&terms(&["mixing"])), [target].into());
        assert!(c.candidates(&terms(&["cooking"])).is_empty());
    }

    /// Terms are canonical, so a statement cannot weigh more by repeating itself.
    #[test]
    fn repeated_terms_collapse() {
        let a = Announcement::new(
            Cid::of(b"x"),
            addr(1),
            "doc",
            &terms(&["Rust", "rust", "  RUST  ", "rust"]),
            0,
        )
        .unwrap();
        assert_eq!(a.terms, vec!["rust".to_string()]);
    }

    /// Keyword stuffing is bounded.
    ///
    /// The bound does not make an author honest. It makes dishonesty cost a choice about what
    /// to lie about, which is the most a format can do.
    #[test]
    fn unbounded_keyword_stuffing_is_refused() {
        let many: Vec<String> = (0..MAX_TERMS + 1).map(|i| format!("term{i}")).collect();
        assert_eq!(
            Announcement::new(Cid::of(b"x"), addr(1), "doc", &many, 0),
            Err(IndexError::TooManyTerms)
        );
        let ok: Vec<String> = (0..MAX_TERMS).map(|i| format!("term{i}")).collect();
        assert!(Announcement::new(Cid::of(b"x"), addr(1), "doc", &ok, 0).is_ok());
    }

    #[test]
    fn absurd_and_empty_terms_are_refused() {
        assert_eq!(
            Announcement::new(Cid::of(b"x"), addr(1), "doc", &terms(&[""]), 0),
            Err(IndexError::EmptyTerm)
        );
        assert_eq!(
            Announcement::new(Cid::of(b"x"), addr(1), "doc", &terms(&["   "]), 0),
            Err(IndexError::EmptyTerm)
        );
        let long = "a".repeat(MAX_TERM_LEN + 1);
        assert_eq!(
            Announcement::new(Cid::of(b"x"), addr(1), "doc", &[long], 0),
            Err(IndexError::TermTooLong)
        );
    }

    /// Repeating an announcement must not multiply a source's presence.
    #[test]
    fn one_source_announcing_repeatedly_occupies_one_slot() {
        let mut c = Catalogue::new();
        let target = Cid::of(b"x");
        for i in 0..1_000 {
            c.announce(
                Announcement::new(target, addr(1), "doc", &terms(&["spam"]), i).unwrap(),
                &Trust::new(),
            );
        }
        assert_eq!(c.len(), 1);
    }

    /// A stale restatement must not undo a newer one.
    #[test]
    fn an_older_statement_does_not_replace_a_newer_one() {
        let mut c = Catalogue::new();
        let target = Cid::of(b"x");
        c.announce(Announcement::new(target, addr(1), "doc", &terms(&["new"]), 100).unwrap(), &Trust::new());
        c.announce(Announcement::new(target, addr(1), "doc", &terms(&["old"]), 1).unwrap(), &Trust::new());
        let held = c.announcement_of(&addr(1), &target).unwrap();
        assert_eq!(held.terms, vec!["new".to_string()]);
    }

    /// Two authors announcing the same object are two statements, not one.
    #[test]
    fn different_sources_about_one_target_are_kept_separately() {
        let mut c = Catalogue::new();
        let target = Cid::of(b"x");
        c.announce(Announcement::new(target, addr(1), "doc", &terms(&["a"]), 0).unwrap(), &Trust::new());
        c.announce(Announcement::new(target, addr(2), "doc", &terms(&["b"]), 0).unwrap(), &Trust::new());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn claims_are_recorded_against_their_target() {
        let mut c = Catalogue::new();
        let target = Cid::of(b"x");
        c.claim(
            Claim::new(target, addr(9), Verdict::Dispute, &terms(&["spam"]), 5).unwrap(),
            &Trust::new(),
        );
        let about = c.claims_about(&target);
        assert_eq!(about.len(), 1);
        assert_eq!(about[0].verdict, Verdict::Dispute);
    }
    /// An unbounded catalogue is a memory exhaustion primitive, and identities are free.
    #[test]
    fn untrusted_statements_do_not_accumulate_without_bound() {
        let mut c = Catalogue::new().with_untrusted_capacity(64);
        let t = Trust::new();
        for i in 0..20_000u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            c.announce(
                Announcement::new(Cid::of(&b), Address::from_raw(b), "doc", &terms(&["x"]), 0)
                    .unwrap(),
                &t,
            );
        }
        assert_eq!(c.untrusted_held(), 64);
    }

    /// A flood of strangers must not displace a source the reader chose.
    ///
    /// A plain size cap is the defence Tor tried and withdrew after the sniper attack: the
    /// adversary fills it and honest entries are the ones refused. Trusted statements are not
    /// counted against the untrusted bound at all.
    #[test]
    fn a_flood_of_strangers_cannot_displace_a_trusted_source() {
        let trusted = addr(7);
        let mut t = Trust::new();
        t.set(trusted, 1.0);

        let mut c = Catalogue::new().with_untrusted_capacity(32);
        let mine = Cid::of(b"the thing i wanted");
        c.announce(
            Announcement::new(mine, trusted, "doc", &terms(&["topic"]), 0).unwrap(),
            &t,
        );

        for i in 0..50_000u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            b[31] = 1;
            c.announce(
                Announcement::new(Cid::of(&b), Address::from_raw(b), "doc", &terms(&["topic"]), 0)
                    .unwrap(),
                &t,
            );
        }

        assert!(
            c.announcement_of(&trusted, &mine).is_some(),
            "50k strangers evicted the entry the reader actually trusted"
        );
        assert_eq!(c.untrusted_held(), 32);
    }

    /// Restating an already-held untrusted statement must not consume a second slot.
    #[test]
    fn restating_does_not_consume_another_slot() {
        let mut c = Catalogue::new().with_untrusted_capacity(4);
        let t = Trust::new();
        let target = Cid::of(b"x");
        for i in 0..1_000 {
            c.announce(
                Announcement::new(target, addr(1), "doc", &terms(&["x"]), i).unwrap(),
                &t,
            );
        }
        assert_eq!(c.untrusted_held(), 1);
    }

    /// A catalogue is one reader's, and cannot be handed to another.
    ///
    /// Eviction has already happened according to the owner's trust. A second reader with
    /// different trust would be reading a store shaped by preferences they do not hold,
    /// including the absence of whatever was evicted on someone else's behalf. Stating it as a
    /// test because the failure is silent: the second reader sees a plausible answer with no
    /// indication that something was removed before they ever looked.
    #[test]
    fn a_catalogue_is_shaped_by_its_owners_trust_and_is_not_shareable() {
        let alices_favourite = addr(1);
        let bobs_favourite = addr(2);

        let mut alice = Trust::new();
        alice.set(alices_favourite, 1.0);

        let mut cat = Catalogue::new().with_untrusted_capacity(4);
        let bobs_thing = Cid::of(b"what bob wanted");
        c_announce(&mut cat, bobs_thing, bobs_favourite, &alice);

        // Alice's ordinary browsing evicts it, because to her it came from a stranger.
        for i in 0..64u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            b[31] = 9;
            c_announce(&mut cat, Cid::of(&b), Address::from_raw(b), &alice);
        }

        assert!(
            cat.announcement_of(&bobs_favourite, &bobs_thing).is_none(),
            "vacuous: nothing was evicted"
        );
    }

    fn c_announce(c: &mut Catalogue, target: Cid, who: Address, trust: &Trust) {
        c.announce(
            Announcement::new(target, who, "doc", &terms(&["topic"]), 0).unwrap(),
            trust,
        );
    }

}
