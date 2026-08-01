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

use karst_id::{Address, Identity};
use karst_object::{Cid, Dec, Enc, Object, ObjectError};

/// Object kinds. A statement is an ordinary signed object, so it travels, verifies and
/// supersedes exactly like everything else at L6.
pub const ANNOUNCE_KIND: &str = "karst.index.announce.v1";
pub const CLAIM_KIND: &str = "karst.index.claim.v1";

pub mod complete;
pub mod rank;

pub use complete::{Census, CensusMonitor, Completeness};
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
    /// The signature did not check out, or the object was not a statement at all.
    Unsigned,
    Malformed,
}

impl From<ObjectError> for IndexError {
    fn from(_: ObjectError) -> Self {
        IndexError::Unsigned
    }
}

/// The key range covering every statement about one target.
fn span(target: &Cid) -> std::ops::RangeInclusive<Key> {
    (*target, Address::from_raw([0u8; 32]))..=(*target, Address::from_raw([0xffu8; 32]))
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
    /// Build an unsigned statement, for signing.
    ///
    /// `author` is what the caller intends to sign as, and it is worth nothing until an object
    /// carrying it is verified. Only [`Announcement::from_object`] produces one a catalogue
    /// will accept.
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

    /// Sign it.
    pub fn publish(&self, author: &Identity, seq: u64) -> Object {
        let mut e = Enc::new();
        e.cid(&self.target)
            .str(&self.kind)
            .u64(self.published_at)
            .u64(self.terms.len() as u64);
        for t in &self.terms {
            e.str(t);
        }
        Object::create(author, ANNOUNCE_KIND, seq, e.finish(), None)
    }

    /// Recover it from a signed object, or refuse.
    ///
    /// The author is taken from the **verified signature** and never from the payload. An
    /// index whose entries name their own author is an index anyone can write in anyone's
    /// name, which would make every trust weight in this crate meaningless: a reader weights
    /// sources, and a source that can be impersonated is not a source.
    pub fn from_object(obj: &Object) -> Result<Verified<Announcement>, IndexError> {
        if obj.kind != ANNOUNCE_KIND {
            return Err(IndexError::Malformed);
        }
        let author = obj.verify()?;
        let mut d = Dec::new(&obj.payload);
        let target = d.cid().map_err(|_| IndexError::Malformed)?;
        let kind = d.str().map_err(|_| IndexError::Malformed)?;
        let published_at = d.u64().map_err(|_| IndexError::Malformed)?;
        let n = d.u64().map_err(|_| IndexError::Malformed)? as usize;
        if n > MAX_TERMS {
            return Err(IndexError::TooManyTerms);
        }
        let mut raw = Vec::with_capacity(n);
        for _ in 0..n {
            raw.push(d.str().map_err(|_| IndexError::Malformed)?);
        }
        d.end().map_err(|_| IndexError::Malformed)?;
        let terms = canonical_terms(&raw)?;
        // Canonicalising must be idempotent on the wire, or two encodings of one statement
        // would carry different weight.
        if terms != raw {
            return Err(IndexError::TermsNotCanonical);
        }
        Ok(Verified(Announcement {
            target,
            author,
            kind,
            terms,
            published_at,
        }))
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
#[repr(u8)]
pub enum Verdict {
    /// Worth reading. Raises rank for readers who weight this source.
    Commend = 0,
    /// Accurate on these terms, without judgement of quality.
    Corroborate = 1,
    /// Mislabelled, spam, or otherwise not what it claims.
    Dispute = 2,
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

    pub fn publish(&self, claimant: &Identity, seq: u64) -> Object {
        let mut e = Enc::new();
        e.cid(&self.target)
            .u8(self.verdict as u8)
            .u64(self.made_at)
            .u64(self.terms.len() as u64);
        for t in &self.terms {
            e.str(t);
        }
        Object::create(claimant, CLAIM_KIND, seq, e.finish(), None)
    }

    /// As with [`Announcement::from_object`], the claimant comes from the signature.
    pub fn from_object(obj: &Object) -> Result<Verified<Claim>, IndexError> {
        if obj.kind != CLAIM_KIND {
            return Err(IndexError::Malformed);
        }
        let claimant = obj.verify()?;
        let mut d = Dec::new(&obj.payload);
        let target = d.cid().map_err(|_| IndexError::Malformed)?;
        let verdict = match d.u8().map_err(|_| IndexError::Malformed)? {
            0 => Verdict::Commend,
            1 => Verdict::Corroborate,
            2 => Verdict::Dispute,
            _ => return Err(IndexError::Malformed),
        };
        let made_at = d.u64().map_err(|_| IndexError::Malformed)?;
        let n = d.u64().map_err(|_| IndexError::Malformed)? as usize;
        if n > MAX_TERMS {
            return Err(IndexError::TooManyTerms);
        }
        let mut raw = Vec::with_capacity(n);
        for _ in 0..n {
            raw.push(d.str().map_err(|_| IndexError::Malformed)?);
        }
        d.end().map_err(|_| IndexError::Malformed)?;
        let terms = canonical_terms(&raw)?;
        if terms != raw {
            return Err(IndexError::TermsNotCanonical);
        }
        Ok(Verified(Claim {
            target,
            claimant,
            verdict,
            terms,
            made_at,
        }))
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
/// A statement whose signature has been checked.
///
/// The only way to build one is [`Announcement::from_object`] or [`Claim::from_object`], both
/// of which verify. A catalogue accepts nothing else, so "did anyone check this signature" is
/// answered by the type rather than by remembering to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Statements are keyed by **target first**.
///
/// The obvious key is `(source, target)`, and it is wrong. Ranking asks "what has anyone said
/// about this object", and under that key the answer requires scanning every statement in the
/// catalogue. Search then costs candidates times catalogue, which is quadratic for any query
/// whose terms are common. Measured before the fix: 21.7 seconds for one query over 64,000
/// objects, growing 37x per 4x growth in corpus.
///
/// Keyed by target, the same question is a range scan.
type Key = (Cid, Address);

#[derive(Debug)]
pub struct Catalogue {
    announcements: BTreeMap<Key, Announcement>,
    claims: BTreeMap<Key, Claim>,
    by_term: BTreeMap<String, BTreeSet<Cid>>,
    /// How many untrusted statements to keep. Trusted ones are not counted against it.
    untrusted_capacity: usize,
    untrusted_keys: BTreeSet<Key>,
    /// Which untrusted keys each source holds, so eviction can charge the biggest occupant.
    untrusted_by_source: BTreeMap<Address, BTreeSet<Key>>,
    /// Occupancy ordered for a cheap maximum.
    occupancy: BTreeSet<(usize, Address)>,
    rng: rand::rngs::StdRng,
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
            untrusted_by_source: BTreeMap::new(),
            occupancy: BTreeSet::new(),
            rng: <rand::rngs::StdRng as rand::SeedableRng>::from_entropy(),
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
        // Rebuild every structure that indexes the untrusted pool, not just the key set.
        // Leaving the per-source occupancy behind would make the quota and eviction disagree
        // with what is actually held, which is how a bound stops binding.
        self.untrusted_keys.clear();
        self.untrusted_by_source.clear();
        self.occupancy.clear();
        let keys: Vec<Key> = self
            .announcements
            .keys()
            .chain(self.claims.keys())
            .copied()
            .collect();
        for key in keys {
            if trust.weight_of(&key.1).is_none() {
                self.track_untrusted(key);
            }
        }
    }

    /// Drop a target from the term index for any term nothing says about it any more.
    ///
    /// Eviction removed statements and left their terms behind, so the term index grew without
    /// bound while the statement store stayed bounded. The bound was therefore not a bound: it
    /// moved the growth rather than stopping it, and `candidates` went on returning objects
    /// the catalogue no longer held anything about.
    ///
    /// This is the shape of partial fix that eMule shipped, where a per-subnet limit on
    /// identities was enforced when adding contacts and not during lookup, leaving the
    /// mechanism it was meant to stop working perfectly well (Kohnen, Leske, Rathgeb, IFIP
    /// Networking 2009). **A bound applied at one stage and not another is not a bound.**
    fn forget_terms(&mut self, target: &Cid, terms: &[String]) {
        for t in terms {
            let still_claimed = self
                .announcements
                .range(span(target))
                .any(|(_, a)| a.terms.iter().any(|x| x == t))
                || self
                    .claims
                    .range(span(target))
                    .any(|(_, c)| c.terms.iter().any(|x| x == t));
            if still_claimed {
                continue;
            }
            if let Some(set) = self.by_term.get_mut(t) {
                set.remove(target);
                if set.is_empty() {
                    self.by_term.remove(t);
                }
            }
        }
    }

    /// How many distinct terms the index holds. Bounded only by what is still held.
    pub fn terms_indexed(&self) -> usize {
        self.by_term.len()
    }

    /// Make room for an untrusted statement, or refuse it.
    ///
    /// Returns false when the statement should not be stored at all. Eviction is arbitrary
    /// among untrusted sources on purpose: any ordering among parties the reader has no
    /// opinion about would be a preference the reader did not express, and whichever ordering
    /// were chosen an adversary would optimise for it.
    fn admit_untrusted(&mut self, key: Key) -> bool {
        if self.untrusted_keys.contains(&key) {
            return true;
        }
        // The quota binds always, not only once the pool is full. Enforcing it at capacity
        // alone let one source fill every slot first and then defend what it had taken.
        let quota = self.per_source_quota();
        let mine = self
            .untrusted_by_source
            .get(&key.1)
            .map_or(0, |set| set.len());
        let victim = if mine >= quota {
            self.random_from(&key.1)
        } else if self.untrusted_keys.len() >= self.untrusted_capacity {
            self.choose_victim(&key)
        } else {
            None
        };

        if let Some(victim) = victim {
            if victim == key {
                return false;
            }
            self.drop_untrusted_key(&victim);
            let a = self.announcements.remove(&victim);
            let c = self.claims.remove(&victim);
            let mut terms: Vec<String> = Vec::new();
            if let Some(a) = a {
                terms.extend(a.terms);
            }
            if let Some(c) = c {
                terms.extend(c.terms);
            }
            self.forget_terms(&victim.0, &terms);
        } else if self.untrusted_keys.len() >= self.untrusted_capacity {
            return false;
        }
        self.track_untrusted(key);
        true
    }

    /// A random key held by one source.
    fn random_from(&mut self, who: &Address) -> Option<Key> {
        use rand::Rng;
        let set = self.untrusted_by_source.get(who)?;
        if set.is_empty() {
            return None;
        }
        let n = self.rng.gen_range(0..set.len());
        set.iter().nth(n).copied()
    }

    /// Pick what to evict.
    ///
    /// Not the smallest key. Keys are `(Cid, Address)` and a Cid is the hash of content its
    /// author chose, so evicting the minimum hands the eviction order to whoever is writing
    /// the content: grind a nonce until the digest starts with `0xff` and the entry is
    /// permanently unevictable while every honest entry is driven out. **An ordering an
    /// adversary can compute is an ordering an adversary controls.**
    ///
    /// Charge the largest occupant instead, breaking ties at random. Holding many slots is
    /// what a flood does and what a single honest source does not, so the cost falls where the
    /// pressure comes from, and grinding a digest changes nothing because it does not change
    /// how many slots a source holds.
    fn choose_victim(&mut self, incoming: &Key) -> Option<Key> {
        use rand::Rng;
        let (count, worst) = self.occupancy.iter().next_back().copied()?;
        // An incoming statement from the current largest occupant is itself the thing to
        // refuse, so a flood cannot displace others once it is already the heaviest.
        if worst == incoming.1 && count >= self.per_source_quota() {
            return Some(*incoming);
        }
        let set = self.untrusted_by_source.get(&worst)?;
        if set.is_empty() {
            return None;
        }
        let n = self.rng.gen_range(0..set.len());
        set.iter().nth(n).copied()
    }

    /// The most slots one untrusted source may hold.
    ///
    /// Random eviction alone is not enough: a source holding N of H slots keeps N/(N+H) of the
    /// pool, so an adversary willing to keep publishing still crowds everyone out slowly. A
    /// quota caps that directly.
    fn per_source_quota(&self) -> usize {
        (self.untrusted_capacity / 16).max(1)
    }

    fn track_untrusted(&mut self, key: Key) {
        self.untrusted_keys.insert(key);
        let set = self.untrusted_by_source.entry(key.1).or_default();
        let before = set.len();
        set.insert(key);
        let after = set.len();
        if before > 0 {
            self.occupancy.remove(&(before, key.1));
        }
        self.occupancy.insert((after, key.1));
    }

    fn drop_untrusted_key(&mut self, key: &Key) {
        self.untrusted_keys.remove(key);
        if let Some(set) = self.untrusted_by_source.get_mut(&key.1) {
            let before = set.len();
            set.remove(key);
            let after = set.len();
            self.occupancy.remove(&(before, key.1));
            if after > 0 {
                self.occupancy.insert((after, key.1));
            } else {
                self.untrusted_by_source.remove(&key.1);
            }
        }
    }

    pub fn announce(&mut self, a: Verified<Announcement>, trust: &rank::Trust) {
        let a = a.into_inner();
        let key = (a.target, a.author);
        let mut superseded: Option<Vec<String>> = None;
        if let Some(prev) = self.announcements.get(&key) {
            if prev.published_at > a.published_at {
                return;
            }
            superseded = Some(prev.terms.clone());
        }
        if superseded.is_none() && trust.weight_of(&a.author).is_none() && !self.admit_untrusted(key)
        {
            return;
        }
        for t in &a.terms {
            self.by_term.entry(t.clone()).or_default().insert(a.target);
        }
        let target = a.target;
        self.announcements.insert(key, a);
        // Replacing a statement drops the terms it used to assert. Pruning only on eviction
        // left one identity holding one slot able to grow the term index without limit by
        // restating with fresh terms, which is the same bound-at-one-stage-only mistake the
        // eviction path already made once.
        if let Some(old) = superseded {
            self.forget_terms(&target, &old);
        }
    }

    pub fn claim(&mut self, c: Verified<Claim>, trust: &rank::Trust) {
        let c = c.into_inner();
        let key = (c.target, c.claimant);
        let mut superseded: Option<Vec<String>> = None;
        if let Some(prev) = self.claims.get(&key) {
            if prev.made_at > c.made_at {
                return;
            }
            superseded = Some(prev.terms.clone());
        }
        if superseded.is_none()
            && trust.weight_of(&c.claimant).is_none()
            && !self.admit_untrusted(key)
        {
            return;
        }
        for t in &c.terms {
            self.by_term.entry(t.clone()).or_default().insert(c.target);
        }
        let target = c.target;
        self.claims.insert(key, c);
        if let Some(old) = superseded {
            self.forget_terms(&target, &old);
        }
    }

    pub fn announcements(&self) -> impl Iterator<Item = &Announcement> {
        self.announcements.values()
    }

    /// Everything said about one object, as a range scan rather than a catalogue sweep.
    pub fn claims_about(&self, target: &Cid) -> impl Iterator<Item = &Claim> {
        self.claims.range(span(target)).map(|(_, c)| c)
    }

    /// Every announcement of one object, as a range scan.
    pub fn announcements_about(&self, target: &Cid) -> impl Iterator<Item = &Announcement> {
        self.announcements.range(span(target)).map(|(_, a)| a)
    }

    pub fn announcement_of(&self, source: &Address, target: &Cid) -> Option<&Announcement> {
        self.announcements.get(&(*target, *source))
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
    use karst_id::Identity;

    fn ident(n: u32) -> Identity {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        Identity::from_seed(seed)
    }

    fn addr(n: u32) -> Address {
        ident(n).address()
    }

    /// Publish and verify. Nothing reaches a catalogue any other way.
    fn ann(
        target: Cid,
        who: u32,
        kind: &str,
        terms: &[String],
        at: u64,
    ) -> Verified<Announcement> {
        let id = ident(who);
        let obj = Announcement::new(target, id.address(), kind, terms, at)
            .unwrap()
            .publish(&id, at);
        Announcement::from_object(&obj).unwrap()
    }

    fn clm(
        target: Cid,
        who: u32,
        verdict: Verdict,
        terms: &[String],
        at: u64,
    ) -> Verified<Claim> {
        let id = ident(who);
        let obj = Claim::new(target, id.address(), verdict, terms, at)
            .unwrap()
            .publish(&id, at);
        Claim::from_object(&obj).unwrap()
    }

    /// Same, for tests that build a distinct source per iteration from a byte pattern.
    fn ann_raw(
        target: Cid,
        seed: [u8; 32],
        kind: &str,
        terms: &[String],
        at: u64,
    ) -> Verified<Announcement> {
        let id = Identity::from_seed(seed);
        let obj = Announcement::new(target, id.address(), kind, terms, at)
            .unwrap()
            .publish(&id, at);
        Announcement::from_object(&obj).unwrap()
    }


    fn terms(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_author_announces_and_the_thing_is_findable() {
        let mut c = Catalogue::new();
        let target = Cid::of(b"a paper about mixing");
        c.announce(
            ann(target, 1, "doc", &terms(&["mixing", "anonymity"]), 10),
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
                ann(target, 1, "doc", &terms(&["spam"]), i),
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
        c.announce(ann(target, 1, "doc", &terms(&["new"]), 100), &Trust::new());
        c.announce(ann(target, 1, "doc", &terms(&["old"]), 1), &Trust::new());
        let held = c.announcement_of(&addr(1), &target);
        assert_eq!(held.unwrap().terms, vec!["new".to_string()]);
    }

    /// Two authors announcing the same object are two statements, not one.
    #[test]
    fn different_sources_about_one_target_are_kept_separately() {
        let mut c = Catalogue::new();
        let target = Cid::of(b"x");
        c.announce(ann(target, 1, "doc", &terms(&["a"]), 0), &Trust::new());
        c.announce(ann(target, 2, "doc", &terms(&["b"]), 0), &Trust::new());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn claims_are_recorded_against_their_target() {
        let mut c = Catalogue::new();
        let target = Cid::of(b"x");
        c.claim(
            clm(target, 9, Verdict::Dispute, &terms(&["spam"]), 5),
            &Trust::new(),
        );
        let about: Vec<&Claim> = c.claims_about(&target).collect();
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
                ann_raw(Cid::of(&b), b, "doc", &terms(&["x"]), 0),
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
        let trusted = 7u32;
        let mut t = Trust::new();
        t.set(addr(trusted), 1.0);

        let mut c = Catalogue::new().with_untrusted_capacity(32);
        let mine = Cid::of(b"the thing i wanted");
        c.announce(
            ann(mine, trusted, "doc", &terms(&["topic"]), 0),
            &t,
        );

        for i in 0..50_000u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            b[31] = 1;
            c.announce(
                ann_raw(Cid::of(&b), b, "doc", &terms(&["topic"]), 0),
                &t,
            );
        }

        assert!(
            c.announcement_of(&addr(trusted), &mine).is_some(),
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
                ann(target, 1, "doc", &terms(&["x"]), i),
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
        let alices_favourite = 1u32;
        let bobs_favourite = 2u32;

        let mut alice = Trust::new();
        alice.set(addr(alices_favourite), 1.0);

        let mut cat = Catalogue::new().with_untrusted_capacity(4);
        let bobs_thing = Cid::of(b"what bob wanted");
        c_announce(&mut cat, bobs_thing, bobs_favourite, &alice);

        // Alice's ordinary browsing evicts it, because to her it came from a stranger.
        for i in 0..64u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            b[31] = 9;
            c_announce_raw(&mut cat, Cid::of(&b), b, &alice);
        }

        assert!(
            cat.announcement_of(&addr(bobs_favourite), &bobs_thing).is_none(),
            "vacuous: nothing was evicted"
        );
    }

    fn c_announce(c: &mut Catalogue, target: Cid, who: u32, trust: &Trust) {
        c.announce(ann(target, who, "doc", &terms(&["topic"]), 0), trust);
    }

    fn c_announce_raw(c: &mut Catalogue, target: Cid, seed: [u8; 32], trust: &Trust) {
        c.announce(ann_raw(target, seed, "doc", &terms(&["topic"]), 0), trust);
    }

    /// The term index must shrink when statements are evicted.
    ///
    /// The statement store was bounded and the term index was not, so eviction removed the
    /// statements and left their terms behind. Memory grew without limit at exactly the rate
    /// an adversary chose, and `candidates` kept returning objects the catalogue held nothing
    /// about, inflating the work of every subsequent search.
    ///
    /// A bound applied at one stage and not another is not a bound.
    #[test]
    fn evicting_a_statement_also_forgets_its_terms() {
        let t = Trust::new();
        let mut c = Catalogue::new().with_untrusted_capacity(64);
        for i in 0..20_000u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            c.announce(
                ann_raw(Cid::of(&b), b, "doc", &[format!("term{i}")], 0),
                &t,
            );
        }
        assert_eq!(c.untrusted_held(), 64);
        assert!(
            c.terms_indexed() <= 64,
            "the statement store held 64 and the term index held {}",
            c.terms_indexed()
        );
    }

    /// Evicted objects must stop being candidates.
    ///
    /// Otherwise every search pays to consider objects nothing is known about, which is the
    /// quadratic behaviour returning by another door.
    #[test]
    fn evicted_objects_stop_being_candidates() {
        let t = Trust::new();
        let mut c = Catalogue::new().with_untrusted_capacity(64);
        for i in 0..20_000u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            c.announce(
                ann_raw(Cid::of(&b), b, "doc", &terms(&["x"]), 0),
                &t,
            );
        }
        assert_eq!(
            c.candidates(&terms(&["x"])).len(),
            64,
            "candidates outnumbered the statements the catalogue actually holds"
        );
    }

    /// A term shared by a surviving statement must not be forgotten with an evicted one.
    #[test]
    fn a_term_still_in_use_survives_an_eviction_that_mentioned_it() {
        let keeper = 200u32;
        let mut t = Trust::new();
        t.set(addr(keeper), 1.0);
        let mut c = Catalogue::new().with_untrusted_capacity(2);
        let target = Cid::of(b"shared");

        c.announce(
            ann(target, keeper, "doc", &terms(&["shared"]), 0),
            &t,
        );
        // An untrusted statement about the same target, using the same term, then evicted.
        c.announce(
            ann(target, 1, "doc", &terms(&["shared"]), 0),
            &t,
        );
        for i in 0..50u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            b[31] = 3;
            c.announce(
                ann_raw(Cid::of(&b), b, "doc", &terms(&["other"]), 0),
                &t,
            );
        }
        assert!(
            c.candidates(&terms(&["shared"])).contains(&target),
            "a trusted statement's term was forgotten when an untrusted one was evicted"
        );
    }

    /// Nobody may write an index entry in somebody else's name.
    ///
    /// This is the defect the whole trust model rested on and did not have. The author was a
    /// caller-supplied field and nothing verified a signature, so an adversary could mint
    /// entries as any source a reader trusted, and every weight in this crate would have been
    /// applied to whatever the adversary wrote. **A source that can be impersonated is not a
    /// source.** The author now comes from the verified signature and never from the payload.
    #[test]
    fn an_entry_cannot_be_minted_in_someone_elses_name() {
        let victim = ident(1);
        let forger = ident(2);

        // The forger writes the victim's address into the payload and signs with their own key.
        let forged = Announcement::new(Cid::of(b"malware"), victim.address(), "doc", &terms(&["safe"]), 0)
            .unwrap()
            .publish(&forger, 0);

        let recovered = Announcement::from_object(&forged).unwrap();
        assert_eq!(
            recovered.get().author,
            forger.address(),
            "the claimed author survived verification"
        );
        assert_ne!(recovered.get().author, victim.address());

        // And a reader trusting the victim gives the forgery nothing.
        let mut t = Trust::new();
        t.set(victim.address(), 1.0);
        let mut cat = Catalogue::new();
        cat.announce(recovered, &t);
        let hits = crate::Ranker::new(t).search(&cat, &terms(&["safe"]));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].trusted_support, 0, "a forgery was counted as trusted");
    }

    /// A tampered object must not decode at all.
    #[test]
    fn a_tampered_statement_is_refused() {
        let id = ident(1);
        let obj = Announcement::new(Cid::of(b"x"), id.address(), "doc", &terms(&["a"]), 0)
            .unwrap()
            .publish(&id, 0);
        let mut bad = obj.clone();
        bad.payload[0] ^= 1;
        assert_eq!(
            Announcement::from_object(&bad).unwrap_err(),
            IndexError::Unsigned
        );
        // And a claim object is not an announcement.
        let c = Claim::new(Cid::of(b"x"), id.address(), Verdict::Dispute, &terms(&["a"]), 0)
            .unwrap()
            .publish(&id, 0);
        assert_eq!(
            Announcement::from_object(&c).unwrap_err(),
            IndexError::Malformed
        );
    }

    /// Ground content addresses must be evictable, and honest entries must survive.
    ///
    /// The previous version counted, immediately after each insert, whether that insert had
    /// landed. A fresh source holds no slots, so it never trips the quota and is always
    /// stored; the counter was measuring "was the thing I just inserted inserted" and read
    /// 200/200 under **every** eviction rule, including the minimum-key rule the fix exists to
    /// replace. It would have passed with the defect fully restored.
    ///
    /// What has to be measured is what survives at the end.
    #[test]
    fn ground_content_addresses_do_not_hold_the_pool_against_honest_entries() {
        let t = Trust::new();
        let mut c = Catalogue::new().with_untrusted_capacity(64);

        // The adversary grinds for the highest digests it can find.
        let mut ground: Vec<Cid> = Vec::new();
        let mut n = 0u32;
        while ground.len() < 200 {
            let cid = Cid::of(&n.to_le_bytes());
            if cid.as_bytes()[0] > 0xf0 {
                ground.push(cid);
            }
            n += 1;
            assert!(n < 400_000, "could not grind enough digests");
        }
        for (k, cid) in ground.iter().enumerate() {
            c.announce(ann(*cid, 900_000 + k as u32, "doc", &terms(&["x"]), 0), &t);
        }
        // Positive control: the ground entries really did get in, so a later count of zero
        // means they were evicted rather than never stored.
        let ground_before = ground
            .iter()
            .filter(|cid| c.announcement_of(&addr(900_000), cid).is_some()
                || c.candidates(&terms(&["x"])).contains(cid))
            .count();
        assert!(ground_before > 0, "vacuous: no ground entry was ever admitted");

        // Honest sources arrive afterwards.
        let mut honest_keys = Vec::new();
        for i in 0..200u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            b[31] = 7;
            c.announce(ann_raw(Cid::of(&b), b, "doc", &terms(&["x"]), 0), &t);
            honest_keys.push((Cid::of(&b), Identity::from_seed(b).address()));
        }

        // What survives, which is the property the name claims.
        let honest_held = honest_keys
            .iter()
            .filter(|(cid, who)| c.announcement_of(who, cid).is_some())
            .count();
        let ground_held = ground
            .iter()
            .filter(|cid| c.candidates(&terms(&["x"])).contains(cid))
            .count();

        // A share, not a survivor. Asserting `> 0` accepts the defect: under minimum-key
        // eviction the ground digests sort high and are never the minimum, so the pool ends
        // holding one honest entry and sixty-three ground ones, and `> 0` is satisfied by that
        // single entry. Two hundred honest sources arriving last, into a pool of sixty-four,
        // should hold most of it.
        assert!(
            honest_held >= 24,
            "honest sources hold only {honest_held} of 64 slots after arriving last, \
             which is what minimum-key eviction produces"
        );
        assert!(
            ground_held < ground.len(),
            "every ground digest survived, so they are not evictable"
        );
    }

    /// One source must not be able to hold the whole untrusted pool.
    #[test]
    fn one_untrusted_source_cannot_occupy_the_whole_pool() {
        let t = Trust::new();
        let capacity = 64;
        let mut c = Catalogue::new().with_untrusted_capacity(capacity);
        for i in 0..10_000u32 {
            c.announce(ann(Cid::of(&i.to_le_bytes()), 5, "doc", &terms(&["x"]), 0), &t);
        }
        let held = c.untrusted_held();
        assert!(
            held <= capacity / 16 + 1,
            "one source held {held} of {capacity} slots"
        );
    }

    /// Restating with fresh terms must not grow the term index without limit.
    ///
    /// Pruning only on eviction left one identity, holding one slot, able to add terms for
    /// ever. That is the same bound-at-one-stage-only mistake as the eviction path, made
    /// again in the very next code path.
    #[test]
    fn restating_with_fresh_terms_does_not_grow_the_index_without_limit() {
        let t = Trust::new();
        let mut c = Catalogue::new().with_untrusted_capacity(64);
        let target = Cid::of(b"one target");
        for i in 0..5_000u64 {
            c.announce(ann(target, 1, "doc", &[format!("term{i}")], i), &t);
        }
        assert_eq!(c.untrusted_held(), 1);
        assert!(
            c.terms_indexed() <= 2,
            "one source restating grew the term index to {}",
            c.terms_indexed()
        );
    }

}
