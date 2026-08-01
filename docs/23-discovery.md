# 23 — Discovery

Crawling exists because publishing does not include announcing. A page appears and nothing
tells anyone, so finding it requires guessing that it exists and going to look. That guessing is
the expensive half of search by a wide margin, and it re-derives, at enormous cost and always
late, a fact the author knew for certain at the moment of writing.

**The author already knows.** Announcement is therefore an obligation of authorship, done once
by the one party who cannot get it wrong. What stays competitive is ranking, which is a small
piece of forkable software rather than a decade of crawl infrastructure and a datacentre. The
moat under a search monopoly is the crawl, not the algorithm.

That is the easy part of the argument. The rest of this document is what the literature says
goes wrong, and which of those failures this design repeats.

---

## The trade that cannot be avoided

Li, Loo, Hellerstein, Kaashoek, Karger and Morris (IPTPS 2003) measured a distributed inverted
index at web scale. Partition-by-keyword costs **530× their communication budget on average**
and **4000× worst case** on the query `the who`. Their best stack of optimisations reaches 75×,
still an order of magnitude short. Their conclusion is not "impossible" but something more
useful: feasibility requires giving up **either ranking quality or decentralisation**.

Their own numbers make the irony explicit. Flooding, which they treat as the naive baseline,
costs 6× — nearly a hundred times better than the DHT approach they then spend the paper
optimising.

**This design takes the first trade.** `search_top` ranks the best *k* and reports how many were
dropped. A query on a common term matches a large fraction of the catalogue and ranking that
many results is linear in the catalogue however good the index is, so completeness of ranking
is what gets surrendered.

The truncation is reported rather than silent. A reader told "these are the results" when it
means "these are some of them" cannot distinguish a sparse topic from a suppressed one, and
that difference is exactly what an adversary suppressing entries wants invisible.

### Distribution is not solved here

Entries are ordinary signed objects and travel the way objects travel. Every reader holding a
full catalogue is the *other* trade in Li et al.'s pair — replicating the index rather than
partitioning it — and it is stated rather than assumed away. It is affordable only because a
catalogue is bounded and the bound is a reader's choice.

---

## Ranking is anchored at the reader, because a theorem leaves nothing else

Douceur (IPTPS 2002) proves that **without a logically centralized authority, Sybil attacks are
always possible** except under unrealistic assumptions. Every defence since works by smuggling
in a substitute authority: a certificate, a social graph, a stake, or a puzzle. Castro et al.
(OSDI 2002) tolerate 25% malicious nodes and **require certified node identifiers**. Whanau
(Lesniewski-Laas and Kaashoek, NSDI 2010) substitutes a social graph, and provides
**availability but not integrity** — an adversary can always insert a different value for a key
already present.

The social-graph family then fails on measurement. Mohaisen, Yun and Kim (IMC 2010) measured
what SybilGuard, SybilLimit and Whanau assumed, and found **the graphs with genuine trust
semantics are the slow-mixing ones**. Viswanath, Post, Gummadi and Mislove (SIGCOMM 2010) showed
all these schemes are really local community detection, and that **targeted** attack-edge
placement defeats every one of them, whereas the schemes assume random placement.

The sharpest result is Cheng and Friedman (P2PECON 2005):

> **Theorem 1. There is no symmetric sybilproof nontrivial reputation function.**

And the strengthening: in any such function, *any* node not already holding the maximum value
has a successful sybil strategy. Their Theorem 2 extends this to k-sybilproofness for every
constant k, so capping identities does not rescue it.

Symmetric means name-blind. Every global ranking is name-blind, which is why every global
ranking is manipulable by manufacturing identities. Cheng and Friedman also name EigenTrust
directly, and EigenTrust's own authors concede that without pre-trusted peers "forming a
malicious collective in fact heavily boosts the trust values of malicious nodes". Fan, Liu, Li
and Su (CollaborateCom 2012) measured EigenTrust performing **worse than no reputation system at
all** once dishonest feedback reaches 40%.

Their escape is the only one left: **asymmetric reputation, anchored at a source.** Ranking must
be relative to who is asking.

So the authority substitute here is **the reader**, and that is named rather than dressed up as
cleverness. Its cost is real: a reader who trusts nobody gets an unranked catalogue, and a new
author with no reputation starts at the untrusted ceiling.

### Untrusted sources contribute once, not once each

Anchoring is necessary and not sufficient. The first version of this ranker let the untrusted
contribution *saturate*, approaching a ceiling as `n/(n+K)`. A thousand strangers were worth
barely more than one, which sounds like enough and is not: going from one identity to two still
raised the score, so the mechanism was **sybil-bounded rather than sybilproof**, and Cheng and
Friedman's result says a bounded gain is still a gain worth taking.

```text
untrusted(0) = 0
untrusted(n) = ceiling,  for every n >= 1
```

Every untrusted source together is worth exactly one voice. The second identity gains nothing
and neither does the two hundred thousandth.

**What that gives up, deliberately:** any signal in *how many* strangers said something. That is
precisely the quantity the theorem shows cannot be counted safely — a popularity signal from
unaccountable identities is a manipulation primitive with a friendly name. A reader who wants it
back subscribes to someone who measures popularity against evidence an adversary cannot mint.

### Two axes, and the invariant that actually holds

Score combines **relevance** (how much of the query a statement matches) with **weight** (how
much the reader values its source). The claim that survives is narrow:

> A source the reader chose outweighs any number of strangers **at equal relevance**.

An earlier version of this document claimed something stronger, and the shipped demo printed the
counterexample two lines above the claim: a trusted source weighted 0.8 matching half a query
scored 0.4 and ranked *below* a stranger flood at 0.5. The cause was that trusted contributions
were scaled by relevance and untrusted ones were not. **Two quantities on different axes are not
comparable**, and no invariant could hold while they were. A reader wanting trust to dominate
relevance weights a source above 1.0.

---

## The defect the whole model rested on

Announcements carried their author as a **caller-supplied field**, and nothing verified a
signature. Anyone could mint an entry in the name of any source a reader trusted, and every
weight in the crate would have been applied to whatever the forger wrote.

**A source that can be impersonated is not a source.** Statements are now signed objects, the
author is taken from the verified signature and never from the payload, and the type system
enforces it: `Catalogue` accepts only `Verified<Announcement>`, which is constructible solely by
`Announcement::from_object`, which verifies. "Did anyone check this signature" is answered by
the type rather than by remembering to.

---

## Bounds that actually bind

An unbounded catalogue is a memory exhaustion primitive available to anyone, because identities
are free. Three attempts were needed to get the bound right, and the pattern in the failures is
worth more than the fixes.

**The bound was on the wrong structure.** Statements were bounded; the term index they populate
was not. Eviction removed statements and left their terms behind, so memory grew without limit
at the rate an adversary chose, and `candidates` kept returning objects the catalogue held
nothing about — 20,000 candidates backed by 64 statements.

**Then it was applied at one stage and not another.** Pruning happened on eviction but not on
*replacement*, so one identity holding one slot could restate with fresh terms for ever. This is
the shape of partial fix eMule shipped, where a per-subnet identity limit was enforced when
adding contacts and **not during lookup**, leaving the attack working perfectly (Kohnen, Leske
and Rathgeb, IFIP Networking 2009). A bound applied at one stage and not another is not a bound.

**And the eviction order was adversary-controlled.** Keys are `(Cid, Address)` and a Cid is the
hash of content its author chose, so evicting the smallest key handed the ordering to whoever
writes the content: grind a nonce until the digest starts with `0xff` and the entry becomes
permanently unevictable while every honest entry is driven out. **An ordering an adversary can
compute is an ordering an adversary controls.**

Eviction now charges the largest occupant, breaking ties at random, with a per-source quota that
binds whether or not the pool is full. Holding many slots is what a flood does and what a single
honest source does not, and grinding a digest changes nothing because it does not change how
many slots a source holds.

---

## Scale, because small-corpus evaluation is worthless

Reynolds and Vahdat (Middleware 2003) reported sub-kilobyte P2P keyword queries — **at 100,000
documents**. Li et al. measured the same approach at 530 MB per query over three billion. Any
evaluation of a decentralised index at small corpus size tells you nothing.

Measuring this one found ranking was **quadratic**, and twenty-one passing tests had not seen
it, because every one used a catalogue small enough for quadratic to look instant.

| objects | before | after |
|---|---|---|
| 1,000 | 6.2 ms | 0.33 ms |
| 4,000 | 48.6 ms | 1.5 ms |
| 16,000 | 580 ms | 8.0 ms |
| 64,000 | **21,773 ms** | 39.8 ms |
| 256,000 | not attempted | 173 ms |

The cause was a key order: statements were keyed `(source, target)`, but ranking asks *what has
anyone said about this object*, which under that key means scanning the whole catalogue once per
candidate. Keyed by target it is a range scan.

`karst-indexscale` measures it with a **Zipf-shaped vocabulary** rather than a uniform one,
because a uniform vocabulary hides exactly the common-term case that broke the published
designs.

The regression tests assert on **statements examined** rather than on a clock. A timing
assertion is flaky enough that it gets deleted the first time CI is busy.

---

## Query privacy is a separate problem, and this does not solve it

The mixnet at L4 conceals who is asking. It does not conceal what is asked, and it is important
that nobody reads L15 as though it did.

Peddinti and Saxena (*Journal of Computer Security*, 2014) took 60 AOL-log users searching over
Tor and identified their queries at **25.95% true-positive rate mixed with 99 other users** and
18.95% mixed with 999. Some users were identified at **80–98% even at N=1000**. This used query
**content alone** and is explicitly transport-independent: "the results are generic and apply to
any anonymizing network". Their conclusion:

> "Our results cast serious doubt on the effectiveness of anonymizing web search queries by
> means of anonymizing networks."

A persistent interest profile is self-linking regardless of what carries it. **Anonymity and
query privacy are two mechanisms, and L4 is only the first.**

One thing the local-catalogue architecture does change: a reader searching their own catalogue
**emits no query at all**, so there is no search traffic to correlate. That is a genuine
structural advantage over a system with a query endpoint. It does not survive the fetch: asking
for content still names it, which is issue #53.

Wang, Mittal and Borisov (CCS 2010) broke NISAN and Torsk by showing **the lookup itself leaks
the key being looked up**, even when the payload is protected, and closed by motivating "the
search for a DHT lookup mechanism that is both secure and anonymous". Nothing since has supplied
one, which is a reason this design has no lookup DHT rather than a better one.

### The PIR problem has moved, not gone

Modern PIR is affordable. Spiral (Menon and Wu, S&P 2022) reaches **1.9× the no-privacy
baseline**; Tiptoe (Henzinger, Dauterman, Corrigan-Gibbs and Zeldovich, SOSP 2023) does private
web search over 360M pages at 2.7 s and 56.9 MiB per query on a 45-server cluster. Sion and
Carbunar's 2007 verdict that PIR can never beat trivial download is obsolete, and specifically
because lattice-based schemes broke the "one modular multiplication per database bit" premise it
rested on.

The cost moved. The fast schemes need a large **client-side hint** derived from the database —
SimplePIR needs 121 MB per 1 GB, DoublePIR 16 MB — and **the hint invalidates whenever the
corpus changes**. In a system whose premise is that publishing is announcing, the corpus changes
continuously. A literature search did not find this interaction addressed anywhere, and it may
be the sharpest open problem in this design.

Tiptoe also degrades quality: average best-result rank 7.7 against 2.3 for non-private neural
search, and it is **poor at exact string matching**. For identifier-style lookups that is
disqualifying.

---

## Architectural decentralisation is not operational decentralisation

Balduf et al. (IMC 2023) measured IPFS, a system designed so that no party could dominate:
**79.6% of DHT server nodes in data centres, the top 3 cloud providers hosting 51.9%, the top 5%
of nodes carrying up to 95% of traffic, and AWS alone generating 96% of content resolution
requests.**

"Because it is peer-to-peer" is not an answer to that, and this design does not offer it. The
answer has to be L16, and L15 is built to give scale nothing to buy:

- **A catalogue is per-reader.** There is no index to run at scale, because the index is not a
  service. Holding more statements does not confer advantage on anyone but the holder.
- **Ranking is per-reader.** There is no ranking to operate, so there is no ranking business.
- **Untrusted contribution is a step.** Operating a hundred thousand announcing nodes is worth
  exactly what operating one is worth.

What an AWS-scale actor can still do is **hold and serve more objects**, which is L6's problem
and L16's, not this layer's. Tigelaar, Hiemstra and Trieschnigg (TOIS 2012) survey a decade of
peer-to-peer information retrieval and open with the verdict that none of it "has seen
widespread real-world adoption". That is the base rate this is working against.

---

## Not built

- **Distribution.** Entries travel as objects, and nothing here gossips, replicates or
  reconciles them. Two readers can hold different catalogues and neither can tell.
- **Trust bootstrapping.** How a reader acquires their first weights is L5's problem.
- **Discovery of publishers a reader has never heard of.** A census tells a reader they are
  missing entries from a publisher they know. It says nothing about a publisher whose existence
  was withheld, because **a reader cannot miss what they do not know exists**. That residue is
  the same one Tor's v3 blinded descriptors leave.

---

## Completeness, which is the property the premise puts under attack

Every mechanism above verifies what a reader **receives**. None of them says anything about what
a reader did not receive, so an adversary forwarding a subset of a publisher's announcements, or
none, is untouched by all of it. Castro, Druschel, Ganesh, Rowstron and Wallach (OSDI 2002) are
explicit that self-certifying data gives nothing when verifying an object is *not* stored.

`karst-index::complete` closes the half that can be closed. A publisher periodically signs a
**census**: how many announcements they have made, and a digest over their targets. A reader
holding fewer than the count knows entries are missing and knows how many, without knowing
which; a reader holding the right number of the wrong entries is caught by the digest.

| Outcome | Meaning |
|---|---|
| `Complete` | Holding everything committed to, commitment current |
| `Missing { held, announced }` | Somebody in between is withholding, and this many |
| `Divergent { expected, held }` | Right count, wrong entries |
| `Expired` | The commitment is too old to conclude from |
| `Unknown` | **Suspect.** No commitment held |

`Unknown` counts as suspect deliberately. A reader who has heard no commitment is in exactly the
position this exists to remove them from, and reporting that as healthy would be the original
failure wearing the mechanism's name.

The structure is TUF's timestamp role, which `karst-object::freshness` already implements:
expiring statements, a monotonic sequence so an old census cannot be replayed to make a reader
believe they are current, and a snapshot commitment so forwarding genuine fresh statements while
withholding what they refer to is detected rather than believed.

Two ways to make the count lie are refused explicitly: another publisher's announcements do not
fill it, or a flood of unrelated entries would make a withheld feed look complete; and claims do
not count as announcements.

## References

- Li, Loo, Hellerstein, Kaashoek, Karger, Morris. *On the Feasibility of Peer-to-Peer Web
  Indexing and Search.* IPTPS 2003.
- Reynolds, Vahdat. *Efficient Peer-to-Peer Keyword Searching.* Middleware 2003.
- Douceur. *The Sybil Attack.* IPTPS 2002.
- Cheng, Friedman. *Sybilproof reputation mechanisms.* P2PECON 2005.
- Cheng, Friedman. *Manipulability of PageRank under Sybil Strategies.* NetEcon 2006.
- Kamvar, Schlosser, Garcia-Molina. *The EigenTrust Algorithm.* WWW 2003.
- Fan, Liu, Li, Su. *EigenTrust++: Attack resilient trust management.* CollaborateCom 2012.
- Lesniewski-Laas, Kaashoek. *Whanau: A Sybil-proof Distributed Hash Table.* NSDI 2010.
- Mohaisen, Yun, Kim. *Measuring the Mixing Time of Social Graphs.* IMC 2010.
- Viswanath, Post, Gummadi, Mislove. *An Analysis of Social Network-Based Sybil Defenses.*
  SIGCOMM 2010.
- Castro, Druschel, Ganesh, Rowstron, Wallach. *Secure Routing for Structured Peer-to-Peer
  Overlay Networks.* OSDI 2002.
- Kohnen, Leske, Rathgeb. *Conducting and Optimizing Eclipse Attacks in the Kad Network.* IFIP
  Networking 2009.
- Liang, Naoumov, Ross. *The Index Poisoning Attack in P2P File Sharing Systems.* INFOCOM 2006.
- Peddinti, Saxena. *Web Search Query Privacy.* Journal of Computer Security, 2014.
- Wang, Mittal, Borisov. *In Search of an Anonymous and Secure Lookup.* CCS 2010.
- Menon, Wu. *Spiral: Fast, High-Rate Single-Server PIR.* IEEE S&P 2022.
- Henzinger, Dauterman, Corrigan-Gibbs, Zeldovich. *Private Web Search with Tiptoe.* SOSP 2023.
- Balduf, Korczynski, Ascigil, Keizer, Pavlou, Scheuermann, Krol. *The Cloud Strikes Back:
  Investigating the Decentralization of IPFS.* IMC 2023.
- Tigelaar, Hiemstra, Trieschnigg. *Peer-to-Peer Information Retrieval: An Overview.* TOIS 2012.
