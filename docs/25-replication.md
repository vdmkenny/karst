# 25 — Replication

One provider per publisher is a single point of failure and a single point of seizure. The feed
stops when that provider stops, and it stops for everyone. A design whose founding requirement
is that no authority can switch it off cannot rest a publisher's reachability on one host.

---

## Where a feed lives, without anyone being told

Placement has to be computable by a reader who has never spoken to the publisher. The
alternative is an announcement saying where to look, and that announcement is one more thing an
adversary can withhold.

So it is derived from public information: the publisher's address, a per-epoch value, and the
provider set. Each provider is scored `H(publisher || beacon || provider)` and the top `k` hold
the feed. This is **rendezvous hashing** (Thaler and Ravishankar, *Using Name-Based Mappings to
Increase Hit Rates*, IEEE/ACM ToN 6(1), 1998).

Its Theorem 1 proves that for any scheme spreading objects evenly, the fraction remapped when a
server joins or leaves is bounded below by `1/m`, and that this scheme attains it. **Minimal
disruption here is optimal rather than merely good**, which matters because a placement that
reshuffled on every membership change would be unknowable in practice: a publisher and a reader
would have to agree on exact membership at an exact instant.

Consistent hashing (Karger, Lehman, Leighton, Panigrahy, Levine, Lewin, STOC 1997) is the
obvious alternative and is worse here. It has no native notion of `k` replicas — Dynamo gets one
by walking the ring and then has to **skip positions** to force distinct physical nodes, which
breaks the clean disruption story — and it needs virtual nodes to balance, at roughly 1000 per
bucket for a few percent deviation. At tens or hundreds of providers, rendezvous hashing's
`O(m)` cost is tens of hashes and buys exactness with no tuning.

---

## This is capturable, and the price is published

A deterministic function of two public identities can be **ground against**: generate provider
identities until one scores into a chosen publisher's top `k`. About `n` hashes per slot.

That is not theoretical, and the deployed numbers are worse than the arithmetic suggests.

| | |
|---|---|
| Tor hidden service directories | grinding a relay fingerprint into the responsible position "takes just a few minutes on a modern multi-core computer"; six precomputed relays captured every responsible directory, demonstrated against Silk Road (Biryukov, Pustogarov, Weinmann, IEEE S&P 2013) |
| IPFS content censorship | ~45 Sybils, **$0.0005** per identity, **about $4 total on AWS** (Sridhar, Ascigil, Keizer, Genon, Pierre, Psaras, Rivière, Król, NDSS 2024) |

The literature's term for this is a **localized attack** (Cholez, Chrisment, Festor, AIMS 2009
and after) or content eclipse. It is not index poisoning, which means something else, and
"targeted eclipse" is descriptive rather than a term of art.

### A claim withdrawn

The first version of this rotated on an epoch **counter** and claimed that converted permanent
capture into per-epoch capture. **That is wrong.** A counter is public and monotonic, so an
adversary grinds an identity that wins for whichever epoch they care about, as far ahead as they
like. Rotation on a predictable value provides no protection against precomputation at all, and
`grinding_against_a_predictable_beacon_captures_any_epoch_you_like` now proves it rather than
asserting the comfortable opposite.

The earlier test showed a slot ground for epoch 0 does not survive to epoch 1 and concluded
rotation worked. Nothing forces an adversary to grind for the epoch they happen to be in.

### What rotation needs to be worth anything

An **unpredictable** value. This is exactly the fix Biryukov et al. proposed in the same paper
and Tor shipped as proposal 250, the shared random value produced by commit-and-reveal among the
directory authorities. Rotating a data item's storage key specifically to frustrate grinding is
older still: Cerri, Ghioni, Paraboschi and Tiraboschi (*ID mapping attacks in P2P networks*,
GLOBECOM 2005) proposed it twenty years ago, alongside binding an identity to its address so it
cannot be freely chosen.

Producing such a value without a trusted party is its own problem, solved by commit-and-reveal
among a quorum (Syta, Jovanovic, Kokoris Kogias, Gailly, Gasser, Khoffi, Fischer, Ford, IEEE
S&P 2017) and deployed as drand. **Nothing here produces one.** `Beacon` is the shape of the
dependency and `Beacon::predictable` is named so that using the unsafe kind is a visible choice.

### And tenure, because a beacon leaks before its epoch

A beacon takes rounds to produce, so it is known slightly before it applies. Tor's own security
analysis records the size of that window: the reveal phase runs for hours, so the value is
predictable roughly **twelve hours ahead**, and Tor argues this survives only because earning a
directory flag requires sustained uptime.

`min_tenure` is that argument. An identity ground against a leaked beacon cannot be assigned
until it has been present longer than the leak, by which time the beacon it was ground for has
passed. It delays capture and does not prevent it: an adversary willing to wait is unaffected,
and the test says so.

### Rotation also cuts the other way

Elahi, Bauer, AlSabah, Dingledine and Goldberg (*Changing of the Guards*, WPES 2012) found that
rotating Tor entry guards **increases** compromise, because every rotation is a fresh
independent draw: rotation "increases the chances of active guard list compromise
substantially", and over enough rotations "all clients will have been compromised at some
point". Tor's response was to rotate *less*, from 45 days to nine months (Dingledine, Hopper,
Kadianakis, Mathewson, HotPETs 2014).

These are not in conflict. Rotation defeats an adversary whose advantage is **choosing** a
position and helps one whose advantage is **waiting** to be chosen. This design has both
properties at once, and which dominates depends on whether per-epoch grinding cost exceeds the
value of one epoch of capture. At $0.0005 an identity, it does not.

**No paper appears to model that crossover.** Elahi et al. give one half, Biryukov et al. the
other. This does not model it either, and the gap is worth naming rather than papering over.

---

## What replication buys beyond availability

Several views to compare.

A hostile replica **cannot inject, alter, or attribute**, because every object is verified
against the publisher's key wherever it came from. It can only **omit**. Replicas therefore add
parties who can fail to serve and none who can lie, which is why `k` is a storage and privacy
decision rather than a trust one.

### This is a quorum read, not fork detection

Detecting a single untrusted server that shows different clients different content is hard in a
way that is proved. Mazières and Shasha (*Building secure file systems out of Byzantine
storage*, PODC 2002 — this is where fork consistency is defined, not the SUNDR implementation
paper at OSDI 2004) state it in their abstract: immediate unconditional detection "is
unfortunately not achievable". What fork consistency buys is that a server which lies to one
client must **permanently partition** it from another, detectable only "with on-line
communication" between clients. Cachin, Shelat and Shraer (PODC 2007) then prove the cost:
fork-linearizability forces an operation to block on another client taking a step **even when
the server is correct**.

None of that binds here, and the reason is worth stating precisely: **that hardness comes from
there being one server.** With `k` providers a single reader gets `k` independent views by
itself, so comparing them is a **Byzantine quorum read** (Malkhi and Reiter, *Byzantine quorum
systems*, Distributed Computing 11, 1998) and needs no other reader.

> A reader who queries **every** replica detects withholding by any **minority** of them, with
> no coordination and no gossip.

### Where it stops, exactly

**A reader who queries fewer than all `k`** has no quorum. Querying one replica is precisely the
single-server case the impossibility results are about, and a test asserts that one replica
always agrees with itself.

**Staleness rather than divergence.** If every replica serves the same old but internally
consistent state, the reader sees perfect agreement. There is nothing to compare against, so
comparison cannot help; it needs a trusted clock or another party's view.
`karst-object::freshness` is the mechanism and is not wired here.

### And the fallback has a poor deployment record

The usual answer to staleness is gossip between readers. Certificate Transparency has the
identical problem and its gossip specification, `draft-ietf-trans-gossip`, **expired without
becoming an RFC**, with measured adoption of the feedback endpoints at **0.015% of domains**
(Gasser, Hof, Helm, Korczynski, Holz, Carle, PAM 2018). What shipped in Chrome is sampled
reporting to Google — centralised auditing by a party that also operates logs. Google's own SoK
concludes security "cannot rely on mandatory changes implemented in web servers" and that how a
client privately reports a missing certificate is still open (Meiklejohn et al., PoPETs 2022).

The current direction is **witness cosigning**: independent witnesses countersign checkpoints
only if they extend what they have already seen, so a split view requires corrupting witnesses
rather than fooling clients (Syta et al., *Keeping Authorities Honest or Bust*, IEEE S&P 2016).

A design whose detection story rests on readers gossiping should expect readers not to. This one
should budget for witnesses, which is L8 and is not built.

---

## Why not erasure coding

Weatherspoon and Kubiatowicz (IPTPS 2002) show coding reaching far higher durability per byte
than replication: at fixed mean time to failure, replication costs **11x** the bandwidth,
storage and disk seeks. Those numbers are **crash-only and assume independent, identically
distributed failures**, which the paper concedes in section 7 is "not true for all sets of
storage servers".

Three reasons it is still the wrong default here.

### The crash-model economics are narrower than they look

Rodrigues and Liskov (IPTPS 2005) find that at four nines with `m=7`, "the redundancy gains from
using coding range from 1 to 3-fold", and which end you land on depends entirely on node
availability: on a PlanetLab-like trace "coding is not a win". They also name a cost Weatherspoon
omits, **repair amplification**: rebuilding one lost fragment means fetching enough to
reconstruct the whole object, so "the amount of data that needs to be transferred is `m` times
higher than the amount of redundancy lost".

Blake and Rodrigues (HotOS IX, 2003) argue separately that the binding constraint in cooperative
storage is **maintenance bandwidth under churn**, not disk, which undercuts the storage-overhead
argument that motivates coding in the first place. Both papers assume independent failures; they
are churn critiques, not correlation critiques.

### Correlation reverses the ranking, measured on real hardware

Nath, Yu, Gibbons and Seshan (*Subtleties in Tolerating Correlated Failures in Wide-area Storage
Systems*, NSDI 2006) find that under independent failures `ERASURE(1,4)` is 1.5 nines *worse*
than `ERASURE(8,16)`, and under a correlated trace it is **2 nines better**. `ERASURE(1,4)` is
four-way replication. The mechanism: "correlated failures hurt systems with large `m` more than
those with small `m`".

Ford, Labelle, Popovici, Stokely, Truong, Barroso, Grimes and Quinlan (*Availability in Globally
Distributed Storage Systems*, OSDI 2010) measured a Google fleet for a year and put a number on
it: ignoring correlation "results in overestimating availability by at least two orders of
magnitude, and eight in the case of RS(8,4)". **37% of node failures are part of a burst of two
or more.** The error grows with redundancy, which is Nath's mechanism showing up in production.

### And under a Byzantine model, fragments are not self-verifying

This is the decisive one. Coding must ensure every fragment corresponds to the same block, and
without that "a different block may be reconstructed from different subsets of fragments"
(Hendricks, Ganger, Reiter, PODC 2007). Weatherspoon's own section 2 names the problem —
"potentially a factorial combination of fragments to try", `(n choose m)` — asserts that a
verification hashing scheme fixes it at a cost "many times less than replication", and never
demonstrates that claim. Everything quantitative in the paper is crash-only.

The coding theory is unambiguous about the price. An MDS code corrects `2s + r < n - k`, so each
corrupt fragment whose position is **unknown** costs two redundancy symbols where an identified
erasure costs one. Goodson, Wylie, Ganger and Reiter (DSN 2004) give the protocol-level bound:
all-Byzantine storage needs `N >= 4t+1`, against `3f+1` for Byzantine state machine replication,
and their fix carries an `N x 16` byte cross-checksum on every block.

> In a content-addressed system a whole replica is **self-verifying from the object hash for
> free**. A fragment is not.

That asymmetry is the whole argument. Replication of content-addressed, publisher-signed objects
identifies a lying replica immediately, with no subset search, no cross-checksums, and no extra
verification layer. Coding would have to buy back a property this design already has.

Worth noting what the deployments do: Facebook's HDFS-RAID work (Sathiamoorthy et al., PVLDB
6(5), 2013) and Windows Azure Storage (Huang et al., USENIX ATC 2012, `LRC(12,2,2)` at 1.33x
overhead) are both **crash and omission only**. Azure verifies with CRCs, which are
non-cryptographic and forgeable by a malicious server, so neither system tolerates a server
returning well-formed wrong data.

---

## Two defects found by running it

**Responses from other providers were discarded rather than filed.** Replicas polled round-robin
systematically dropped each other's replies, so every replica but one looked like it was
withholding. The response now echoes the box it answers and replies are filed by `(provider,
feed)` rather than filtered against whichever provider was being polled at that instant.

**A caller that stops polling early manufactures its own false positives.** A replica that was
never finished being read is indistinguishable from one that is withholding. The first version
of the demo stopped as soon as the reader had what it wanted and reported two honest providers
as behind alongside the one that was actually down. That is a requirement on the caller and is
now written where the counting is.

---

## References

- Thaler, Ravishankar. *Using Name-Based Mappings to Increase Hit Rates.* IEEE/ACM ToN 6(1), 1998.
- Karger, Lehman, Leighton, Panigrahy, Levine, Lewin. *Consistent Hashing and Random Trees.* STOC 1997.
- Cerri, Ghioni, Paraboschi, Tiraboschi. *ID mapping attacks in P2P networks.* IEEE GLOBECOM 2005.
- Biryukov, Pustogarov, Weinmann. *Trawling for Tor Hidden Services.* IEEE S&P 2013.
- Sridhar, Ascigil, Keizer, Genon, Pierre, Psaras, Rivière, Król. *Content Censorship in the
  InterPlanetary File System.* NDSS 2024.
- Cholez, Chrisment, Festor. *Evaluation of Sybil Attacks Protection Schemes in KAD.* AIMS 2009.
- Elahi, Bauer, AlSabah, Dingledine, Goldberg. *Changing of the Guards.* WPES 2012.
- Dingledine, Hopper, Kadianakis, Mathewson. *One Fast Guard for Life (or 9 months).* HotPETs 2014.
- Syta, Jovanovic, Kokoris Kogias, Gailly, Gasser, Khoffi, Fischer, Ford. *Scalable
  Bias-Resistant Distributed Randomness.* IEEE S&P 2017.
- Baumgart, Mies. *S/Kademlia.* ICPADS 2007.
- Castro, Druschel, Ganesh, Rowstron, Wallach. *Secure Routing for Structured Peer-to-Peer
  Overlay Networks.* OSDI 2002.
- Douceur. *The Sybil Attack.* IPTPS 2002.
- Mazières, Shasha. *Building secure file systems out of Byzantine storage.* PODC 2002.
- Li, Krohn, Mazières, Shasha. *Secure Untrusted Data Repository (SUNDR).* OSDI 2004.
- Cachin, Shelat, Shraer. *Efficient Fork-Linearizable Access to Untrusted Shared Memory.* PODC 2007.
- Malkhi, Reiter. *Byzantine quorum systems.* Distributed Computing 11, 1998.
- Syta, Tamas, Visher, Wolinsky, Jovanovic, Gasser, Gailly, Khoffi, Ford. *Keeping Authorities
  Honest or Bust with Decentralized Witness Cosigning.* IEEE S&P 2016.
- Gasser, Hof, Helm, Korczynski, Holz, Carle. *In Log We Trust.* PAM 2018.
- Meiklejohn, DeBlasio, O'Brien, Thompson, Yeo, Stark. *SoK: SCT Auditing in Certificate
  Transparency.* PoPETs 2022(3).
- Weatherspoon, Kubiatowicz. *Erasure Coding vs. Replication: A Quantitative Comparison.*
  IPTPS 2002, LNCS 2429, 328-338.
- Rodrigues, Liskov. *High Availability in DHTs: Erasure Coding vs. Replication.* IPTPS 2005,
  LNCS 3640, 226-239.
- Blake, Rodrigues. *High Availability, Scalable Storage, Dynamic Peer Networks: Pick Two.* HotOS IX, 2003.
- Nath, Yu, Gibbons, Seshan. *Subtleties in Tolerating Correlated Failures in Wide-area Storage
  Systems.* NSDI 2006, 225-238.
- Ford, Labelle, Popovici, Stokely, Truong, Barroso, Grimes, Quinlan. *Availability in Globally
  Distributed Storage Systems.* OSDI 2010, 61-74.
- Goodson, Wylie, Ganger, Reiter. *Efficient Byzantine-Tolerant Erasure-Coded Storage.* DSN 2004.
- Hendricks, Ganger, Reiter. *Verifying Distributed Erasure-Coded Data.* PODC 2007, 139-146.
- Sathiamoorthy, Asteris, Papailiopoulos, Dimakis, Vadali, Chen, Borthakur. *XORing Elephants.*
  PVLDB 6(5), 2013.
- Huang, Simitci, Xu, Ogus, Calder, Gopalan, Li, Yekhanin. *Erasure Coding in Windows Azure
  Storage.* USENIX ATC 2012.
- Wan, Johnson, Wails, Wagh, Mittal. *Guard Placement Attacks on Path Selection Algorithms for
  Tor.* PoPETs 2019(4).
