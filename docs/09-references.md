# 09 — References

Sources for the load-bearing claims in these documents. Where a design here is an
existing published system, that is stated rather than implied. Very little of KARST is
new; the contribution is the assembly and the four-error framing, not the primitives.

This is a reading list, not a complete bibliography, and it does not assert that every
claim elsewhere in the repository appears here.
[`docs/30-research-and-its-citations.md`](30-research-and-its-citations.md) is the
verification pass: it checks each citation against the source text, quotes the passage
the claim rests on, and records where a document states a cited result imprecisely. Where
the two disagree, docs/30 is the one that was checked.

---

## Anonymity and mix networks

**Loopix.** Piotrowska, Hayes, Elahi, Meiser, Danezis. *The Loopix Anonymity System.*
USENIX Security 2017.
<https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska>

L4 Mixing is Loopix. Poisson mixing with independent per-message delays, cover traffic,
and self-injected loop traffic that lets mixes and clients detect active attacks, in a
stratified topology. The paper claims traffic analysis resistance against a global
network adversary, which is exactly the adversary onion routing declines to defend
against, and reports that a mix node's bandwidth grows linearly to around 225
messages per second before flattening, with end-to-end latency on the order of seconds.
The abstract's "upwards of 300 messages per second" is a lower bound and not a ceiling;
see `26-media.md` for why the difference matters and which experiment produced which
number.

**Loopix's parameters, verified against arXiv:1703.00536v1 Table 1 and the figure captions,
because two of them are easy to get backwards.**

| Symbol | What it is |
|---|---|
| `lambda_P` | payload traffic rate, user |
| `lambda_L` | loop traffic rate, user |
| `lambda_D` | drop cover traffic rate, **user only** |
| `lambda_M` | loop traffic rate, **mix**. Not a mix drop-cover rate; mixes emit loops and nothing else |
| `mu` | the exponential **rate** of the per-hop delay. The mean delay is `1/mu` |
| `l` | path length |

Table 1 glosses `mu` as "The mean delay at mix Mi", and every use in the body contradicts that
gloss: Figure 4's caption reads "for different delays with mean 1/mu", and Section 5 writes "the
mean delay 1/mu sec.". Taking Table 1 literally inverts the parameter.

The paper recommends no values. Every rate in it is an experimental setup, and the only
guidance it gives is the ratio `lambda/mu >= 2` for the aggregate arrival rate at a mix. So a
deployment cannot copy Loopix's numbers; it has to derive its own. See `15-fundamental-limits.md`.

Two honest notes. First, we did not invent this layer, we selected it. Second, Loopix
calls itself low latency relative to other mix systems, meaning seconds rather than the
hours of older remailers. It is not low latency relative to Tor, and `05-anonymity.md`
should be read with that in mind.

**Sphinx.** Danezis, Goldberg. *Sphinx: A Compact and Provably Secure Mix Format.*
IEEE Symposium on Security and Privacy 2009.
<https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf>

The packet format L4 should use rather than inventing one. It hides path length and the
relay's position on the path, provides unlinkability for each leg, supports
indistinguishable replies, and detects tagging and replay attacks, with security proved
in the random oracle model. Our requirement that all packets be one fixed size composes
directly with it.

---

## Tor, and what has been done to it

**Directory authorities.** Tor uses a small set of hardcoded directory authorities,
around nine or ten, which vote hourly to produce the consensus document listing relays.
<https://community.torproject.org/relay/governance/policies-and-proposals/directory-authority/>

Cited in `04-lessons-from-tor.md` §2 as the argument that a hardcoded key set is a root
store by another name.

**Ten ways to discover Tor bridges.** Roger Dingledine, *Research problems: Ten ways to discover
Tor bridges*, Tor Project blog, 2011.
<https://blog.torproject.org/research-problems-ten-ways-discover-tor-bridges/>

The source for the September 2009 HTTPS break and the March 2010 mail break, for the phrase "by
just pretending to be enough legitimate users from enough different subnets", and for the 176 and
201 bridge pool sizes. Cited in WHITEPAPER §3 L5 and in `karst-member`, as the record of what
happened to membership concealment when a state attacked it.

**Bridge enumeration from a middle relay.** Zhen Ling, Junzhou Luo, Wei Yu, Ming Yang and Xinwen
Fu, *Extensive Analysis and Large-Scale Empirical Evaluation of Tor Bridge Discovery*, IEEE
INFOCOM 2012, pp. 2381-2389.

One malicious middle relay run for fourteen days enumerated 2,369 bridges, as many as a month of
enumeration across 500 PlanetLab nodes and 2,000 mail accounts. Cited in WHITEPAPER §3 L5 for the
claim that distribution was never the weak part.

**Bridge guards.** Tor proposal 188, *Bridge Guards and other anti-enumeration defenses*.
<https://spec.torproject.org/proposals/188-bridge-guards.html>

Tor's structural answer to the above. Still marked Reserve, shelved in 2020 on the grounds that
the attack had not been observed in use rather than that it had been fixed.

**KAX17.** A single unattributed operator ran over 900 Tor relays at peak, against a
network of roughly 9,000 to 10,000, from 2017 until removal between October and November
2021, across more than fifty autonomous systems. At its height a user faced up to a 16%
chance of a KAX17 guard, 35% for a middle relay, and 5% for an exit.
<https://therecord.media/a-mysterious-threat-actor-is-running-hundreds-of-malicious-tor-relays>

Cited in `04-lessons-from-tor.md` §6. This is the empirical case that manual Sybil
detection does not work, and the motivation for L16's structural approach. It is also
the case *against* our approach: KAX17 was interested in observation rather than
reputation, and flat returns on standing would not have stopped a single one of those
relays from being deployed. See WHITEPAPER §6.

---

## Membership by social introduction, as deployed

**The Dark Freenet.** Ian Clarke, Oskar Sandberg, Matthew Toseland and Vilhelm Verendel,
*Private Communication Through a Network of Trusted Connections: The Dark Freenet*, 2010.
<https://www.hyphanet.org/assets/papers/freenet-0.7.5-paper.pdf>

The architecture behind Freenet 0.7's darknet mode, released May 2008: nodes connect only to
peers whose references were exchanged out of band, chosen by trust rather than by a routing
algorithm. This is L5's mechanism, shipped to end users eighteen years ago.

**Sybils do not form a tight region.** Zhi Yang, Christo Wilson, Xiao Wang, Tingting Gao, Ben Y.
Zhao and Yafei Dai, *Uncovering Social Network Sybils in the Wild*, IMC 2011, extended in ACM
Transactions on Knowledge Discovery from Data 8(1), February 2014.

A detector deployed on Renren found more than 100,000 sybil accounts, in a dataset of 650,000.
Verbatim: "contrary to prior conjecture, Sybils in OSNs do not form tight-knit communities". Over
70% have no edge to any other sybil; of the remainder, the largest component "formed accidentally".
This is a measurement refutation of the assumption the SybilGuard family is built on, not a
modelling quibble. Cited in WHITEPAPER §3 L5 and in `karst-member`.

**And the schemes score below chance.** Lorenzo Alvisi, Allen Clement, Alessandro Epasto, Silvio
Lattanzi and Alessandro Panconesi, *SoK: The Evolution of Sybil Defense via Social Networks*, IEEE
Symposium on Security and Privacy 2013, pp. 382-396. Extended as *Communities, Random Walks, and
Social Sybil Defense*, Internet Mathematics 10(3-4):360-420, 2014.

Simulating the Renren attack shape on a Facebook graph, the probability that a random honest node
ranks above a random sybil: SybilLimit 0.45, SybilGuard 0.44, Mislove 0.34, Gatekeeper 0.49, ACL
0.37, where 0.5 is a coin flip. All five below chance, including the ACL algorithm the same paper
introduces as the first with provable guarantees. The extended version states the conclusion
plainly: the goal of universal decentralized sybil defense "rests on assumptions (short mixing
time and cut sparseness) whose validity is at best dubious". Cited in WHITEPAPER §3 L5 and in
`karst-member`.

**What the users did with it.** The Hyphanet project's own documentation states:
"Unfortunately most people use Hyphanet in opennet mode currently", and explains that opennet
exists "to let people try it out before they ask their friends to connect".
<https://www.hyphanet.org/pages/help.html>

Cited in WHITEPAPER §3 L5. Offered a secure mode requiring social effort and an insecure mode
requiring none, users took the insecure one. This is the strongest available evidence about
whether L5's cost is one a population will accept, and it is a primary source about its own
users rather than a measurement by a third party.

**Measurement.** Stefanie Roos, Benjamin Schiller, Stefan Hacker and Thorsten Strufe,
*Measuring Freenet in the Wild: Censorship-Resilience under Observation*, PETS 2014, 263-282.

Measures the deployed network at several tens of thousands of users and finds topology control
suboptimal for routing. **Not** cited for a darknet-versus-opennet split: that figure could not
be confirmed from the paper, and the project's own statement above is used instead.

---

## Authorization

**Macaroons.** Birgisson, Politz, Erlingsson, Taly, Vrable, Lentczner. *Macaroons:
Cookies with Contextual Caveats for Decentralized Authorization in the Cloud.* NDSS 2014.
<https://research.google.com/pubs/archive/41892.pdf>

L9 Authority and `crates/karst-cap` are macaroons: bearer credentials carrying caveats
that attenuate when, where, by whom and for what purpose a request may be authorized,
with delegation by extending the chain.

**One deliberate difference.** Macaroons chain nested HMACs, which is fast and compact
and requires the verifier to share a secret with the issuer. That is fine inside one
cloud provider and wrong here: it reintroduces a party who must be consulted, which is
error 03. `karst-cap` chains Ed25519 signatures instead, so a capability verifies
offline against nothing but itself and the object it addresses. We pay in bytes and in
verification cost, and we get a credential that works with no directory, no authority,
and no network.

**Capability security generally.** KeyKOS, the E language, and Capsicum predate the web
and had the ambient authority problem solved before the cookie was specified. Nothing at
L9 is a new idea; it is a fifty-year-old idea that lost.

---

## The document layer

**Link rot.** Pew Research Center. *When Online Content Disappears.* May 2024.
<https://www.pewresearch.org/data-labs/2024/05/17/when-online-content-disappears/>

A quarter of all pages that existed between 2013 and 2023 were gone by October 2023.
For pages that existed in 2013 specifically, 38% were gone. **54% of Wikipedia pages
contain at least one dead link in their references.**

That last figure is the argument for L13 in one number. The most carefully maintained
citation graph humans have ever built is more than half broken, because a link names a
place rather than a thing.

**Xanadu.** Bidirectional links and transclusion, designed before the web and lost to it
on deployability. L13's backlinks and L10's `Quote` node are Xanadu's ideas with content
addressing doing the work that Xanadu's central address space was supposed to do.

**HTTP 402.** `402 Payment Required` has been reserved and unimplemented since HTTP/1.1.
Cited in WHITEPAPER §1 as the most expensive omission in the history of the web.

---

## Content addressing and swarm delivery

**BitTorrent** solved media delivery economics in 2001: every reader serves, so an origin
emits once regardless of audience. L7 Streams is this applied to live media.

**IPFS** and **Named Data Networking** are content addressing as a network primitive.
L6 Objects is their model with signed authorship attached.

**Hypercore** is signed append-only logs, which is what L7 manifests are.

---

## Claims in these documents with no citation

Stated plainly so they are not mistaken for established results:

1. **L16 Symmetry.** Flat returns to scale, non-transferable standing, and the ban on
   privileged clients. There is no literature demonstrating this works against a
   determined operator, and no deployment. It is the newest and weakest part of the
   design. See WHITEPAPER §6.6.
2. **L15's publish-equals-index obligation** and the authorship-not-holding distinction.
   The distinction is derived from Tor v3 onion service descriptor blinding, but the
   application to a general discovery layer is ours and is untested.
3. **L11 Affordance** as a document-native machine surface. Every current agent protocol
   wraps a web that was not designed for machines; putting the operations inside the
   signed object is a different approach and not a validated one.
4. **The four-error framing itself.** It is a way of organising known problems, not a
   result. It is useful if it predicts where the next chokepoint appears, and so far it
   has only been used to explain ones that already exist.

---

## Hardware-backed keys

**Direct Anonymous Attestation.** Brickell, Camenisch, Chen. *Direct Anonymous
Attestation.* ACM CCS 2004.
<https://eprint.iacr.org/2004/205.pdf>

Lets a TPM prove it is a genuine TPM without revealing which one, removing the per-device
correlation that the Privacy CA model creates. Adopted by the TCG into TPM 2.0 as ECDAA.

Cited in `11-hardware-keys.md` §2.2 as the real mitigation for TPM attestation privacy, and
as insufficient for our purposes: DAA removes the correlation and keeps the issuer, and that
issuer is tied to the manufacturer.

**TPM 2.0 was considered and rejected.** Not for the attestation privacy problem alone, but
because supporting it requires a second signature suite: `TPM_ECC_CURVE_25519` is registered
in the TCG Algorithm Registry yet barely implemented, and deployed TPMs do RSA and NIST-curve
ECDSA while KARST signs everything with Ed25519. Algorithm agility buys downgrade attacks and
two verifier code paths where there was one, which is directly contrary to design commitment
3. See `11-hardware-keys.md`.

**TPM 2.0 and Ed25519.** `TPM_ECC_CURVE_25519` is registered in the TCG Algorithm Registry
but is barely present in the TPM Library and PC Client specifications and rarely implemented;
deployed TPMs do RSA and NIST-curve ECDSA. This is a concrete blocker for hardware-backing
KARST identities, not a detail to sort out later.

---

## Algorithm evolution

**NIST post-quantum signature standards.** FIPS 204 (ML-DSA, formerly CRYSTALS-Dilithium)
and FIPS 205 (SLH-DSA, formerly SPHINCS+), both finalised August 2024. FIPS 206 (FN-DSA,
Falcon) expected to follow.
<https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards>

Cited in `12-algorithm-evolution.md`. The successor to Ed25519 is already named, which
removes most of the uncertainty and leaves cost as the problem: ML-DSA signatures are roughly
2.4 KB against Ed25519's 64 B. Since L4 fixes mix packets at 1024 bytes, a post-quantum
migration is a redesign of the wire format rather than a swap of a signing function.

**Agility is not negotiation.** TLS spent two decades learning that runtime cipher
negotiation is where downgrade attacks live, and TLS 1.3 responded by deleting most of the
negotiation surface rather than extending it. KARST takes the same position: one active suite
per protocol version, changed by specification on a schedule, never chosen per peer.

---

## Defending against observation

**Guard placement attacks.** Wan, Johnson et al. *Guard Placement Attacks on Path Selection
Algorithms for Tor.* PoPETs 2019.
<https://www.ohmygodel.com/publications/guard-placement-popets2019.pdf>

Counter-RAPTOR, DeNASA and LASTor, the three state-of-the-art location-aware path selection
algorithms for Tor, all fall to the same attack. An adversary contributing 0.216% of Tor's
bandwidth attains 18.22% guard selection probability, 84 times vanilla Tor. The paper also
proposes a generic mechanism that provably defends any path selection algorithm against
placement.

Cited in `13-observation-defence.md`. This is why L16's standing-disjoint path rule must not
ship as specified: any structural preference an operator can read is a placement target.

**SybilLimit.** Yu, Gibbons, Kaminsky, Xiao. *SybilLimit: A Near-Optimal Social Network
Defense against Sybil Attacks.* IEEE S&P 2008. Preceded by **SybilGuard** (Yu, Kaminsky,
Gibbons, Flaxman, SIGCOMM 2006).

Bounds accepted Sybils per attack edge to within a log *n* factor of optimal, roughly 200x
better than SybilGuard on a million-node experiment, and supplied the first real-world
evidence that social networks are fast mixing. This is the right shape for L5, which already
requires a social graph: it bounds **admission**, which is what an observer needs, rather than
**reputation**, which it does not.

---

## Value without deanonymisation

**Coconut.** Sonnino, Al-Bassam, Bano, Meiklejohn, Danezis. *Coconut: Threshold Issuance
Selective Disclosure Credentials with Applications to Distributed Ledgers.* NDSS 2019.
<https://arxiv.org/pdf/1802.07344>

Threshold issuance, selective disclosure, re-randomisation, and multiple unlinkable showings,
remaining correct when a subset of issuing authorities is malicious or offline. Its listed
applications include anonymous payments and distributing proxies for censorship resistance,
which is the L14 problem exactly.

Cited in `14-value-and-anonymity.md`. Threshold issuance is what stops the value layer
becoming error 03: a single issuer sees every request and can link every one to the party that
made it.

**RSA Blind Signatures.** RFC 9474, IRTF CFRG.
<https://www.rfc-editor.org/rfc/rfc9474>

The single-issuer ancestor, standardising Chaum's construction for untraceable payments, with
the unblinded signature verifiable by a standard RSA-PSS library. Simpler than Coconut and
without threshold issuance, so it trades the singleton back in.

`karst-value` implements neither. It implements the protocol shape and real threshold sharing,
and tests that the issuance and spend transcripts share no field. The cryptographic binding is
open work.

---

## Long-run attacks, and a contested assumption

**Statistical disclosure attacks.** Danezis, 2003, extending Kesdogan's disclosure attack.
<https://www.freehaven.net/doc/e2e-traffic/e2e-traffic.pdf> (Mathewson and Dingledine,
*Practical Traffic Analysis: Extending and Resisting Statistical Disclosure*, PET 2005)

The long-term intersection attack against mix systems. It works by differencing the recipient
population in rounds where a target is sending against rounds where they are not. Against a
steady-state mix network it is slowed but still succeeds. The conditions that make it
impractical are highly variable delivery times, an adversary who observes little, and users
who pad consistently while the adversary cannot learn how the network behaves in their
absence.

Cited in `05-anonymity.md`. KARST's constant-rate emission targets the third condition
directly, and `karst-mix::intersection` measures it: without padding the attack reaches full
attribution by round 500, with constant-rate padding it never separates the target from a
stranger. The exception it also measures is joining, since a user who arrives partway through
gives the adversary the absent-population baseline the attack needs.

**Mixing time of social graphs.** Mohaisen, Yun, Kim. IMC 2010.
<https://conferences.sigcomm.org/imc/2010/papers/p383.pdf>

Measures the mixing time of real social graphs and finds it **much larger than the literature
assumes**, so systems built on fast mixing have weaker guarantees than claimed or must be less
efficient to compensate. Directly qualifies the SybilLimit bound cited in
`13-observation-defence.md`.

---

## Fundamental limits

**Anonymity trilemma.** Das, Meiser, Mohammadi, Kate. *Anonymity Trilemma: Strong Anonymity,
Low Bandwidth Overhead, Low Latency, Choose Two.* IEEE S&P 2018.
<https://www.freehaven.net/anonbib/cache/trilemma-oakland2018.pdf>

Proves an anonymous communication protocol achieves at most two of strong anonymity, low
bandwidth overhead and low latency against a global passive adversary, with separate bounds for
synchronised and unsynchronised user behaviour.

Cited in `15-fundamental-limits.md`. This establishes that KARST's bandwidth cost is
theorem-mandated rather than an implementation defect, and it raises the question the doc then
answers: KARST pays *both* costs where the theorem requires one, which is justified because the
trilemma governs passive adversaries only and the latency is buying active resistance.

**Membership-concealing overlay networks.** Vasserman, Jansen, Tyra, Hopper, Kim. ACM CCS 2009.
<https://www.robgjansen.com/publications/mcon-ccs2009.pdf>

Formalises hiding the real-world identities of participants, so an observer cannot tell who is a
member. Three proof-of-concept designs trading efficiency against churn robustness. Membership
concealment is orthogonal to anonymity and makes pseudonymous communication and censorship
resistance easier when present.

Cited in `15-fundamental-limits.md`, where it withdraws the claim that the join boundary has no
complete defence. It has a known direction and no deployed solution, which is a different
statement.

---

## Fetch privacy and relay incentives

**Private information retrieval.** Corrigan-Gibbs and Kogan, *PIR with Sublinear Online Time*
(<https://eprint.iacr.org/2019/1075.pdf>); *Simple and Practical Amortized Sublinear PIR using
Dummy Subsets*, ACM CCS 2024 (<https://eprint.iacr.org/2023/1072.pdf>); SealPIR and the XPIR
line on query compression.

Cited in `16-fetch-privacy.md`. Online overhead approaching twice an unprotected fetch is
affordable; what is not is the surrounding structure, since sublinear schemes need client state
built with a specific server and multi-server schemes need non-colluding servers. Both are
assumptions KARST refuses elsewhere.

**Anonymous relay incentives.** TEARS (Jansen, Miller, Syverson, Ford, HotPETs 2014,
<https://www.robgjansen.com/publications/tears-hotpets2014.pdf>); BRAIDS; LIRA (NDSS 2013);
TorCoin/TorPath (<https://dedis.cs.yale.edu/dissent/papers/hotpets14-torpath.pdf>). Overview:
<https://blog.torproject.org/tor-incentives-research-roundup-goldstar-par-braids-lira-tears-and-torcoin/>

Cited in `17-paying-concealed-relays.md`. All four make the *payment* anonymous and all four
observe the *earning*, which is evidence that the conflict with membership concealment is
structural rather than an oversight. TEARS' PriorityPass construction, which lets relays prevent
double spending locally without leaking information, is directly relevant to the open question
in #44.

---

## Three decisions

**Chaum, Fiat, Naor.** *Untraceable Electronic Cash.* CRYPTO 1988.

Double spending reveals the spender rather than being prevented, via cut-and-choose over
identity shares. Needs no online authority and no consensus, which is what made every
prevention-shaped option expensive. Cited in `20-three-decisions.md` §1 and implemented in
`karst-value::doublespend`.

**Camenisch, Hohenberger, Lysyanskaya.** *Compact E-Cash.* EUROCRYPT 2005.
<https://eprint.iacr.org/2005/060>

A wallet of 2^l unlinkably spendable coins at O(l+k) complexity, and crucially
**exculpability**: a verifier can prove a double spend to a third party rather than assert it.
That matters more without an authority than with one. Not implemented.

**Samuel, Mathewson, Cappos, Dingledine.** *Survivable Key Compromise in Software Update
Systems.* CCS 2010. <https://www.freehaven.net/~arma/tuf-ccs2010.pdf>

TUF. Threshold signing, role separation, key rotation, and the timestamp role's defence against
**freeze attacks**, where an adversary withholds updates and the client believes it is current
forever. Cited in `20-three-decisions.md` §3 and implemented as `karst-object::freshness`. Two
of the four authors are Tor, and the freeze attack is the exact failure mode the Ricochet case
in `18-documented-attacks.md` demonstrates.

**Biryukov, Pustogarov.** *Proof-of-Work as Anonymous Micropayment: Rewarding a Tor Relay.*
FC 2015. <https://eprint.iacr.org/2014/1011.pdf>

Blind signatures conceal the *client* from the relay. Cited in `20-three-decisions.md` §2 as
evidence that the reverse direction, concealing the relay from an observer while still paying
it, remains unachieved.
