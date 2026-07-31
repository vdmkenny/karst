# 09 — References

Sources for the load-bearing claims in these documents. Where a design here is an
existing published system, that is stated rather than implied. Very little of KARST is
new; the contribution is the assembly and the four-error framing, not the primitives.

---

## Anonymity and mix networks

**Loopix.** Piotrowska, Hayes, Elahi, Meiser, Danezis. *The Loopix Anonymity System.*
USENIX Security 2017.
<https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska>

L4 Mixing is Loopix. Poisson mixing with independent per-message delays, cover traffic,
and self-injected loop traffic that lets mixes and clients detect active attacks, in a
stratified topology. The paper claims traffic analysis resistance against a global
network adversary, which is exactly the adversary onion routing declines to defend
against, and reports mix throughput above 300 messages per second with end-to-end
latency on the order of seconds.

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

Cited in `11-hardware-keys.md` §2 as the real mitigation for TPM attestation privacy, and as
insufficient for our purposes: DAA removes the correlation and keeps the issuer, and that
issuer is tied to the manufacturer.

**TPM 2.0 and Ed25519.** `TPM_ECC_CURVE_25519` is registered in the TCG Algorithm Registry
but is barely present in the TPM Library and PC Client specifications and rarely implemented;
deployed TPMs do RSA and NIST-curve ECDSA. This is a concrete blocker for hardware-backing
KARST identities, not a detail to sort out later.
