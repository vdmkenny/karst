# 18 — Audit against attacks that actually worked

Every other document here reasons about adversaries in the abstract. This one takes three
deanonymisations that happened, to real people, and asks what KARST would have done.

Two of them would work against KARST as designed. One is a finding this audit produced that
no other document had noticed.

---

## 1. BKA timing analysis, 2019 to 2021 (Boystown, Ricochet)

**What happened.** Germany's Federal Criminal Police Office ran a large number of Tor nodes
over an extended period. Timing analysis across those nodes identified the guard node used by
a Ricochet user. A Frankfurt court then ordered Telefónica to identify which o2 subscriber had
connected to that node. The administrator was arrested and sentenced in December 2022. The
victim was running an older Ricochet without Vanguards-lite.

The attack has four stages. KARST's answer differs sharply at each.

| Stage | Tor's exposure | KARST |
|---|---|---|
| Run many nodes | Anyone may join and be selected | **Fails.** L16 does not stop this, confirmed by our own simulation; L5 admission is the intended defence and is unbuilt |
| Timing correlation | Onion routing forwards promptly | **Holds.** Constant-rate cover plus Poisson delay is aimed at exactly this |
| Guard discovery | An attacker can volunteer to be your guard | **Holds.** Entry is socially introduced, so an attacker must be introduced, not merely present |
| ISP identifies the subscriber | Legal process on the access provider | **Fails, and worse than Tor.** See §2 |

**Two of four stages hold.** The stage that KARST is proudest of, timing resistance, is the one
it genuinely wins. The two it loses are the first and the last, and the last is new.

### The Vanguards detail is the one to learn from

The victim was deanonymised partly because he ran a version without the current guard
protections. Tor had shipped a defence; it was not deployed on that endpoint.

KARST has an equivalent hazard and should say so: this stack has **no update mechanism** and
no way for a user to learn their client is missing a defence. L6 gives firmware and code signed
lineage, and nothing tells anyone to fetch it. A defence that exists and is not running is worth
nothing, which is precisely what this case demonstrates.

---

## 2. The finding: constant-rate emission is an ISP-visible signature

The BKA case ended at the access provider. That final stage is the one this design has never
examined, and examining it turns up a serious problem.

**L3 hides what the bytes are. L4 mandates a shape nothing else produces.**

Ordinary residential traffic is bursty: idle overnight, spikes for a video, nothing for an hour.
L4 requires a fixed packet rate, continuously, forever. `karst-mix::exposure` measures the
separation:

| Profile | Rate variability |
|---|---|
| Ordinary browsing and streaming | > 0.8 |
| **L4 constant-rate emission** | **0.00** |

A classifier separating them scores above 99% with **a byte counter**. No payload inspection,
no protocol fingerprinting, no machine learning. Every access provider already runs the
necessary measurement for billing.

So an ISP served with "which of your subscribers uses this network" can answer it, and answer
it accurately, without touching a single packet's contents.

**This inverts one of the design's claims.** WHITEPAPER §3 L3 says the wire image adapts so
traffic is unrecognisable. That is true of the bytes and false of the pattern, and the pattern
is what the last stage of the BKA attack needed.

**The only defence is adoption.** The anonymity set here is not everyone on the network, it is
everyone *on that ISP* who emits at a constant rate. Early in deployment that is a very short
list, and a short list is a workable shortlist. This is a bootstrapping problem of a
particularly unpleasant shape: the mechanism that provides anonymity at scale is the mechanism
that removes it when few people are using it.

Nothing in the design currently addresses this. It is filed rather than fixed.

---

## 3. CMU/CERT relay-early attack, 2014

**What happened.** Researchers at Carnegie Mellon's Software Engineering Institute ran a Sybil
fleet of relays from January to July 2014 and combined it with a traffic confirmation attack.
The relays **modified Tor protocol headers**, injecting a signal into relay-early cells so that
a colluding entry relay could recognise traffic that had passed a colluding exit. Evidence
indicates the results reached the FBI, with payment reported at around one million dollars.

**KARST assessment: closed.** This audit is what prompted implementing the Sphinx construction
properly, and `karst-mix::packet` now carries it.

A tagging attack needs to modify a packet and have the modification survive somewhere it can be
recognised. Both halves are now shut:

- **The header carries a per-hop MAC, verified before any processing.** A modified header is
  dropped at the first honest relay rather than forwarded with a signal in it. Tested against
  bit flips across the whole header.
- **The payload uses a wide-block cipher rather than a stream cipher.** This was the more
  dangerous of the two defects and the easier to miss, because a stream cipher looks like
  encryption and passes every functional test. Under one, flipping ciphertext bit *k* flips
  plaintext bit *k*, which is exactly the predictable mark a confederate looks for. A single
  flipped bit now changes more than half the payload.

Replay tags are also carried and checked.

The Sybil half of the attack is the same first stage as §1, with the same answer: unaddressed
until L5 admission exists.

The Sybil half of the attack is the same first stage as §1, with the same answer: unaddressed
until L5 admission exists.

---

## 4. FBI Network Investigative Technique, Playpen 2015

**What happened.** The FBI seized a hidden service, kept it running on government
infrastructure for two weeks, pushed browser exploits to visitors, and collected real IP
addresses from the compromised endpoints.

**KARST assessment: partly better, structurally.**

Half the playbook does not apply. There is no service to seize, because content is
content-addressed and every reader is a replica, so there is no unique host to take over and
operate.

The other half is where L10 earns its keep, and this is the clearest practical argument for
decisions that otherwise look austere:

- **No scripting in documents.** A NIT needs code execution.
- **Deny-by-default sandbox** for behaviour modules, holding only capabilities handed to them.
- **No ambient network access from content**, so exfiltrating a real address requires a
  capability that was never granted.
- **A format small enough for one person to implement** has a correspondingly small attack
  surface, which is the same argument as error 03 arriving at a different destination.

WHITEPAPER §6.4 says the endpoint beats every layer above it, and that remains true. What
changes is how much endpoint there is to attack. A browser is millions of lines with a JIT; L10
is a typed node decoder. That is not immunity and it is a materially smaller target.

**Caveat.** This holds only for content rendered through L10. Anything reached through a
gateway to today's web carries today's risk in full, and during the entire adoption period
that is most content.

---

## 5. Summary

| Attack | KARST | Status |
|---|---|---|
| Timing correlation | Defended | Constant-rate cover plus Poisson delay, simulated |
| Guard discovery | Defended | Social introduction; attacker cannot volunteer |
| Seize and operate the service | Not applicable | No unique host exists |
| Endpoint exploitation | Reduced, not removed | Small format, no scripting, no ambient network |
| **Sybil relay fleet** | **Fails** | L16 confirmed insufficient; L5 admission unbuilt |
| **Tagging attack** | **Fails** | Packet format lacks Sphinx's tagging resistance |
| **ISP traffic-shape identification** | **Fails** | Constant-rate emission is a byte-counter-visible signature |

Three failures, two of which were already tracked and one of which this audit found.

The pattern worth noting: **KARST wins where it spent effort and loses where it assumed.** The
timing defence was simulated repeatedly and holds. The packet format was labelled a proof of
concept and never revisited. The ISP relationship was never examined at all, and it is where the
only real-world case in this document actually ended.

---

## References

- Tor Project. *Response to reports of German police deanonymizing users.*
  <https://blog.torproject.org/>; coverage via NDR Panorama and STRG_F, 2024.
- Schneier. *Law Enforcement Deanonymizes Tor Users.* October 2024.
  <https://www.schneier.com/blog/archives/2024/10/law-enforcement-deanonymizes-tor-users.html>
- Tor Project. *Tor security advisory: "relay early" traffic confirmation attack.* July 2014.
  <https://blog.torproject.org/tor-security-advisory-relay-early-traffic-confirmation-attack/>
- Tor Project. *Did the FBI Pay a University to Attack Tor Users?* November 2015.
  <https://blog.torproject.org/did-fbi-pay-university-attack-tor-users/>
- Tippe et al. *Onion Services in the Wild: A Study of Deanonymization Attacks.* PoPETs 2024.
  <https://www.petsymposium.org/popets/2024/popets-2024-0117.pdf>
- *De-anonymisation attacks on Tor: A Survey.* <https://arxiv.org/pdf/2009.13018>
