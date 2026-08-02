# 27 — Path

BGP has no notion of who is entitled to announce a prefix. An announcement is believed because
it was made, so a network claiming a route it does not operate is indistinguishable from one
that does until somebody notices. And because there is one global consensus, one operator's
mistake or one operator's compliance with an order becomes everybody's outage.

---

## What the measurement literature says the problem actually is

Worth establishing before proposing anything, because the incident lists everyone quotes are
not measurements.

Argus (Shi, Xiang, Wang, Yin, Wu, IMC 2012) ran control-plane and data-plane correlation for
over a year: roughly 40,000 routing anomalies yielded **220 confirmed stable prefix hijackings**,
about 0.55% of raw anomalies. Around **20% lasted under ten minutes**.

Operators remember it differently. A survey of 75 network operators (Sermpezis, Kotronis,
Dainotti, Dimitropoulos, CCR 2018) reports **57% of hijacks lasting more than an hour and 25%
more than a day**. The two disagree in character rather than in fact: the automated view sees a
heavy short tail the operators do not recall, which is itself informative about detection.

Testart, Richter, King, Dainotti and Clark (IMC 2019) take a per-network view and identify
**around 900 networks** behaving like serial hijackers, "often over the course of many months or
even years".

---

## The deployed defence, and why its record argues against incrementalism

RPKI route origin validation is what actually shipped. Reading its record matters here, because
if a global routing consensus could be secured incrementally then this layer would not need to
exist.

| | |
|---|---|
| Prefixes with a ROA | about two thirds |
| Networks **fully protected** by validation | 12.3% (RoVista, IMC 2023) |
| Networks classified as protected that enforce **nothing** | 68.5%, inheriting filtering from a transit provider |
| Reachability for RPKI-invalid routes restored by disabling validation at **13 tier-1 networks** | 23.8% of the internet |

That last row is the one to sit with. The security property is not distributed across the
networks that adopted it; it is held by about thirteen operators. **That is a centralisation
result rather than a resilience result**, and it reproduces the failure mode this design exists
to remove, inside the mechanism meant to fix it.

RPKI also **fails open by design**: when a relying party cannot retrieve objects from a
publication point, routers decide without validation. Stalloris (Hlavacek, Jeitner, Mirdita,
Shulman, Waidner, USENIX Security 2022) turns that into an attack, finding at least 47% of
public repositories vulnerable to an off-path rate-limiting variant. An adversary does not need
to break the cryptography, only the availability.

And BGPsec, the successor that validates the whole path rather than the origin, has essentially
no deployment. Lychev, Goldberg and Schapira (SIGCOMM 2013) give the load-bearing reason:
partial deployment interacting with plain BGP **can introduce new vulnerabilities**. A defence
that is worse than nothing until nearly everyone has it does not get adopted by anyone.

---

## The mechanism

An operator signs the segments it is willing to carry. A sender composes an end-to-end path
from segments it holds and carries the path in the packet. Nothing converges, so there is no
leak and no withdrawal; nothing was allocated, so there is no authority to revoke from.

This is SCION's design rather than a new one, and the honest summary of SCION is narrower than
"it works": commercial traffic since 2017, specifications still Internet-Drafts on the
Independent Submission stream after nine years, and a break of its own data plane published by
its own authors — standard SCION's hop-field authorisation permits token reuse, which EPIC
(Legner, Klenze, Wyss, Sprenger, Perrig, USENIX Security 2020) fixes with per-packet MACs.

Source routing's own history also has to be acknowledged rather than skipped. IPv4 loose and
strict source routing were disabled everywhere for concrete reasons enumerated in RFC 7126:
bypassing firewall rules, reaching otherwise unreachable systems, stealthy connection
establishment, topology discovery, and bandwidth exhaustion. IPv6's Type 0 Routing Header was
deprecated outright by RFC 5095 after a demonstrated **88-fold amplification** from a packet
oscillating between two processing nodes.

Both classes are addressed here structurally rather than by policy. A segment is signed by the
operator that will carry it, so a path cannot name a party that never agreed; and `MAX_SEGMENTS`
plus loop refusal in `Path::assemble` means an oscillating path is not constructible, which is
the RH0 amplification removed by making it unrepresentable rather than by asking routers to drop
it.

---

## What a signature buys, stated narrowly

A segment is a claim of **willingness by a named party**, not a promise of delivery. Signing
removes exactly one thing: announcing a route you do not operate. It does not stop an operator
dropping traffic it agreed to carry, and no signature can, because carriage is a future act and
a signature is about the present.

> A path names, verifiably and in advance, every party that must misbehave for it to fail.

Attribution rather than prevention, which is where this design keeps landing.

### The binding is narrower than it looks

A segment carries its operator's verifying key; an address is that key's hash; the two must
agree. Checking the signature alone is **not** enough, and the reason took a mutation to find.

Relabelling a segment's operator invalidates its signature, because the operator is inside the
signed bytes. So the obvious attacks are caught by the signature and the binding looks
redundant. The case it actually protects cannot be built through the constructor at all: an
attacker signs bytes that **name the victim** and presents their own key. The signature verifies
under the key given, and without the binding the segment reads as the victim's.

That is announcing a route you do not operate, arriving through the check meant to stop it. The
test for the layer's whole point passed with the binding deleted until that case was
constructed directly.

---

## Two senders holding different segments are both correct

Neither advertises anything onward and neither is authoritative. That is the absence of
convergence rather than a weaker form of it, and it is asserted as a test rather than as prose.

In BGP the two would disagree, one would be wrong, and the disagreement would propagate.

---

## Selection is not made here

Which of several valid paths a sender takes is an L4 question. A structural preference that
relay operators can read is a placement target: an adversary with **0.216% of Tor's bandwidth
reached 18.22% of guard selections** against location-aware selection algorithms (Wan, Johnson,
Wails, Wagh, Mittal, PoPETs 2019(4)). `compose` returns paths in an order that is a function of
the paths rather than of anything an operator can influence by how it presents itself.

---

## What is not built

- **Distribution of segments.** A sender composes from what it holds and nothing here tells it
  anything. This is the same gap as every other layer's distribution story.
- **The economics.** Sender-chosen paths mean the sender decides who gets paid, which inverts
  transit settlement. The whitepaper records this as open and it remains open.
- **Carriage itself.** Nothing forwards a packet along a composed path; this layer decides what
  a path is and whether one is valid.

---

## References

- Shi, Xiang, Wang, Yin, Wu. *Detecting prefix hijackings in the internet with Argus.* IMC 2012.
- Sermpezis, Kotronis, Dainotti, Dimitropoulos. *A Survey among Network Operators on BGP Prefix
  Hijacking.* ACM SIGCOMM CCR 48(1), 2018.
- Testart, Richter, King, Dainotti, Clark. *Profiling BGP Serial Hijackers.* IMC 2019.
- Li, Lin, Ashiq, Aben, Fontugne, Phokeer, Chung. *RoVista: Measuring and Analyzing Route Origin
  Validation in RPKI.* IMC 2023.
- Hlavacek, Jeitner, Mirdita, Shulman, Waidner. *Stalloris: RPKI Downgrade Attack.* USENIX
  Security 2022.
- Lychev, Goldberg, Schapira. *BGP security in partial deployment: is the juice worth the
  squeeze?* ACM SIGCOMM 2013.
- Legner, Klenze, Wyss, Sprenger, Perrig. *EPIC: Every Packet Is Checked in the Data Plane of a
  Path-Aware Internet.* USENIX Security 2020.
- Gont. *Implementation Advice for IP Version 4 Options.* RFC 7126 / BCP 186.
- Abley, Savola, Neville-Neil. *Deprecation of Type 0 Routing Headers in IPv6.* RFC 5095.
- Wan, Johnson, Wails, Wagh, Mittal. *Guard Placement Attacks on Path Selection Algorithms for
  Tor.* PoPETs 2019(4).
