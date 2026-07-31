# 13 — Defending against observation

Simulation of L16 (`karst-symmetry`) establishes the shape of the problem: **flattening
returns to scale defends against buying position and does nothing about buying presence.**
Path coverage tracks node count, with no ceiling, because no reputation is involved to
saturate. A KAX17-sized fleet of 900 relays against 9,500 touches 25.8% of paths and holds
both endpoints of 0.90% of them under every reputation rule tested.

This document covers what the literature offers instead, including one attractive answer
that is known to make the problem worse.

---

## 1. The obvious fix is a trap

The natural response is diversity-aware path selection: prefer relays in under-represented
networks, jurisdictions or social neighbourhoods, so an adversary cannot cheaply hold both
ends of a path. L16 proposes exactly this shape, requiring hops be drawn from
standing-disjoint neighbourhoods.

Wan, Johnson et al., *Guard Placement Attacks on Path Selection Algorithms for Tor*, PoPETs
2019, break it. Counter-RAPTOR, DeNASA and LASTor are the three state-of-the-art
location-aware path selection algorithms for Tor, and all three fall to the same attack,
defeating the defences each was built around.

> **An adversary contributing 0.216% of Tor's total bandwidth attains 18.22% guard selection
> probability, 84 times what vanilla Tor would give it.**

The mechanism generalises to any selection rule an adversary can read. The rule announces
which positions are preferred, so the adversary places relays exactly there. A preference
intended to reward scarcity is a map to the most valuable place to stand.

`karst-symmetry::placement` reproduces the effect against the rule L16 proposes. With a
realistic skewed relay population and an adversary holding a quarter of one percent of relays
placed in the emptiest neighbourhoods:

| Selection rule | Selection probability | Amplification | Both endpoints |
|---|---|---|---|
| Uniform | resource share | 1.0x | baseline |
| Diversity-aware | far above resource share | **>20x** | **>400x baseline** |

Endpoint correlation goes as the square of per-hop probability, so amplification hurts twice.
That is the number that matters, because holding both ends is what deanonymises.

**Consequence for KARST: the standing-disjoint path rule in L16 is dangerous as specified and
must not ship in that form.** Any structural preference visible to relay operators is a
placement target.

The same paper proposes a generic mechanism that provably defends any path selection algorithm
against guard placement. That is the direction to take, rather than inventing a diversity rule
and hoping nobody reads it.

---

## 2. Move the defence from reputation to admission

The reason L16 cannot help is that it operates on *standing*, and an observer does not want
standing. It wants to be present. The lever that bites is therefore **admission**: how many
identities an adversary can get into the network at all.

KARST already has the necessary structure. L5 admits peers by social introduction, so there is
a social graph, and social-graph Sybil defence is a mature literature with proofs.

**SybilLimit** (Yu, Gibbons, Kaminsky and Xiao, IEEE S&P 2008) bounds the number of Sybil
identities accepted per attack edge to within a log *n* factor of optimal, roughly 200 times
better than its predecessor SybilGuard (Yu, Kaminsky, Gibbons and Flaxman, SIGCOMM 2006) in a
million-node experiment.

This is the right shape for L5:

- It bounds **admission**, which is what an observer needs, rather than **reputation**, which
  it does not.
- It needs a social graph, which L5 already requires for unrelated reasons.
- It produces a bound with a proof rather than a hope.

### The assumption underneath it is contested

Both protocols rest on social graphs being **fast mixing**, meaning a short random walk
approaches the stationary distribution. SybilLimit presented evidence for it.

Mohaisen, Yun and Kim measured it directly (*Measuring the Mixing Time of Social Graphs*, IMC
2010) and found **the mixing time of real social graphs is much larger than the literature
assumes.** Their stated consequence is that systems built on fast mixing either have weaker
guarantees than claimed, or must run less efficiently to compensate.

That is not a reason to abandon the approach, and it is a reason not to quote SybilLimit's
bound as though it transfers unexamined. The bound is contingent on a graph property that has
been measured and found weaker than assumed, and KARST's introduction graph is not a general
social network anyway: it is built by deliberate introductions for the purpose of joining a
network, which may mix better or worse than a friendship graph and has never been measured
because it does not exist.

**So the honest position is that L5 adopts SybilLimit's structure and owes a measurement.**
Quoting the log *n* bound before measuring the graph it applies to would repeat the error the
IMC paper documents.

---

## 3. The residual, stated plainly

SybilLimit bounds Sybils **per attack edge**. An adversary who genuinely infiltrates the
social graph, by buying, coercing or patiently earning real relationships, gets Sybils in
proportion to the edges they acquire. The bound constrains *cheap* Sybils and not *determined*
ones.

For a well-resourced actor of the kind that ran KAX17 for four years across more than fifty
autonomous systems without attribution, patience is the cheap input. So:

- Admission control raises the price of a fleet from "rent servers" to "acquire social
  standing with many independent people", which is a large increase and not a wall.
- Nothing here helps against an adversary willing to spend years.
- The design should say this rather than claim Sybil resistance.

---

## 4. Where this leaves the design

1. **L16 keeps its scope.** It defends against acquisition, which the simulation confirms it
   does. It is not a Sybil defence and the whitepaper no longer implies it is.
2. **L5 acquires the real work.** Social introduction becomes a SybilLimit-style admission
   bound with an explicit parameter, rather than an unquantified "bounded rate".
3. **L4 path selection stays uniform over admitted relays**, or uses a defence with a proof.
   A readable diversity heuristic is worse than uniform random.
4. **The residual is documented, not closed.** A patient well-funded adversary who invests in
   the social graph gets in, in proportion to that investment.

---

## References

- Wan, Johnson et al. *Guard Placement Attacks on Path Selection Algorithms for Tor.* PoPETs
  2019. <https://www.ohmygodel.com/publications/guard-placement-popets2019.pdf>
- Yu, Gibbons, Kaminsky, Xiao. *SybilLimit: A Near-Optimal Social Network Defense against
  Sybil Attacks.* IEEE S&P 2008.
- Yu, Kaminsky, Gibbons, Flaxman. *SybilGuard: Defending Against Sybil Attacks via Social
  Networks.* SIGCOMM 2006.
- Mohaisen, Yun, Kim. *Measuring the Mixing Time of Social Graphs.* IMC 2010.
  <https://conferences.sigcomm.org/imc/2010/papers/p383.pdf>
