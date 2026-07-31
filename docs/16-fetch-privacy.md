# 16 — What a fetch reveals

A gap the design has never addressed.

L15 makes announcement an obligation of **authorship** rather than **holding**, so replicating
an object is not observable. That protects the holder. It says nothing about the **fetcher**,
and content addressing means a request names exactly one object by hash.

L4 conceals *who* is asking. It does not conceal *what* is asked for. For a rare enough object
those are the same fact.

---

## 1. Where the line falls

The fetcher is hidden among the parties who plausibly want the object, not among the
population. `karst-mix::retrieval` measures it:

| Parties interested | Identification | Mixing alone |
|---|---|---|
| 10,000 | 0.01% | sufficient |
| 20 | 5% | borderline |
| 3 | 33% | insufficient |
| 1 | **100%** | **useless** |

A population of ten million does not help if three people want the document. **If one party in
the world wants a given object, observing a request for it identifies them completely,
regardless of how well the sender is hidden.**

The boundary is the reciprocal of whatever identification probability you will tolerate: at a
5% threshold, mixing suffices down to twenty interested parties and no further.

## 2. How much of a catalogue this covers

Under a Zipf-ish popularity curve, which is what real catalogues look like:

| Catalogue vs population | Exposed fraction |
|---|---|
| 10,000 objects, 100,000 readers | ~49% |
| 100,000 objects, 10,000 readers | **>98%** |

The second row is the realistic one. Real catalogues hold far more objects than the network
holds people, so almost everything is tail, and almost every fetch is identifying.

This is not an edge case to note and move past. It is the normal case.

---

## 3. What would fix it

**Private information retrieval.** PIR lets a client retrieve a record without the server
learning which record. It is the direct answer and it is expensive.

The state of the art has moved a long way. SealPIR compresses queries to roughly 1/27 of
XPIR's. Offline/online schemes reach O(√n) total communication, online time and client storage
using only linearly homomorphic encryption, with no public-key operations in the online phase.
Amortised sublinear schemes report online response overhead around twice that of simply
fetching the entry with no privacy at all.

Twice the cost of an unprotected fetch is affordable. The catch is what surrounds it:

- Single-server PIR classically requires the server to touch the **whole database per query**.
  Sublinear schemes escape this with client state and preprocessing, which means a client that
  has done offline work with *that server*, which is a relationship KARST otherwise avoids.
- A content-addressed store is not a fixed database. Objects arrive and leave constantly, and
  most PIR preprocessing assumes a database that holds still.
- PIR hides *which* record from *one* server. KARST fetches from whoever has the object, so
  the natural design is multi-server, and multi-server PIR needs non-colluding servers, which
  is an assumption this stack refuses to make anywhere else.

---

## 4. The cheaper mitigations, and their limits

**Fetch more than you want.** Request a set containing the target. Cost scales with the set
size and the anonymity gained is exactly the set size, so buying a 20-fold anonymity set costs
20 times the bandwidth. This is PIR's poor relation and it composes badly with the trilemma
cost already being paid.

**Fetch what you do not want.** Cover fetches, on the same principle as L4's cover traffic and
with the same objection: it works, and it is charged continuously to everyone.

**Prefetch popularly.** Pull the popular head of the catalogue whether or not you want it, so
that a later request for a tail object is not the first time you touched that neighbourhood.
Helps against a coarse observer and not against one who watches which object you actually read.

**Ask a peer who already has it.** If retrieval is from a socially introduced peer (L5) rather
than from a public index, the observer set is much smaller. This does not remove the leak, it
narrows who receives it, and it is the mitigation KARST gets for free from its existing
structure.

---

## 5. Position

The honest statement, which the whitepaper now carries:

> **KARST conceals who is fetching and does not conceal what is fetched. For objects with
> many readers this is sufficient. For the long tail, which is most of a real catalogue, a
> request identifies its requester and no layer in the stack currently prevents that.**

PIR is the known answer, it is nearly affordable, and adopting it collides with the
no-relationship and no-non-collusion-assumption commitments elsewhere in the design. That
collision is unresolved.

---

## References

- Angel et al. **SealPIR**, and the XPIR line of work on query compression.
- Corrigan-Gibbs, Kogan. *Private Information Retrieval with Sublinear Online Time.*
  <https://eprint.iacr.org/2019/1075.pdf>
- *Simple and Practical Amortized Sublinear Private Information Retrieval using Dummy Subsets.*
  ACM CCS 2024. <https://eprint.iacr.org/2023/1072.pdf>
