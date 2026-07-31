# KARST

**A network stack with no seizable chokepoint, no accumulable position, and no markup.**

> *karst*: a limestone landscape with no surface rivers. Water moves through thousands of
> dissolved channels underground, so there is nothing to dam, and when one channel silts up
> the water is already taking four others.

The internet made four design errors in the early nineteen eighties. The web, built on top of
it twenty years later, made the identical four again at the document layer. Surveillance,
takedowns, link rot, advertising, national shutdowns, credential theft, the search monopoly,
app store gatekeeping, and agents reduced to scraping pages written for human eyes are all
symptoms of one of those eight instances.

This is a seventeen layer stack, from the physical bearer to the discussion board, that commits
none of them.

**Start with [`WHITEPAPER.md`](WHITEPAPER.md).**

---

## Status

Research project. Working code for eight layers, a specification for the rest, and an itemised
list of everything the design makes worse.

> **Nothing built so far is private.** Everything below assumes a network that does not yet
> protect who is talking to whom. L4 Mixing is Phase 1 and it is the precondition for the rest
> being worth anything.

```bash
cargo test          # 60 tests
cargo run -p karst-demo
```

| Crate | Layer | What it does |
|---|---|---|
| [`karst-id`](crates/karst-id) | L2 Identity | Address is the hash of a locally generated key. No registrar, nothing to seize. |
| [`karst-object`](crates/karst-object) | L6 Objects | Canonical encoding, signed immutable objects, offline verification. |
| [`karst-blob`](crates/karst-blob) | L6/L7 Files | Chunked merkle manifests, automatic dedup, verified seeking, measured swarm delivery. |
| [`karst-doc`](crates/karst-doc) | L10 Document | A typed content-addressed node graph. Not a markup language. |
| [`karst-cap`](crates/karst-cap) | L9 Authority | Capability chains that can only ever narrow, verifiable with no directory. |
| [`karst-attest`](crates/karst-attest) | L13.1 | Human or machine authorship, declared and where possible verified. |
| [`karst-afford`](crates/karst-afford) | L11 Affordance | Typed, priced machine operations inside the signed object. |
| [`karst-thread`](crates/karst-thread) | Applications | Threads assembled from backlinks, boards as views, no host. |

## What the demo actually proves

- Identities need no registrar, and no authority could refuse or enumerate one.
- Tampering breaks both the object's name and its signature, so there is no origin to trust.
- One document serves a person and an agent with no markup, no second API, and nothing to scrape.
- Files deduplicate globally, seek verifiably with a 128 byte proof, and cost the origin exactly
  one upload whether the audience is one or ten thousand.
- Delegated authority can only ever narrow. An agent that signs itself a wider capability,
  correctly, is still rejected. An API key cannot do that.
- A community survives a hostile curator at the cost of one subscription change.
- An agent's post carries a delegation chain back to whoever is accountable. A forged claim of
  delegation is caught. A bot claiming to be human is **not** caught, and that limit is
  permanent and documented rather than papered over.

## Documents

| | |
|---|---|
| [`WHITEPAPER.md`](WHITEPAPER.md) | The complete design. All seventeen layers, the threat model, and the costs. |
| [`docs/04-lessons-from-tor.md`](docs/04-lessons-from-tor.md) | Eleven of Tor's known weaknesses, what each taught us, and what our answer costs. |
| [`docs/05-anonymity.md`](docs/05-anonymity.md) | L4 Mixing: constant-rate cover and Poisson delay, against a global passive adversary. |
| [`docs/06-messaging-and-boards.md`](docs/06-messaging-and-boards.md) | Why neither needs to be a layer. |
| [`docs/07-authorship.md`](docs/07-authorship.md) | Human versus machine content, and why detection is the wrong question. |
| [`docs/10-versioning-and-permanence.md`](docs/10-versioning-and-permanence.md) | Updating content while old versions survive, and what still needs an archive. |
| [`docs/08-roadmap.md`](docs/08-roadmap.md) | Phases, mapped to milestones. |
| [`docs/09-references.md`](docs/09-references.md) | Citations, and an explicit list of claims with none. |

## Design commitments

1. **No global singletons.** No namespace, allocator, routing table, trust root, membership
   roll, or governance body. Zero or *n*, never one.
2. **No ambient authority.** Every right is an explicit, attenuable, revocable capability.
3. **Small enough to reimplement is a security property.** A specification only two
   organisations can afford to implement has a de facto owner regardless of who wrote it.
4. **Reject, never recover.** Malformed input is an error. Parser differentials are how signed
   documents come to mean two things.
5. **State the costs.** A design that lists only its properties is a manifesto.

## What this costs

The full list is WHITEPAPER §6. The three that matter most:

- **Nothing can ever be taken down.** Content addressing plus universal re-serving means abuse
  material is exactly as permanent as everything else. No host has a plug to pull. Any version
  of this design claiming otherwise is lying about how content addressing works.
- **Ungovernable is symmetric and cannot be aimed.** The properties that defeat a censor equally
  defeat a fraud investigation and a court order for a stalker's logs. No chokepoint opens only
  for good reasons.
- **L16 may simply not work.** Flat returns to scale is the newest idea here and has no proof and
  no deployment. If it fails, this becomes another decentralised network with three companies in
  it, and the failure will not be a seizure. It will be an acquisition.

## Prior art

Almost none of this is new, which is the interesting part. Loopix, Sphinx, SCION, HIP, ILNP,
IPFS, NDN, BitTorrent, Hypercore, macaroons, KeyKOS, Certificate Transparency, Xanadu, the
Bundle Protocol. Full citations in [`docs/09-references.md`](docs/09-references.md), including a
section listing the claims here that have no citation because they are ours and untested.

## License

MIT or Apache-2.0, at your option.
