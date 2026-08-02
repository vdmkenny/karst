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

Research project. Working code for ten layers, a specification for the rest, and an itemised
list of everything the design makes worse.

> **L4 mixing runs.** `karst-net-demo` stands up seven mixes in four layers on real UDP
> sockets, one thread each, and two clients exchange messages through them with cover traffic
> carrying the rest of the stream. Against a whole-network observer the design holds the
> adversary to chance, at roughly 200x bandwidth. Poisson delay earns its place against an
> *active* adversary, where a batch mix is isolated 51.7% of the time and a Poisson mix 0.7%.
> Against a *patient* one, constant-rate emission defeats statistical disclosure entirely,
> **except at the moment you join**, which fully deanonymises a user the adversary was already
> watching. See [`docs/05-anonymity.md`](docs/05-anonymity.md) and
> [`docs/21-a-running-network.md`](docs/21-a-running-network.md).

```bash
cargo test          # 503 tests
cargo run -p karst-net --bin karst-net-demo    # a real network on real sockets, with live drop detection
cargo run -p karst-index --bin karst-search    # discovery with 200,000 sybils in the room
cargo run --release -p karst-stack --bin karst-stack-demo  # the whole stack, composed
cargo run --release -p karst-net --bin karst-bulkcost      # what the mixnet cannot carry
cargo run -p karst-demo
cargo run -p karst-mix --bin karst-mixsim      # anonymity vs passive and active adversaries
cargo run -p karst-symmetry --bin karst-symsim  # does flat returns prevent capture?
```

| Crate | Layer | What it does |
|---|---|---|
| [`karst-path`](crates/karst-path) | L1 Path | Senders compose paths from signed segments. Nothing converges, nothing is allocated. |
| [`karst-id`](crates/karst-id) | L2 Identity | Address is the hash of a locally generated key. No registrar, nothing to seize. |
| [`karst-member`](crates/karst-member) | L5 Membership | No roll to enumerate, and introduction by shared contact via private set intersection. |
| [`karst-object`](crates/karst-object) | L6 Objects | Canonical encoding, signed immutable objects, offline verification. |
| [`karst-blob`](crates/karst-blob) | L6/L7 Files | Chunked merkle manifests, automatic dedup, verified seeking, measured swarm delivery. |
| [`karst-doc`](crates/karst-doc) | L10 Document | A typed content-addressed node graph. Not a markup language. |
| [`karst-witness`](crates/karst-witness) | L8 Witness | Countersigning that a publisher only moved forward. A witness can refuse and cannot lie. |
| [`karst-cap`](crates/karst-cap) | L9 Authority | Capability chains that can only ever narrow, verifiable with no directory. |
| [`karst-attest`](crates/karst-attest) | L13.1 | Human or machine authorship, declared and where possible verified. |
| [`karst-agency`](crates/karst-agency) | L12 Agency | A document requests a rendering, the client decides, and the fetch pattern says nothing. |
| [`karst-afford`](crates/karst-afford) | L11 Affordance | Typed, priced machine operations inside the signed object. |
| [`karst-mix`](crates/karst-mix) | L4 Mixing | Sphinx packets with per-hop MAC and wide-block payload, plus four adversary simulators. |
| [`karst-node`](crates/karst-node) | L4 Mixing | A mix that runs: defended clock, delay queue, shuffled release, eviction by remaining hold. |
| [`karst-wire`](crates/karst-wire) | L3 Wire | One datagram size, Poisson emission drawn without reference to the queue. |
| [`karst-seal`](crates/karst-seal) | L4/L6 | HPKE base mode. Sealing keys are separate from identity keys, on purpose. |
| [`karst-net`](crates/karst-net) | L3-L5 | Directory, stratified routes, providers, clients, public feeds. The network, running. |
| [`karst-stack`](crates/karst-stack) | all | The layers composed: publish a document, a stranger reads it, over real sockets. |
| [`karst-index`](crates/karst-index) | L15 Discovery | Publishing is announcing. Ranking is the reader's, and every stranger together counts once. |
| [`karst-symmetry`](crates/karst-symmetry) | L16 Symmetry | Does flattening returns to scale actually prevent capture? Partly. |
| [`karst-value`](crates/karst-value) | L14 Value | Capacity credentials, earned by relaying and spent unlinkably. No bank. |
| [`karst-fuzz`](crates/karst-fuzz) | commitment 4 | Property tests for reject-never-recover across every decoder. |
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
- Capacity credentials are earned by relaying and spent unlinkably: the issuance transcript and
  the spend transcript share no field, and no bank is involved anywhere in the loop.

## Documents

| | |
|---|---|
| [`WHITEPAPER.md`](WHITEPAPER.md) | The complete design. All seventeen layers, the threat model, and the costs. |
| [`docs/04-lessons-from-tor.md`](docs/04-lessons-from-tor.md) | Eleven of Tor's known weaknesses, what each taught us, and what our answer costs. |
| [`docs/05-anonymity.md`](docs/05-anonymity.md) | L4 Mixing: constant-rate cover and Poisson delay, against a global passive adversary. |
| [`docs/06-messaging-and-boards.md`](docs/06-messaging-and-boards.md) | Why neither needs to be a layer. |
| [`docs/07-authorship.md`](docs/07-authorship.md) | Human versus machine content, and why detection is the wrong question. |
| [`docs/10-versioning-and-permanence.md`](docs/10-versioning-and-permanence.md) | Updating content while old versions survive, and what still needs an archive. |
| [`docs/11-hardware-keys.md`](docs/11-hardware-keys.md) | TPM 2.0 considered and rejected, and where the line actually falls. |
| [`docs/12-algorithm-evolution.md`](docs/12-algorithm-evolution.md) | Ed25519 is not forever. Versioned evolution, never runtime negotiation. |
| [`docs/13-observation-defence.md`](docs/13-observation-defence.md) | Why diversity-aware path selection backfires, and where the Sybil defence actually belongs. |
| [`docs/14-value-and-anonymity.md`](docs/14-value-and-anonymity.md) | Paying for capacity without deanonymising the payer. |
| [`docs/15-fundamental-limits.md`](docs/15-fundamental-limits.md) | The anonymity trilemma, why the bandwidth cost is a theorem, and one claim withdrawn. |
| [`docs/16-fetch-privacy.md`](docs/16-fetch-privacy.md) | Requesting an object names it. Most of a catalogue is tail, so most requests identify you. |
| [`docs/17-paying-concealed-relays.md`](docs/17-paying-concealed-relays.md) | You cannot conceal that a node relays and pay it for relaying. |
| [`docs/18-documented-attacks.md`](docs/18-documented-attacks.md) | Audited against three deanonymisations that actually happened. Two would work. |
| [`docs/19-where-the-design-is-wrong.md`](docs/19-where-the-design-is-wrong.md) | Stocktake: what needs a decision, what needs research, what is merely unbuilt. |
| [`docs/20-three-decisions.md`](docs/20-three-decisions.md) | Three decisions taken, and why all three option lists were incomplete. |
| [`docs/08-roadmap.md`](docs/08-roadmap.md) | Phases, mapped to milestones. |
| [`docs/09-references.md`](docs/09-references.md) | Citations, and an explicit list of claims with none. |

## Design commitments

1. **No global singletons.** No namespace, allocator, routing table, trust root, membership
   roll, or governance body. Zero or *n*, never one.
2. **No ambient authority.** Every right is an explicit, attenuable, revocable capability.
3. **Small enough to reimplement is a security property.** A specification only two
   organisations can afford to implement has a de facto owner regardless of who wrote it.
4. **Reject, never recover.** Malformed input is an error, and every accepted byte string
   re-encodes to itself, so exactly one encoding names each value. Parser differentials are how
   signed documents come to mean two things. Enforced by `karst-fuzz`, not by assertion.
5. **State the costs.** A design that lists only its properties is a manifesto.
6. **Attack it, do not exercise it.** Tests that confirm a thing works find fewer defects than
   tests that ask what an adversary with a stated capability does. Every defect found in this
   repo was found the second way and none by the first. The largest was a total break of L4
   that eighty-six passing tests did not see, because every one of them put the adversary
   outside the route and the adversary that mattered was on it (#101, `docs/28-blinding.md`).
   Naming the adversary is the part that does the work; if the name is wrong the tests are
   decoration.
7. **A test must be able to fail.** Naming a security property is not testing it. Four tests
   here asserted properties they were structurally incapable of detecting, and each passed
   from the day it was written:
   - one varied a parameter the function under test did not take;
   - one flipped a byte to `0x41` when only `0x02` mattered;
   - one compared a slice to itself;
   - one exercised only the case where the adversary does nothing.

   So a test that claims an adversary cannot do X must contain the input where the adversary
   tries hardest, and a test asserting something is absent must first show it could have been
   present. Where that is not obvious, the test says how it could fail.
8. **Fix both sides.** A rule enforced where an object is produced and not where it is consumed
   is not enforced. Three defects here were rules present in the writer and missing in the
   reader, twice in code whose earlier half had been fixed hours before.

## What this costs

The full list is WHITEPAPER §6. The three that matter most:

- **Nothing can ever be taken down.** Content addressing plus universal re-serving means abuse
  material is exactly as permanent as everything else. No host has a plug to pull. Any version
  of this design claiming otherwise is lying about how content addressing works.
- **Ungovernable is symmetric and cannot be aimed.** The properties that defeat a censor equally
  defeat a fraud investigation and a court order for a stalker's logs. No chokepoint opens only
  for good reasons.
- **L16 defends against half its threat.** Simulation shows the per-node ceiling does hold and does
  stop an advantage compounding. It does nothing about an adversary who buys *presence* rather than
  position: a KAX17-sized fleet touches a quarter of all paths under every rule tested.

## Prior art

Almost none of this is new, which is the interesting part. Loopix, Sphinx, SCION, HIP, ILNP,
IPFS, NDN, BitTorrent, Hypercore, macaroons, KeyKOS, Certificate Transparency, Xanadu, the
Bundle Protocol. Full citations in [`docs/09-references.md`](docs/09-references.md), including a
section listing the claims here that have no citation because they are ours and untested.

## License

MIT or Apache-2.0, at your option.
