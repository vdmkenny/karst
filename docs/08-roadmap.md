# 08 — Roadmap and phases

Phases map to GitHub milestones. Each is gated on the previous one being genuinely done
rather than nominally done, because the failure mode of a project like this is a wide
shallow layer cake where nothing composes.

**The single most important line in this document:** nothing built so far is private.
Everything in Phase 0 assumes a network that does not yet protect who is talking to whom.
Phase 1 is not a feature, it is the precondition for the rest being worth anything.

---

## Phase 0 — Foundations `done`

The parts that could be built without a network. All 57 tests green.

| Layer | Crate | State |
|---|---|---|
| L2 Identity | `karst-id` | Ed25519 keys, self-certifying addresses, no registrar |
| L6 Objects | `karst-object` | Canonical encoding, signed immutable objects, tamper evidence |
| L6/L7 Files | `karst-blob` | Chunking, merkle manifests, dedup, verified seeking, swarm model |
| L9 Authority | `karst-cap` | Capability chains, attenuation, offline verification |
| L10 Document | `karst-doc` | Typed node DAG, no markup, one object for human and machine |
| L11 Affordance | `karst-afford` | Typed operations in the object, priced, capability-gated |
| L13.1 Authorship | `karst-attest` | Agency classes, verifiable delegation |
| Applications | `karst-thread` | Hostless threads, plural boards, authorship policy |

## Phase 1 — Anonymity `critical path`

L4 Mixing. Loopix over Sphinx. Until this exists, KARST is a content-addressed store with
good authorization and no privacy at all, and should be described that way.

- Sphinx packet format, fixed size
- Poisson mix node with per-packet exponential delay
- Constant-rate client emission with cover displacement
- Loop cover traffic and active-attack detection
- `Deferred` and `Prompt` classes, with `Prompt` visibly marked as weaker
- Simulation harness measuring the anonymity set under a global passive adversary

## Phase 2 — Reachability

Getting packets between keys when someone does not want that to happen.

- L1 sender-composed signed path segments
- L5 social introduction, bounded rate, attributable
- L3 adaptive wire image
- L0 multi-bearer with delay tolerance as the base case

## Phase 3 — Trust and discovery

- L8 plural transparency logs, no root store, no default authority set
- L15 publish-equals-index, authorship-not-holding announcement
- Local ranking, subscribable label sets
- Petname layer, with an explicit plan for not becoming singleton number seven

## Phase 4 — Economics and symmetry

The two layers most likely to be wrong.

- L14 settlement as a protocol primitive
- **Resolve the L14/L4 conflict**, or document that it cannot be resolved and pick one
- L16 flat returns, non-transferable standing, no privileged client
- Adversarial simulation of whether flat returns actually holds
- Send cost: memory-hard proof of work or socially issued allowances, neither satisfactory

## Phase 5 — Client and profiles

- L12 Agency: client-controlled rendering, capability-gated motion and interruption
- Device profile on real constrained hardware
- Agent runtime over L11
- Blinded drops for offline messaging

---

## Not on the roadmap

Deliberately, with reasons in WHITEPAPER §6:

- **Deletion.** Not available. Nothing in any phase will make content removable.
- **Bot detection.** Not attempted. See `07-authorship.md`.
- **A proof-of-personhood registry.** Incompatible with the rest of the design.
- **Backwards compatibility with HTTP or HTML.** Gateways are outside the guarantees.
- **A governance body.** If one is needed, the design failed.
