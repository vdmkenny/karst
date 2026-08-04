# 12 — Algorithm evolution without algorithm negotiation

Ed25519 is the right default now. It will not be the right default in ten years, and it is
outright wrong the day a cryptographically relevant quantum computer exists. A stack whose
signatures are permanent records is a stack that has to plan for its own primitives being
broken.

`11-hardware-keys.md` rejects TPM 2.0 partly on the grounds that supporting it requires a
second signature suite. That objection is narrow and specific, and this document states its
scope: a second suite is unacceptable when it is permanent and selected per peer, and
necessary when it is a versioned migration.

---

## 1. The distinction that does the work

**Agility is not negotiation.** These get conflated constantly and they have opposite
security properties.

| | Runtime negotiation | Versioned evolution |
|---|---|---|
| Who picks | The two endpoints, per connection | The specification, once |
| Attack surface | Downgrade to the weakest mutually supported option | None: there is nothing to downgrade to |
| Verifier code paths | All suites, simultaneously, forever | One, plus a bounded migration window |
| Failure mode | Silent weakening | Loud incompatibility |

TLS spent two decades learning this the hard way, and TLS 1.3 responded by deleting most of
the negotiation surface rather than adding more options to it.

So the rule is:

> **KARST has exactly one active signature suite at any protocol version. There is no
> capability discovery, no "which algorithms do you support" exchange, and no per-peer
> choice. Changing the suite means a new protocol version, on a schedule, with a fixed
> migration window and a hard end date.**

That permits evolution and forbids negotiation, which is what we actually want. The TPM
objection survives under this framing, but for the accurate reason: a TPM needs a *concurrent
second suite for some peers and not others*, chosen by what hardware someone happens to own.
That is negotiation, and it is permanent rather than a bounded migration.

---

## 2. What has to be in place before it is needed

### The suite identifier is inside the signed bytes

Every signing context already begins with a domain string: `karst.object.v1`,
`karst.grant.v1`, `karst.invoke.v1`, `karst.node.v1`. That version is covered by the
signature, so it cannot be stripped or rewritten by an attacker, and a verifier that does not
recognise it **rejects** rather than guessing. This is the single most important piece and it
holds throughout the codebase.

A v2 suite becomes `karst.object.v2`. A v1 verifier does not silently accept it, and a v2
verifier does not silently accept v1 once v1 is retired.

### Identity migration has machinery

An address is the hash of a public key, so a new signature algorithm means a new address. That
looks catastrophic for a system built on stable identity and is not, because L13 carries signed
lineage.

The migration is: publish an object under the old key that names the new key, signed by the
old key, and an object under the new key that names the old one, signed by the new key. Both
directions, so neither key alone can claim the other. Anyone holding the pair can follow an
old reference to a current identity, exactly as `Lineage` already follows a superseded
document to its head.

The same-author rule on lineage edges has an explicit exception for this: a key rotation is the
one legitimate cross-key edge. `Rotation` in `karst-object` implements it, and **both halves are
required**. The old key attests to its successor and the new key attests to its predecessor,
because backward-only would let anyone claim to be anyone's successor from public bytes alone. A
one-sided claim moves nothing.

Countersigning does not survive compromise of the old key, which produces both halves: the
forward with the stolen key, the backward with the attacker's own over the old key's public
bytes. The containment is that two countersigned successions from one address fork the identity
and neither certifies an edge, so a holder who still has their key can make the theft visible.

### Hashes are the harder problem, and they are worse

Signatures protect *future* claims. A content address is a *permanent name*. If BLAKE3 is
broken, every reference in every document everywhere points at a name that an attacker can
now collide, and there is no migration that preserves the references, because the reference
*is* the hash.

Realistic mitigations, none of them good:

- **Multihash-style self-describing digests**, so a v2 hash is distinguishable rather than
  ambiguous. **Implemented.** A `Cid` carries an algorithm tag and a digest length, both inside
  the canonical encoding, and a decoder rejects an unknown algorithm rather than assuming the
  current one. Two bytes per reference. It does not save existing references, which is exactly
  why it had to exist before there were any.
- **Re-anchoring**: a signed statement that old-hash *X* and new-hash *Y* name the same bytes,
  which is only trustworthy if published before the break.
- **Accept that pre-break content becomes advisory** rather than verifiable.

This deserves stating plainly because it is a genuine unsolved weakness of every
content-addressed system, and KARST is more exposed than most because L13 and L15 both assume
that a hash is a permanent name.

---

## 3. The post-quantum case specifically

NIST finished its signature standardisation in August 2024:

- **FIPS 204, ML-DSA** (formerly CRYSTALS-Dilithium), the primary lattice-based signature
  standard.
- **FIPS 205, SLH-DSA** (formerly SPHINCS+), hash-based, deliberately built on different
  mathematics as a hedge in case ML-DSA falls.
- **FIPS 206, FN-DSA** (Falcon) is expected to follow.

So the successor is already named, which removes most of the uncertainty. What remains is
cost. ML-DSA signatures are roughly two kilobytes against Ed25519's sixty-four bytes, and
public keys are over a kilobyte against thirty-two. For a stack where **every object, every
grant in a capability chain, and every mix packet carries signatures**, that is not a detail:

- L4 fixes packets at 1024 bytes. A 2.4 KB signature does not fit in one, full stop.
- A capability chain of four grants goes from roughly 400 bytes to roughly 10 KB.
- Object overhead stops being negligible relative to small payloads.

**A post-quantum migration is a redesign of the wire format, not a swap of a signing
function.** Anyone claiming otherwise has not looked at the sizes.

### The hybrid question

The standard transitional move is to sign with both, so a break in either leaves you covered.
It doubles the cost of something that is already the dominant cost, and it means two
verifications on every object.

For KARST the honest position is that hybrid is right for **long-lived, high-value objects**,
where a signature has to hold up for decades: identity keys, key rotation records, and root
capability grants. It is wrong for **high-volume ephemeral traffic**, where the cost falls on
every packet and the value of a decades-long guarantee is nil. That is a per-object-type
decision fixed by the specification, not a per-peer negotiation, so it does not violate §1.

---

## 4. Consequences

Nothing changes in the wire format. Two things follow:

1. **The TPM objection is scoped.** It targets a *permanent concurrent* second suite selected
   by hardware ownership, which is negotiation. It is not an objection to changing algorithms.
2. **Migration groundwork is in place.** Version strings sit inside the signed bytes, the
   lineage machinery exists, key rotation is a countersigned cross-key edge, and digests are
   self-describing.

What remains is the hard part rather than the preparation: choosing a successor suite, and the
hash problem in §2, which self-description makes *navigable* rather than solved. A future
verifier can tell an old digest from a new one; it still cannot verify content named under a
broken hash.

---

## 5. Sizes, for reference

| Scheme | Signature | Public key |
|---|---|---|
| Ed25519 | 64 B | 32 B |
| ML-DSA-44 | ~2.4 KB | ~1.3 KB |
| SLH-DSA-128s | ~7.8 KB | 32 B |

SLH-DSA's tiny key and enormous signature make it attractive for rarely-signed, long-lived
records like key rotations, and unusable for anything per-packet. That asymmetry is worth
exploiting rather than treating the choice as a single global decision.
