# Why the group element is blinded and not re-derived

Record of a total break of L4 that shipped, passed 500 tests, and was found by an evaluation
pass rather than by any test. Issue #101.

## 1. The defect

Sphinx gives each hop a shared secret `s_i` and an element `α_i`. This crate derived the next
element from the shared secret:

```rust
eph = StaticSecret::from(subkey(&shared, "next"));
alpha = PublicKey::from(&eph).to_bytes();
```

Both the sender and the forwarding hop ran that line, which is what made it look correct: the
packet routed, every MAC verified, and the element visibly changed at every hop, so an external
observer could not link the packet across a node.

The hop is not an external observer. `StaticSecret::from(subkey(&shared, "next"))` **is the
private scalar** behind the next element, and the forwarding hop computes it from a shared secret
it holds by right. With that scalar and the next hop's public key it computes the next hop's
shared secret, checks the guess against `γ_{i+1}` (an exact confirmation, not a statistical one),
and repeats.

One relay therefore recovered the full remaining route, every remaining per-hop secret, the exit
node, and the plaintext. A client's first hop already knows the client's address, so the adversary
that breaks this is the weakest one in the threat model: a single relay, run by anyone.

Verified by exploit against the unmodified crate, holding only hop 0's key and public directory
entries:

```
hop 0: recovered shared secret e06829f09c9abf18   next hop id = 1
hop 1: recovered shared secret 7a10f145abba337b   next hop id = 2
hop 2: TERMINAL
recovered payload: "the exit hop and the plaintext are supposed to be secret"
```

Without a directory the attack still runs: the hop tries each relay key it knows and `γ` says
which one is right.

## 2. How it got in

The deviation was deliberate, reasoned, and written down. The module said so:

> **The group element is re-derived rather than blinded.** Sphinx computes `α_{i+1} = α_i^{b_i}`
> in a prime-order group. X25519 clamps scalars, so composing blindings that way does not behave
> as the proof assumes. Here each hop derives a fresh element from the shared secret instead,
> which preserves per-hop unlinkability and is not the construction the security proof covers.

Every clause before the last is true. X25519 clamps: it clears the low three bits and sets bit
254 of every scalar, so `b·(a·G) ≠ (ab)·G` and a blinding chain does not compose. The
disclaimer even conceded that the proof does not cover the result.

The failure was in what got disclaimed. "Not covered by the proof" was treated as a bounded
weakening, when what had actually happened was that the property the proof establishes had been
inverted. And "preserves per-hop unlinkability" was asserted against the wrong adversary: it
holds against an observer of the wire and fails against a member of the route, which is the
adversary the layer exists for.

The general lesson, which is the reason this document exists: **a primitive that does not fit is
a reason to change the primitive, not the construction.** The workspace already depended on
`curve25519-dalek` for L5, so a prime-order group was one line of Cargo.toml away.

## 3. What the tests were doing instead

Eighty-six tests covered this module, including an `adversarial` section. The nearest one was:

```rust
fn the_same_message_is_unrecognisable_between_hops()
```

which counts matching wire bytes between consecutive hops. That is an external-observer property,
and it passed, correctly, on broken code. `the_wrong_node_cannot_peel_the_layer` used a stranger's
key rather than a route member's.

Nothing asked what a hop could compute **from its own shared secret**. The adversary was always
outside the route, so the question of what someone inside it could do was never put. This is
commitment 6 unmet on the crate's central property: the tests exercised the construction rather
than attacking it.

## 4. The fix

Ristretto (Hamburg; `curve25519-dalek` 4) is a prime-order group built over Curve25519 with no
cofactor and no clamping, so scalar multiplication composes exactly as the Sphinx proof requires.

- Sender: `x` secret, `α_i = x·b_0···b_{i-1}·G`, shared secret `H(x·b_0···b_{i-1}·P_i)`.
- Hop `i`: `s_i = H(y_i·α_i)`, `b_i = H(α_i, s_i)`, forwards `α_{i+1} = b_i·α_i`.

The hop computes `b_i` because it must, to forward. It multiplies a point whose discrete logarithm
it does not know by a scalar it does, and the product's logarithm stays unknown to it. Computing
`s_{i+1} = H(x·b_0···b_i·P_{i+1})` needs either `y_{i+1}` or that logarithm, and the hop has
neither, because it never held `x`.

Wire format is unchanged: a compressed Ristretto point is 32 bytes, as X25519 was.

Two smaller things follow from the group change:

- **Invalid encodings and the identity are refused.** Ristretto rejects non-canonical encodings by
  construction. The identity is rejected explicitly, because an identity key would make every
  sender's secret with that node the same known constant.
- **Scalars are derived by wide reduction.** A 32-byte hash reduced mod the group order is
  biased; 64 bytes reduced is not. The bias was negligible and removing it was free.

## 5. The test that now holds it

`a_hop_cannot_derive_the_next_hops_shared_secret` puts hop 0's exact view — `shared_0`, `α_0`,
and the packet it forwards — against hop 1's public key, and enumerates the derivations available
from that view, starting with the historical break verbatim. For each it asserts both that the
guess is not hop 1's secret and that it does not authenticate hop 1's header.

Mutation-verified: with re-derivation restored, the first candidate hits and the test fails with
the two secrets printed identical.

The construction itself is pinned by `the_element_a_hop_forwards_is_a_blinding_of_the_one_it
_received`, which asserts the forwarded element equals `b_i·α_i` for the blinding factor derived
from the hop's own view.

## 6. References

- Danezis and Goldberg, *Sphinx: A Compact and Provably Secure Mix Format*, IEEE S&P 2009. The
  construction, and the proof whose blinding chain this now follows.
- Bernstein, *Curve25519: new Diffie-Hellman speed records*, PKC 2006. Clamping, in §3, is a
  defence against small-subgroup and invalid-curve attacks in a Montgomery-ladder DH; it is not
  a property a blinding chain can be built through.
- Hamburg, *Decaf: Eliminating cofactors through point compression*, CRYPTO 2015, and the
  Ristretto construction derived from it. Removes the cofactor rather than clamping around it.
- de Valence et al., `curve25519-dalek`. The Ristretto implementation used here.
