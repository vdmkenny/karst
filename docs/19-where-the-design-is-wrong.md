# 19 — Where the design is wrong, and what is buildable

A stocktake. Seventeen layers, eleven crates, 167 tests, twenty-eight open issues.

The useful split is not by layer. It is between **things that need a decision**, **things that
need research nobody has done**, and **things that are settled and merely unbuilt**. Those need
different work and get confused constantly.

---

## 1. The meta-observation

Every conflict found in the last stretch of work is **between layers**, not inside one:

| Conflict | Layers |
|---|---|
| Constant-rate emission is an ISP signature | L4 needs it, L3 promises the opposite |
| Paying a relay reveals it is a relay | L14 needs measurement, L5 needs concealment |
| A fetch names what you wanted | L6 addresses by hash, L4 hides only the sender |
| Announcement leaks authorship | L15 needs it, L4 wants nothing observable |

That pattern is diagnostic. **Anonymity is not a layer, and neither is economics.** Both are
whole-stack properties that were factored into L4 and L14 respectively, and the factoring keeps
leaking. A layer diagram is the wrong tool for a property that every layer can violate.

This does not mean rewriting the stack. It means the whitepaper should stop presenting anonymity
as something L4 provides and start presenting it as an invariant every layer must preserve, with
L4 as the main contributor rather than the owner. The four conflicts above are then predictable
rather than surprising, and the next one gets caught in review instead of in an audit.

**Amendment 1: restate anonymity and economics as cross-cutting invariants, not layers.**

---

## 2. Needs a decision, not research

These are blocked on somebody choosing. The options are known and each has been costed.

### 2.1 Double-spend scope (#44)

A credential is worth one unit per verifier. Options: shared ledger with consensus cost, short
epochs bounding the damage, or accept per-verifier semantics. The same question applies to L9
use counts, and **the stack should give one answer for both** rather than two.

TEARS' PriorityPass construction is directly relevant and unread: it lets relays prevent double
spending locally without leaking information.

### 2.2 Strike the standing-disjoint path rule (#39)

`docs/` already says path selection is uniform over admitted relays. The whitepaper L1 and L4
text should be checked line by line for surviving references, because a rule that guard
placement attacks defeat should not be recoverable from a stale sentence.

### 2.3 Relay visibility (#54)

Three options, all costed in `17-paying-concealed-relays.md`: relays public and clients
concealed (Tor's position, trades censorship resistance for economics), concealed and unpaid
(Tor's deployed reality, produces relay scarcity), or the current position where participation
leaks to the issuer quorum only. **Pick one and say so.**

### 2.4 Update mechanism (#57)

Version attestation, subscribed advisories, or expiring builds. Each trades against L16
differently. Currently decided by omission, which is the worst option.

---

## 3. Needs research nobody has done

In dependency order.

1. **#47 measure the introduction graph's mixing time.** Blocks #40. SybilLimit's bound is
   contingent on fast mixing and Mohaisen et al. measured real graphs as much slower than the
   literature assumes. KARST's graph is not a friendship graph and has never existed.
2. **#40 SybilLimit admission.** The actual defence against an observer. Blocked on the above.
3. **#56 ISP exposure.** The most serious open problem and the one with the least clear path.
   Constant-rate emission separates KARST users from everyone else with a byte counter. The only
   defence is adoption, which is circular.
4. **#53 fetch privacy.** PIR is nearly affordable and collides with the no-relationship and
   no-non-collusion commitments.
5. **#50 membership concealment.** 2009 proof-of-concept work, none deployed.
6. **#13 petname layer.** Predicted to become singleton number seven.

Note that #56 and #50 pull in opposite directions: concealment wants you invisible, and constant
rate makes you conspicuous to the one observer who knows your name.

---

## 4. Settled and buildable now

Ordered by value. All of these have a settled design and need only code.

### 4.1 Real Sphinx (#1) — done

Implemented. Per-hop header MAC verified before processing, wide-block payload cipher, constant
length headers with proper filler, replay tags. The tagging attack class the 2014 CMU/CERT
campaign exploited is closed.

The group element is blinded per the paper, `α_{i+1} = b_i·α_i` over Ristretto. It was
re-derived from the shared secret until #101, on the reasoning that X25519 clamping does not
compose as the proof assumes. That reasoning was sound and the conclusion drawn from it was not:
re-derivation hands each hop the private scalar behind the next element, so one relay unrolls the
entire route and reads the payload. The right response to a group that does not compose is a group
that does. See docs/28-blinding.md.

The wide-block payload cipher went the same way. It was a four-round unbalanced Feistel written
in the repository, in the LIONESS shape, keying the stream cipher by hashing the round key with
the left half rather than by the paper's `S(L xor K)`. It is `lioness-rs` now. Neither Rust
LIONESS crate ships known-answer vectors, so the test is a second implementation: Burdges'
`lioness` and Nym's `lioness-rs` agree byte for byte, which is the evidence a KAT would have
provided.

One deviation remains documented rather than hidden: LIONESS's four round keys are
information-theoretically independent in the paper and are subkeys of one per-hop secret here.
It is not a reviewed implementation.

### 4.2 Migration groundwork (#41)

Two small pieces that must exist **before there is data to migrate**:

- **Cross-key rotation exception** to the same-author rule on lineage edges. A key rotation is
  the one legitimate cross-key edge, with bidirectional signing so nobody can claim to be
  someone's successor from their public key alone. **It does not survive compromise of the old
  key**, which signs the forward half while the attacker's own key signs the backward half. Two
  successions from one address fork the identity and neither certifies an edge, so a holder who
  still has their key can make the theft visible; a holder who does not cannot. Prevention needs
  a third party to countersign, which `karst-witness` could do and does not.
- **Self-describing digests**, so a future hash is distinguishable rather than ambiguous.

Cheap now, impossible later. Content addresses are permanent names.

### 4.3 Loop cover traffic (#4)

`karst-mix::active` already models loop traffic as the detection mechanism and reports 100%
detection against an n-1 attack. The mechanism itself is unimplemented, so the number describes
a design rather than a thing.

### 4.4 Blind signature (#43)

Coconut or RFC 9474. The choice is costed: Coconut brings threshold issuance and a pairing
dependency, RFC 9474 is simpler and reintroduces the single issuer. Threshold is worth the
dependency.

### 4.5 Live append to stream manifests (#24)

Self-contained. `karst-blob` has the merkle structure; live and archived should be one object
that stops appending.

### 4.6 Publish-equals-index (#12) and transparency logs (#11)

Both fully specified, neither started. #14 timestamp attestation depends on #11.

---

## 5. Recommendation

**Build:** #1, then #41's two pieces, then #4. Those three are settled, and the first is a live
attack class.

**Decide:** #44 and #54, because they are choices being made by default.

**Research:** #47, since it unblocks the only real defence against an observer.

**Accept for now:** #56. It has no clear path, it is honestly recorded, and pretending otherwise
would be worse than the gap.

---

## 6. What this stocktake did not do

It did not re-examine the four errors in WHITEPAPER §1, which have not been tested against
anything since they were written. They organise the document well, and "useful framing" and
"correct" are different claims. That is worth a separate pass.
