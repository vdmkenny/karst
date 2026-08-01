# 14 — Value without deanonymisation

The whitepaper names this the most serious unresolved technical problem in the stack. L14
needs settlement trustworthy enough to be relied on; L4 needs it unlinkable; and a payment
system inside an anonymity network is a notorious correlation surface. If who paid whom is
observable, the anonymity above it is decorative.

The conflict is resolvable, and the resolution is to stop building money.

---

## 1. Separate acquisition from spending

The mistake is treating a payment as one act. It is two, with opposite requirements, joined
only by habit:

| | Acquisition | Spending |
|---|---|---|
| Frequency | rare | constant |
| Must be unlinkable | **no** | **yes** |
| Reveals | that you obtained *n* units | that *someone* holds a valid unit |
| Anonymity set | not applicable | everyone who ever acquired |

Credentials are acquired in the open and spent unlinkably. The spender's anonymity set is not
"everyone spending right now", which would be small and time-correlated. It is **everyone who
ever acquired a credential**, which is large and grows monotonically.

This is *Coconut* (Sonnino, Al-Bassam, Bano, Meiklejohn, Danezis, NDSS 2019): threshold
issuance, selective disclosure, re-randomisation, and multiple unlinkable showings. Its listed
applications include anonymous payments and **distributing proxies for censorship
resistance**, which is this problem exactly. The single-issuer ancestor is Chaum's blind
signature, standardised as RFC 9474.

---

## 2. Threshold issuance, because one issuer is error 03

A single issuer sees every request and can link every one to the party that made it. It is
also one subpoena, one compromise, one outage.

Issuance is therefore `t`-of-`n`. Fewer than `t` colluding issuers learn nothing about the
issuing key, and no single party is worth compelling. `karst-value::shamir` implements this
over a prime field and tests that any threshold subset reconstructs while any smaller subset
does not.

---

## 3. Do not touch money at all

The move that matters most for KARST is smaller than Coconut and does more work.

**Capacity is earned by providing capacity.** A relay that carries traffic earns credentials.
A client that consumes capacity spends them. The loop closes with no bank, no card network,
and nothing to de-bank, which is what L14 required in the first place: a payment rail is a
chokepoint and reintroduces everything the stack removes.

A financial on-ramp can exist for people who want capacity without running a relay. It is
optional rather than structural, and its absence breaks nothing. That is the difference
between a network with an economy and a network that depends on the banking system.

`karst-value::EarnLedger` enforces conservation: credentials cannot be drawn against service
that was not performed.

---

## 4. Fixed denominations

Variable amounts are a fingerprint. An observer who sees a 4,096-unit credential spent has
narrowed the spender to whoever acquired one of those.

Every credential is worth exactly one unit and is the same size on the wire. Larger amounts
are several credentials. This costs bandwidth and is not negotiable.

---

## 5. What is not solved

### Double spending: not prevented, made self-incriminating

Decided in `20-three-decisions.md` §1 and implemented in `karst-value::doublespend`. A
credential carries the holder's identity split into share pairs; one spend opens one half of
each and discloses nothing; two spends against different verifier challenges reconstruct the
holder. No online authority, no consensus.

**One hole is open and demonstrated by a passing test.** A holder who double spends and simply
*lies* in the second opening, sending fabricated halves, produces two openings that agree on no
address, so `recover_holder` returns `None` and the liar escapes identification.

Chaum, Fiat and Naor prevent this with cut-and-choose **at issuance**: the issuer makes the
holder open many candidate credentials, checks they are well formed, and signs only an unopened
one, so embedding garbage is caught before the credential exists. That step is not implemented.

Partial mitigation is in place: `consistency` lets a verifier distinguish a real double spend
from a fabricated credential, so a bad credential can be refused even when nobody can be named.
That is the difference between an unattributable double spend and an undetectable one.

### Acquisition timing is still an intersection surface

Acquisition is linkable by design, which is fine on its own and not fine in combination with
timing. Acquiring credentials immediately before a burst of activity narrows the field.

Mitigations, none complete: acquire well in advance of use, acquire on a schedule rather than
on demand, and prefer earning by relaying over buying, since a relay's earning pattern is
driven by other people's traffic rather than its own intentions.

### The blind signature is implemented; threshold and blindness are not yet composed

`karst-value::blind` implements Chaum's construction, standardised as RFC 9474: the issuer
signs a value it cannot read, and the unblinded signature verifies against the issuer's
**public key alone**, so a verifier can check a credential it could not itself have issued.

Perfect blinding is demonstrated constructively rather than asserted: because `r ↦ r^e` is a
bijection modulo `n`, a test reconstructs the same blinded value from an entirely unrelated
message, showing the issuer's view is consistent with every possible message.

Two defects were found by writing attacks rather than exercises, and both are fixed:

- **A blinding factor of one is no blinding at all**, handing the message straight to the
  issuer while every later step still works perfectly. Values of 0 and 1 are now rejected,
  because a weak or failing RNG is exactly how this occurs.
- **Unblinding returned a malicious issuer's garbage without checking it**, so the holder would
  discover the problem later, at a verifier, where the failure is unattributable and possibly
  incriminating. It now verifies before returning.

**What is not composed:** RSA blind signatures give plurality of issuers and public
verifiability, and lose threshold-within-a-set. That is a smaller loss than it first appeared,
because the two properties were being conflated: plurality of issuer *sets* is what error 03
demands, and threshold *within* a set protects one set against a compromised member. Recovering
both needs Coconut over a pairing curve, or threshold RSA. `shamir` still carries the threshold
structure separately.

---

## 6. Where this leaves L14

The layer stands, with its claim narrowed and its dependency removed:

1. **Settlement is credentials, not money.** Earned by service, spent for service, no rail.
2. **Issuance is threshold**, so no issuer is a chokepoint or a correlation point.
3. **Spending is unlinkable to acquisition**, which is what L4 required.
4. **Double spending is bounded per verifier**, not globally, and that is a stated cost rather
   than a solved problem.

WHITEPAPER §6.10 previously said no design satisfies both L14 and L4. That is too strong: the
design exists and is published. What remains open is the double-spend scope and the
implementation of the blind signature.

---

## References

- Sonnino, Al-Bassam, Bano, Meiklejohn, Danezis. *Coconut: Threshold Issuance Selective
  Disclosure Credentials with Applications to Distributed Ledgers.* NDSS 2019.
  <https://arxiv.org/pdf/1802.07344>
- Denis, Jacobs, Wood. *RSA Blind Signatures.* RFC 9474, IRTF CFRG.
  <https://www.rfc-editor.org/rfc/rfc9474>
- Chaum. *Blind Signatures for Untraceable Payments.* CRYPTO 1982.
