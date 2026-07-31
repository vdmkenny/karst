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

### Double spending across disconnected verifiers

A serial can be caught when spent twice **at one verifier**. Two verifiers that cannot see
each other will both accept the same credential, and making that impossible requires either a
shared ledger with its consensus cost or an always-online authority, which is the thing this
stack exists to remove.

So a credential is worth one unit *per verifier*, not one unit in the universe. The options
are a shared ledger and its cost, short epochs that bound the damage, or accepting that each
relay honours a credential once. `karst-value` tests this limit explicitly so it cannot be
quietly forgotten. It is the same limit `karst-cap::UseLedger` has, for the same reason, and
in both places the honest move is to state which option was picked.

### Acquisition timing is still an intersection surface

Acquisition is linkable by design, which is fine on its own and not fine in combination with
timing. Acquiring credentials immediately before a burst of activity narrows the field.

Mitigations, none complete: acquire well in advance of use, acquire on a schedule rather than
on demand, and prefer earning by relaying over buying, since a relay's earning pattern is
driven by other people's traffic rather than its own intentions.

### The proof of concept is not the cryptography

`karst-value` implements the protocol shape and real threshold sharing. It does **not**
implement the blind signature: issuers receive a commitment rather than a serial, and the
tests verify that the issuance transcript and the spend transcript share no field, but the
cryptographic binding needs Coconut or RFC 9474.

Verification currently uses the threshold-issued secret, so a verifier could forge a
credential it never issued. Coconut removes this with public verifiability against an issuer
verification key. This is a gap in the implementation, not in the design.

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
