# 17 — Paying a relay you are not supposed to know exists

Two layers of this design pull in opposite directions, and the conflict was created by
adopting membership concealment in `15-fundamental-limits.md`.

- **L14** pays relays for carrying traffic. Payment requires the contribution to be
  established, which requires it to be seen.
- **L5 with membership concealment** hides who is participating at all.

You cannot both conceal that a node is relaying and pay it for relaying. The measurement is
the leak.

---

## 1. The literature confirms the conflict rather than dissolving it

Anonymous incentive schemes for Tor are a well-worked area, and every one of them keeps a
measurement step:

| Scheme | Mechanism | Where it observes |
|---|---|---|
| **BRAIDS** | Tickets from a bank, embedded in cells | Agent nodes **monitor** other nodes and distribute tickets in proportion to observed bandwidth |
| **LIRA** | Lottery; relays get guaranteed winning guesses proportional to contribution | A central entity, for relays only, which is thousands rather than millions |
| **TEARS** | Relays **audited**, rewarded with anonymous coins ("Shallots") redeemable for PriorityPasses | The audit |
| **TorCoin** | Proof-of-bandwidth on a distributed ledger, no central authority | The proof, which is public |

The payment side is anonymous in all of them. **The earning side is observed in all of them.**
That is not an oversight repeated four times; it is the structure of the problem.

### One genuinely useful borrowing

TEARS' PriorityPass construction lets **relays prevent double spending locally without leaking
information**. That is exactly the problem left open in issue #44, where a credential is worth
one unit per verifier because disconnected verifiers cannot see each other's ledgers. Worth
reading properly before choosing an option there.

---

## 2. What KARST already does, stated precisely

`karst-value::EarnedWarrant` is signed by **the party that was served**, not produced by an
external auditor. That is a meaningfully different shape from BRAIDS' monitoring agents or
TEARS' audit.

What it buys: no third party watches the wire to measure a relay. The evidence comes from
inside the transaction.

What it does not buy: the warrant is presented to the issuer quorum to mint credentials, so
**that quorum learns the relay carried traffic.** With `t`-of-`n` threshold issuance this is
`t` parties rather than one, and it is not zero.

So the accurate position is:

> Relay participation is revealed to the issuer quorum, not to a network observer.

That is better than public measurement and worse than concealment, and neither the whitepaper
nor `14-value-and-anonymity.md` said so before.

---

## 3. The options, none free

**Relays public, clients concealed.** Accept the asymmetry: relaying is a declared role,
using the network is not. This is Tor's position, it makes payment straightforward, and it
makes relays blockable, which is precisely the enumeration problem L5 exists to avoid. It
trades censorship resistance for economics.

**Relays concealed, no payment.** Volunteer relaying. Tor's actual deployed model, which does
work, and which produces the relay scarcity every incentive paper in §1 was written to fix.

**Relays concealed, paid by served-party attestation.** What KARST does now. Leaks
participation to the issuer quorum only. Improvable by shrinking what the quorum learns:
attesting to *an amount* without naming the relay, so the quorum verifies work occurred and
mints against a blinded identity. This is the same blind-signature gap already open as #43,
applied to the earning side rather than the spending side.

**Proof of work as the payment.** Decouple earning from measurement entirely: a relay mints by
burning computation rather than by proving service. Nobody observes anything. It also rewards
whoever has the most silicon rather than whoever carries the most traffic, which is error 04
with extra steps, and it pays no attention to whether the relay actually relayed.

---

## 4. Position

The design keeps the third option and states its leak rather than claiming concealment it does
not have. Closing the gap means extending #43's blind signature work to cover issuance against
a blinded relay identity, so the quorum can verify that service occurred without learning who
performed it.

Whether that is achievable with threshold issuance is unresolved. It is the same shape as
anonymous credentials generally, and the fact that four published Tor incentive schemes all
declined to attempt it is evidence about difficulty rather than about oversight.

---

## References

- Jansen, Miller, Syverson, Ford. *From Onions to Shallots: Rewarding Tor Relays with TEARS.*
  HotPETs 2014. <https://www.robgjansen.com/publications/tears-hotpets2014.pdf>
- Jansen, Hopper, Kim. **BRAIDS**: Tor incentives via tickets and monitoring agents.
- Jansen, Johnson, Syverson. **LIRA**: Lightweight Incentivized Routing for Anonymity. NDSS
  2013.
- Ghosh, Ford et al. *A TorPath to TorCoin: Proof-of-Bandwidth Altcoins for Compensating
  Relays.* HotPETs 2014. <https://dedis.cs.yale.edu/dissent/papers/hotpets14-torpath.pdf>
- Tor Project. *Tor incentives research roundup.*
  <https://blog.torproject.org/tor-incentives-research-roundup-goldstar-par-braids-lira-tears-and-torcoin/>
