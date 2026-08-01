# 20 — Three decisions, taken

`19-where-the-design-is-wrong.md` identified three questions blocked on somebody choosing
rather than on research, and noted they were being decided by omission, which is the worst
option. Researching them found that **all three of my option lists were incomplete**, and in
two cases the missing option is better than everything I had listed.

---

## 1. Double spending across disconnected verifiers (#44)

### The options I had

A shared ledger with consensus cost, short epochs bounding damage, or accepting per-verifier
semantics. All three treat the problem as **prevention**, and prevention is what requires an
authority or a consensus.

### The option I missed

Chaum, Fiat and Naor, *Untraceable Electronic Cash* (CRYPTO 1988): **do not prevent double
spending, make it reveal the spender.**

A credential carries the holder's identity split into pairs of shares. Each spend opens one
half of each pair, chosen by the verifier's challenge, which discloses nothing. Two spends
against different challenges open both halves of some pair, and the identity reconstructs.

This needs **no online authority and no consensus**, which is exactly the constraint that made
the other three expensive.

### Why the punishment is proportionate rather than a privacy failure

Revealing the acquirer looks like it contradicts §14's separation of acquisition from spending.
It does not. **Acquisition is deliberately linkable already.** An honest spender reveals
nothing; a double spender is linked back to a transaction that was never private. The anonymity
property holds precisely where it was claimed.

Combined with L16, where standing is earned per relationship and does not transfer, a burned
identity cannot be replaced by buying a fresh one.

### Decision

> **Accept per-verifier acceptance, and make double spending self-incriminating.** A credential
> may be spent at two verifiers; doing so reveals who did it.

Implemented in `karst-value::doublespend`. The mechanism fails only when two verifiers issue
identical challenges, which is `2^-64` or a verifier deriving its challenge deterministically.
`recover_holder` returns `None` in that case rather than a wrong answer.

**Not implemented:** Compact E-Cash (Camenisch, Hohenberger, Lysyanskaya, EUROCRYPT 2005) is
the modern construction and additionally gives **exculpability**, meaning a verifier can *prove*
a double spend to a third party rather than merely assert it. That matters more here than in a
banked setting, because there is no authority whose word anyone takes.

### The same answer applies to L9

`Caveat::MaxUses` has the identical shape, and the stocktake asked for one answer rather than
two. Invocations are already signed by the holder (#30), so two signed invocations against a
one-use capability are already evidence anyone can check. The verifier cannot prevent the
second offline; it can prove it happened.

---

## 2. Relay visibility (#54)

### The options

Relays public and clients concealed (Tor's position, trades censorship resistance for
economics), relays concealed and unpaid (Tor's deployed reality, which produces the relay
scarcity every incentive paper was written to fix), or the current position where participation
leaks to the issuer quorum only.

### What the research adds

TorCoin/TorPath states the goal explicitly: verification of bandwidth **without identifying its
provider**. So the problem is recognised and has been attempted. Biryukov and Pustogarov's
proof-of-work micropayment scheme uses blind signatures, but in the other direction: it conceals
the *client* from the relay, not the relay from an observer.

Nothing deployed achieves what #54 wants.

### Decision

> **Keep the current position, and state its leak precisely rather than claiming concealment.**
> Warrants are signed by the party served rather than produced by an auditor, so no third party
> watches the wire. The warrant reaches the issuer quorum, so **relay participation is revealed
> to `t` issuers and not to a network observer.**

That is better than public measurement and it is not concealment. The improvement path is
named: extend #43's blind signature work to the earning side, so a quorum can verify service
occurred without learning who performed it.

Whether that composes with threshold issuance is unresolved, and four published schemes
declining to attempt it is evidence about difficulty rather than about oversight.

---

## 3. Update mechanism (#57)

### The options I had

Version attestation in the protocol (effective, and a privileged-client mechanism wearing a
safety hat, which L16 forbids), signed advisories subscribed like label sets (consistent with
the design and entirely voluntary, which is the failure mode), or expiring builds (blunt and
hostile to archival use).

The first two looked like a genuine dilemma between effectiveness and L16.

### The option I missed

Samuel, Mathewson, Cappos and Dingledine, *Survivable Key Compromise in Software Update
Systems*, CCS 2010, which is TUF. Two of the four authors are Tor, and it is designed for
adversarial update distribution specifically.

The piece that matters is the **timestamp role and its defence against freeze attacks**. An
adversary who simply withholds updates leaves a client believing it is current, forever, with
no error to notice. That is exactly the Ricochet failure: a defence existed and the endpoint
did not have it, and nothing told the user.

TUF's answer is short-expiry signed metadata. A client knows what fresh metadata looks like and
how often to expect it, so **silence is distinguishable from "nothing new"**.

### Why this dissolves the L16 tension

It is not a privileged-client mechanism and nobody pushes anything. **The client pulls, and
detects its own staleness locally.** No authority is required for a client to notice it has
stopped hearing, so there is nothing here for anyone to be privileged about.

That is why the dilemma was false: I had been choosing between mechanisms that act *on* the
client, when the answer acts *in* it.

### Decision

> **Adopt TUF's structure.** Freeze detection now, the rest mapped onto existing primitives.

Implemented in `karst-object::freshness`: expiring signed statements, monotonic sequence so an
old statement cannot be replayed, and a client-side monitor distinguishing fresh, expired,
rolled back, never-heard, and content-withheld. A publisher with nothing to say still says so.

**Expiry alone is not enough**, which adversarial testing showed. An adversary who forwards
genuine, fresh, correctly-sequenced statements while withholding the advisories they refer to
leaves a client reporting current and missing exactly the update it needs: the freeze attack
wearing a disguise. Each statement therefore commits to a digest of the advisory set it vouches
for, which is TUF's snapshot role, and a client comparing that against what it holds detects
the withholding.

Two limits stated rather than papered over. Expiry checks are only as good as the client's
clock, so an adversary with local access who sets it back defeats them. And a publisher issuing
very long validity windows disables the detector without ever lying, so validity is a security
parameter rather than a convenience.

TUF's other mechanisms map onto primitives that already exist and are not yet wired up:
threshold signing (`karst-value::shamir`), role separation, and key rotation
(`karst-object::Rotation`, implemented for #41). Advisories themselves are ordinary objects
distributed as label sets at L15.

---

## What this exercise showed

Three option lists, three missing options, two of them better than anything listed. The common
shape: **each list was framed around preventing something, and the better answer was to make it
visible or costly instead.**

- Do not prevent double spending; make it identify you.
- Do not conceal the relay from the quorum; state precisely who learns what.
- Do not push updates at clients; let clients notice they have stopped hearing.

That is worth remembering the next time a decision looks like a choice between bad options. It
is often a sign the frame is wrong rather than the options.

---

## References

- Chaum, Fiat, Naor. *Untraceable Electronic Cash.* CRYPTO 1988.
- Camenisch, Hohenberger, Lysyanskaya. *Compact E-Cash.* EUROCRYPT 2005.
  <https://eprint.iacr.org/2005/060>
- Samuel, Mathewson, Cappos, Dingledine. *Survivable Key Compromise in Software Update
  Systems.* CCS 2010. <https://www.freehaven.net/~arma/tuf-ccs2010.pdf>
- Biryukov, Pustogarov. *Proof-of-Work as Anonymous Micropayment: Rewarding a Tor Relay.*
  FC 2015. <https://eprint.iacr.org/2014/1011.pdf>
- Ghosh, Ford et al. *A TorPath to TorCoin.* HotPETs 2014.
