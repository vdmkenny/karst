# 11 — Hardware-backed keys: TPM 2.0 considered and rejected

**Decision: KARST does not use TPM 2.0. Not required, not optional, not behind a feature
flag.**

This document records why, because it is a question that will be asked again and the
reasoning is not obvious. The short version is that the benefit is modest and already
largely covered elsewhere, while the costs attack three separate design commitments at
once.

---

## 1. What was on offer

A TPM generates a keypair and never releases the private half. An address is the hash of a
public key, so L2 would not have changed at all. The gain would have been that stealing the
disk, a backup, or process memory does not steal the identity, and malware can sign only while
it is actually resident rather than exfiltrating the key and continuing next month.

That is a real gain. It is not nothing. It is also smaller than it first appears, for the
reasons in §3.

---

## 2. Why not

### 2.1 It requires a second signature suite, and that is the decisive one

`TPM_ECC_CURVE_25519` is registered in the TCG Algorithm Registry but is barely present in
the TPM Library and PC Client specifications, and is rarely implemented. Deployed TPMs do RSA
and NIST-curve ECDSA. KARST signs everything, everywhere, with Ed25519.

So supporting TPMs means shipping a second signature suite and a mechanism for deciding which
one is in use. Algorithm agility is one of the most reliable sources of protocol
vulnerabilities in existence: it adds negotiation, negotiation adds downgrade attacks, and
every verifier now has two code paths where it had one.

Design commitment 3 says **small enough to reimplement is a security property**. Doubling the
signature surface of the entire stack, so that some users on some hardware get better key
storage, is directly contrary to it. One curve, no negotiation, no downgrade path is worth
more than hardware key custody.

> **Scope of this objection, per `12-algorithm-evolution.md`.** It is not an argument against
> ever changing algorithms, which would forbid migrating off Ed25519 and is untenable, since
> Ed25519 is not the right default forever and is wrong once a cryptographically relevant
> quantum computer exists.
>
> The objection is to a **permanent concurrent** second suite, active for some peers and not
> others, selected by what hardware someone happens to own. That is negotiation, and
> negotiation is where downgrade attacks live. A **versioned** migration, where the
> specification changes the one active suite on a schedule with a hard end date, has no
> downgrade surface and is planned for.

### 2.2 The attestation machinery is a manufacturer singleton, and it will not stay optional

Every TPM ships with an endorsement key burned in by its manufacturer, usually with a
manufacturer-issued certificate. Verifying that a signature came from a genuine TPM means
trusting Infineon, Nuvoton, ST, AMD or Intel. That is a root store with five entries, which
is error 03 with the numbers filed off, and L8 exists to delete exactly that.

Direct Anonymous Attestation (Brickell, Camenisch and Chen, ACM CCS 2004), adopted into TPM
2.0 as ECDAA, is the real mitigation and it is a genuine advance: a TPM can prove it is a
genuine TPM without revealing which one, which removes the per-device correlation the Privacy
CA model creates. It does not remove the issuer, and the issuer is tied to the manufacturer.

The intended posture was "key storage yes, attestation never". The problem with that posture
is the same argument this project already makes about protocol capabilities generally: **a
protocol that can require attestation will eventually be made to require it.** Once TPM
plumbing exists in the client, the distance to a relay or index that prefers attesting peers
is one patch and a plausible anti-abuse rationale. Remote attestation used as gatekeeping
excludes old hardware, free operating systems, and anyone compiling their own client, which
contradicts L16's no-privileged-client rule outright.

Not building the plumbing is a stronger guarantee than building it and promising not to
misuse it.

### 2.3 It risks a second partition of the anonymity set

The device profile is already exempt from constant-rate cover and is therefore not anonymous
(WHITEPAPER §6.11). That partition is a known hole. If hardware-backed identities were ever
distinguishable on the wire, whether through a different signature suite, a different key
format, or an attestation blob, that would be a second partition for a much weaker reason.

### 2.4 The benefit is already partly bought elsewhere

Issue #30 introduced signed invocations, so a copied capability is useless without the
holder's key. That closes the copied-credential attack without any hardware. What a TPM adds
on top is protection against key *exfiltration* specifically.

That matters, and WHITEPAPER §6.4 already says plainly that the endpoint beats every layer
above it. An adversary with code execution on your machine can sign whatever they like for as
long as they are there, TPM or not. Buying "they cannot also sign next month" at the price of
§2.1 and §2.2 is not a good trade.

---

## 3. What is still allowed

Rejecting TPM 2.0 is not rejecting hardware key custody in general. The objections above are
specific:

- a second signature suite (§2.1),
- attestation machinery and its manufacturer trust root (§2.2).

A secure element that simply **holds an Ed25519 key and signs with it**, with no attestation
surface, no endorsement certificate, and no second algorithm, has none of those problems. It
is invisible to every peer, it changes no wire format, and it is a purely local choice about
where a key lives. Several exist.

So the line is:

> **Acceptable:** hardware that stores an Ed25519 key and signs, and is indistinguishable
> from software to every other participant.
>
> **Rejected:** TPM 2.0, and anything else that brings a second signature suite, a
> manufacturer trust root, or a remote attestation capability.

If a future TPM generation implements Ed25519 widely *and* the attestation surface can be
compiled out entirely, this is worth revisiting. Neither is true today.

---

## 4. Consequence for the design

No change to any layer. This is a decision not to add something, which is the cheapest kind
of decision to implement and the easiest kind to get wrong by drift, so it is written down
here rather than left implicit.

The signing path stays a single Ed25519 implementation with no algorithm negotiation
anywhere in the stack.
