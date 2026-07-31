# 11 — Hardware-backed keys, and TPM 2.0

**Short answer: yes, optionally, for storing keys. Never as a condition of being talked to.**

That distinction is the whole design, and it is not a detail. A TPM used one way
strengthens L2 and L9 at essentially no architectural cost. The same chip used the other
way reintroduces error 03 in its most concentrated form and would undo L16.

---

## 1. What it genuinely buys

### Keys that cannot be copied (L2)

A TPM generates a keypair and never releases the private half. It signs on request. Under
KARST an address is the hash of a public key, so nothing about L2 changes: the address is
derived the same way, there is still no registrar, and the object format is untouched. What
changes is that stealing the disk, the backup, or the process memory no longer steals the
identity.

### Proof of possession that survives compromise (L9)

Issue #30 introduced signed invocations: the holder must sign a canonical request, so a
copied capability is useless without the key. A TPM sharpens that considerably. Malware on
the machine can ask the TPM to sign *while it is resident*, but it cannot exfiltrate the key
and keep signing next month from somewhere else.

That is a downgrade from permanent compromise to transient compromise, which is a real and
underrated improvement. It does not make the endpoint trustworthy, and WHITEPAPER §6.4
still stands.

### Devices that outlive their vendor (device profile)

The device profile already says identity is generated at manufacture or first boot, from
nobody. A TPM or a cheap secure element is the natural way to do that: a per-device key that
was never in a vendor database and cannot be read out. Measured boot over PCRs additionally
gives firmware integrity that composes with L6's signed firmware lineage.

---

## 2. Why attestation is the dangerous part

A TPM can prove things about itself remotely. That capability, not the key storage, is where
this stops being free.

### The manufacturer is a singleton

Every TPM ships with an Endorsement Key burned in by the manufacturer, usually with an EK
certificate issued by that manufacturer. Verifying that a signature came from "a genuine
TPM" means trusting Infineon, Nuvoton, ST, AMD, or Intel. That is a root store with five
entries, which is error 03 with the numbers filed off, and it is precisely what L8 exists to
delete.

The classic Privacy CA arrangement is worse still: the CA is assumed to know the Endorsement
Keys of all valid TPMs, so it is simultaneously a global registry of devices and a
correlation point.

### DAA is the real mitigation, and it does not remove the issuer

Direct Anonymous Attestation (Brickell, Camenisch and Chen, ACM CCS 2004) exists exactly for
this, and the TCG adopted it into TPM 2.0 as ECDAA. It lets a TPM prove it is a genuine TPM
**without revealing which one**, removing the per-device correlation the Privacy CA model
creates.

That is a genuine advance and it is not sufficient here. DAA still requires a DAA issuer
whose signature says "this is a real TPM", and that issuer is tied to the manufacturer. The
correlation goes away; the singleton does not.

### Ed25519 is largely unavailable

`TPM_ECC_CURVE_25519` is registered in the TCG Algorithm Registry, but it is barely present
in the TPM Library and PC Client specifications and rarely implemented. Deployed TPMs do RSA
and NIST-curve ECDSA. KARST signs everything with Ed25519.

So a TPM-backed identity today means either a per-device signature suite (an ECDSA variant
alongside Ed25519, with all the negotiation surface that implies) or waiting for hardware
that does not exist in volume. This is a concrete blocker, not a detail to sort out later.

---

## 3. The rule

> **Hardware backing is a local choice about where your key lives. It is never an admission
> criterion, and attestation never appears on the wire in normal operation.**

Allowed:

- I choose to keep my key in a TPM, secure element, or Secure Enclave.
- My client tells *me* that my key is hardware-backed.
- A device ships with a hardware identity because that is how its manufacturer built it.

Forbidden by design:

- A relay, board, index, or resource requiring proof that your key is in hardware before it
  will talk to you.
- Any capability, rate limit, or standing that is available only to attesting clients.

The second list is remote attestation used as gatekeeping, which is the substance of the
objection to Web Environment Integrity style proposals. It would exclude old hardware, free
operating systems, anyone compiling their own client, and anyone whose vendor did not sign
their bootloader. It directly contradicts L16's "no privileged client", and it converts
"small enough to reimplement" from a security property into a fiction, because a
reimplementation that cannot attest is a reimplementation nobody will accept.

**A protocol that can require attestation will eventually be made to require it.** So the
capability should not exist at the protocol level at all, rather than existing with a
convention against using it.

---

## 4. Costs, if this is adopted

1. **Signature suite fragmentation.** Ed25519 everywhere is a simplification worth
   protecting. Adding an ECDSA path for hardware-backed keys doubles the verification
   surface and adds algorithm negotiation, which is a classic source of downgrade attacks.
2. **A second anonymity-set split.** The device profile is already exempt from cover traffic
   and therefore not anonymous (WHITEPAPER §6.11). If hardware-backed identities were ever
   distinguishable on the wire, that would be a second partition of the set, for the same
   bad reason.
3. **False confidence.** A TPM protects the key, not the machine. A user told their identity
   is hardware-backed may reasonably conclude they are safe from an adversary who has root,
   and they are not: that adversary can sign anything they like for as long as they are
   present.
4. **It does not fix the `Autonomous` problem.** Attestation could in principle substantiate
   "this agent runs this software under this operator", which is exactly the claim
   `Agency::Autonomous` currently cannot make (issue #28). Making that verifiable would
   require the manufacturer trust root, so we are choosing to leave the claim unverifiable
   rather than buy verifiability at that price. That is a deliberate trade and it is worth
   revisiting only if a manufacturer-independent attestation scheme appears.

---

## 5. Status

Nothing implemented. The clean shape is a signing trait behind which a software key, a TPM,
a Secure Enclave, or a smartcard can sit, chosen locally and invisible to every peer.

Tracked as an issue. See also `docs/09-references.md`.
