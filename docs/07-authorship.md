# 07 — Human and machine authorship

The requirement: be able to separate human-created content from bot-created content.

The honest answer: **you cannot verify what produced a piece of content, and you should
stop trying.** What you can verify is who takes responsibility for it. That is a weaker
claim, it is achievable, and it turns out to be the more useful one.

This document works through why the obvious approaches fail, what the stack can actually
do, and what remains impossible.

---

## 1. What does not work

### Detection

Statistical classification of text. This fails permanently and in every direction:

- It is an arms race the detector loses by construction, since any reliable detector is
  a training signal for evading it.
- False positives fall hardest on non-native speakers and on anyone whose writing is
  unusual, and the cost of a false accusation is borne by the accused.
- Accuracy against current models is already close to useless, and paraphrase defeats
  what remains.

Detection is also the wrong shape for this stack. It is a judgement applied after the
fact by whoever is doing the judging, which makes it a centralised opinion wearing the
costume of a fact.

### Watermarking

Requires every model provider to cooperate, is removed by paraphrase, and gives nothing
at all for open weight models running on someone's own hardware. Dead on arrival in an
adversarial setting, which this is.

### Proof of personhood registries

Biometric or document-backed registries of real humans. This is error 03 in its purest
form: a global singleton, holding the most sensitive database anyone has ever proposed,
that becomes the gate for speech. It is flatly incompatible with every other decision in
this stack, and building it would undo the rest.

### Interactive challenges

A puzzle at posting time proves a human was present for *that action*. It does not prove
a human wrote the content, machines beat the puzzles, and the puzzles are an accessibility
tax.

---

## 2. The reframe

Stop asking "was this written by a human." Ask "**who is accountable for this, and what
was their relationship to producing it.**"

The second question has a verifiable answer, because the stack already has every piece:

- **L2**: every actor is a key, including every agent.
- **L9**: capabilities carry a delegation chain that verifies offline.
- **L13**: every object already carries a signed authorship chain.

An agent has its own identity, distinct from the person it works for, and it already acts
on capabilities attenuated from that person. So an object can declare its **agency class**
and, where the class involves a machine acting for someone, carry the delegation chain
proving whose authority it acted under.

---

## 3. The mechanism

Four classes, declared in the signed object:

| Class | Meaning | Verifiable? |
|---|---|---|
| `Direct` | The signing key composed this itself. | **No.** Unfalsifiable claim. See §4. |
| `Assisted` | A person composed it with a named tool and signs it personally. | No, but the person's key is on it. |
| `Delegated` | An agent acted under a specific principal's authority. | **Yes.** Carries the signed capability, verified in full. |
| `Autonomous` | An agent acting on its own standing, no principal for this act. | **No.** Nothing proves the named operator runs it. |

`Delegated` is cryptographically checkable, because the claim **carries the actual signed
capability** rather than a summary of it. Verification checks every grant signature, chain
continuity, that authority only ever narrowed, that the root grant came from the declared
resource owner, and that the final audience is the key that signed the object. A forged
claim fails, so you cannot falsely claim to be *authorised by* someone.

An earlier version of this stored only `(issuer, audience)` address pairs and checked that
they lined up, which meant an attacker could name any victim as their principal and have a
post attributed to them. That was reported as issue #28 and it was a total forgery of the
one property this layer exists to provide. The evidence now travels with the claim.

`Autonomous` is **not** checkable, and no longer says it is. Nothing in it proves the named
operator runs the agent, so it is a bare claim exactly like `Direct`, and responsibility
falls on whoever signed it rather than on the operator they named.

`Direct` is not checkable and never will be. That is the whole difficulty and this document
will not pretend otherwise.

---

## 4. What this actually buys, since it is not detection

**A false claim of humanity becomes a signed, permanent, attributable act.**

A bot can always publish under a fresh key and declare `Direct`. Nothing stops it. But:

1. The claim is signed by a key, and that key's claims are permanent and append only under
   L13. There is no editing it later.
2. When a key is later shown to be automated, every object it ever signed carries the false
   claim, and every index that referenced it can label the lot in one operation (L15).
3. Reputation at L16 is earned per relationship and decays, so a key that burns its
   credibility cannot buy a new one and cannot transfer standing to a fresh key.

This does not make lying impossible. It makes lying **costly, permanent, and retroactively
attributable to everything else that key ever said**, which is a different problem to have
than the one we have now, where the cost of a false claim is zero and the evidence
evaporates.

**Second, and more interesting: the incentives point the right way.**

An agent that honestly declares itself gets to hold attenuated capabilities, invoke L11
affordances, and be paid at L14. An agent pretending to be a person cannot present a
delegation chain, therefore cannot hold delegated authority, therefore **cannot do anything
except emit text**. Declaring yourself a machine buys you the ability to act; hiding it
confines you to speech.

That property falls straight out of L9 and was not designed for this. It is the strongest
part of the answer.

---

## 5. Personhood signals that do not require a registry

Where a community genuinely needs confidence about people rather than accountability, the
stack has an answer that is not a global database: **L5's social graph, used as attestation.**

Peers vouch, using their own keys, that they know a key as a person. That produces:

- No global authority, so no error 03.
- **Plural and local confidence.** A key well attested in one community may be unknown in
  another, and both are correct. There is no single number and no appeal to a central
  arbiter.
- **Graceful degradation.** An unattested key is unattested, not banned. Boards choose
  whether they care.

This is a web of trust for personhood rather than a registry of humans. It is old, it is
unfashionable, and it is the only shape compatible with the rest of this design.

Its weaknesses are the classic ones and are real: attestation networks reflect existing
social access, they are vulnerable to a well-connected liar, and they exclude anyone who
knows nobody. See §7.

---

## 6. Policy belongs at L15, not in the protocol

The protocol provides the field and the verifiable chain. It takes no position on what
anyone should do with them. Boards and indexes choose:

- index only `Direct` from keys with *n* independent attestations,
- index everything and label the machine-authored,
- index only `Delegated`, for an agent-to-agent marketplace,
- ignore the field entirely.

Three people reading the same posts through different policies see different boards, and all
three are correct. That is the same mechanism as moderation and it is deliberate: **a rule
about who may speak is an opinion, and opinions belong in subscribable views rather than in
the protocol.**

---

## 7. What this costs, and what it does not solve

1. **`Direct` remains unfalsifiable.** A determined bot with a fresh key claims humanity and
   nothing catches it at the protocol layer. Everything in §4 is about consequences after
   exposure, not prevention. If your threat model is "a well-resourced actor floods a board
   with content claiming to be human," this design does not stop them. It makes the cleanup
   one label operation instead of a manual purge, which is worth something and is not what
   was asked for.

2. **Attestation networks inherit social power.** Vouching for personhood reproduces existing
   social access, and a well-connected bad actor can attest to fictions. This is the same cost
   as L5, arriving in a more sensitive place.

3. **The categories are already blurring, permanently.** A person writing with autocomplete, a
   person editing model output, a model drafting and a person signing, an agent operating under
   standing instructions written months ago. `Assisted` is a single word covering an enormous
   and growing range, and the boundary it names is dissolving. Any taxonomy here has a shelf
   life.

4. **It can be used for exclusion.** A verifiable machine-authorship field makes it trivial to
   build boards that exclude assistive tools, which will land on disabled users and non-native
   speakers first. The protocol cannot prevent this and the policy layer is where it will
   happen.

5. **Nothing here helps with content laundering.** A human who signs `Direct` over text a model
   wrote is making a true statement about accountability and a false one about production. Under
   this design that is not a protocol violation, and arguably it is the correct outcome, since
   they *are* accountable. Whether that satisfies the original requirement depends on why you
   wanted the distinction.

---

## 8. Summary

We do not detect bots. We make accountability structural and machine authorship
*declarable and, when it involves delegation, verifiable*. We make lying about it permanent
and attributable rather than free and ephemeral. We make honest declaration more useful than
dishonest silence, because only declared agents can hold authority. And we leave every actual
policy decision to subscribable views.

That is what is achievable. Claiming more would be the same mistake as the detection vendors.

Implemented in [`crates/karst-attest`](../crates/karst-attest), wired into posts and board
policy in [`crates/karst-thread`](../crates/karst-thread).
