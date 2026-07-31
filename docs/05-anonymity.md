# 05 — L4 Mixing: anonymity as the default path

Anonymity is a requirement, not a mode. This document specifies the layer that
provides it and states plainly what it does not provide.

The design target is stated as a negative: **an adversary who observes every link in
the network simultaneously should not be able to determine who is talking to whom.**
That is the global passive adversary that onion routing explicitly does not defend
against, and defending against it is the single largest architectural difference
between KARST and Tor.

---

## 1. Position in the stack

```
  L5  Membership     who you may reach at all
  L4  Mixing         <-- this document
  L3  Wire           what the bytes look like to a censor
```

L3 makes traffic unrecognisable. L4 makes it uncorrelatable. These are different
problems and conflating them is a common error: an unfingerprintable protocol with
predictable timing is still trivially correlated end to end.

---

## 2. The two things that leak

Encryption solves content. It does not touch:

- **Volume.** How many bytes moved, and when.
- **Timing.** The gap pattern between packets, which survives every hop that forwards
  promptly.

Both survive any number of encryption layers. Onion routing hides the *path* from any
single relay while preserving both signals end to end, which is why an adversary at
both ends wins.

---

## 3. Mechanism

### 3.1 Constant-rate emission

Every participating node emits packets at a fixed rate, always, whether or not it has
anything to send. Real payloads displace cover packets; when there is no payload, cover
is sent. All packets are one fixed size.

Consequence: **volume carries zero information.** An idle node and a node streaming a
film emit identically. Participation intensity, session start and session end are all
invisible, and website fingerprinting fails because there is no size or timing profile
to match against.

This is the expensive mechanism and it is not optional. Every partial version of this
that has been deployed has been broken, because a padding scheme with gaps leaks at the
gaps.

### 3.2 Continuous-time mixing

Each hop holds each packet for an independently drawn exponential delay before
forwarding. This is a Poisson mix, in the Loopix tradition, rather than a batch mix.

Consequence: **timing correlation fails at every hop and the failures compound.** A
packet leaving a mix carries no timing relationship to the packet that entered. Batch
mixes have a well-known weakness where an adversary flushes the batch with known traffic
and watches what comes out; continuous-time mixing with per-packet delays removes the
batch boundary the attack depends on.

Delay is a tunable parameter. Higher delay means more traffic mixed together per
observation window, which means a larger anonymity set per packet.

### 3.3 Loop cover traffic

Nodes send loops: packets addressed back to themselves, routed through the network like
any other. Mixes do the same.

Consequence: an adversary who drops or delays traffic to observe the effect (an active
attack) reveals themselves, because loops that fail to return are evidence. This turns
the classic n-1 and flooding attacks from cheap and invisible into detectable.

### 3.4 Path selection without a consensus document

Tor clients need a global view to pick relays, which is why the consensus exists, which
is why the directory authorities exist, which is why there is a singleton to attack.

KARST composes paths from the signed path segments of L1, learned through the social
introductions of L5. There is no document listing the network and no authority
publishing one.

**Selection is uniform over admitted relays.** A structural preference that relay operators
can read is a placement target: guard placement attacks defeat Counter-RAPTOR, DeNASA and
LASTor, letting an adversary with 0.216% of Tor's bandwidth reach 18.22% guard selection.
Diversity heuristics are worse than uniform unless they carry a proof. The defence against an
observer sits at L5 admission instead. See `13-observation-defence.md`.

---

## 4. Traffic classes

Latency is real and some workloads cannot pay it. There are two classes and the
distinction is deliberately visible to the user.

| | `Deferred` | `Prompt` |
|---|---|---|
| Default | yes | no, must be requested |
| Latency | seconds to minutes | tens of milliseconds |
| Mixing | full Poisson delay per hop | forwarded promptly |
| Cover traffic | constant rate | constant rate |
| Global passive adversary | resisted | **not resisted** |
| Suitable for | publishing, fetching, messaging, media prefetch, agent tasks, device sync | interactive calls, live control loops |

`Prompt` is approximately Tor's guarantee: safe against a local observer and a single
malicious relay, not safe against someone watching both ends. It is available because
refusing to provide it means people tunnel latency-sensitive work over something worse,
and that is a real outcome rather than a hypothetical.

**Honest statement:** using `Prompt` is observable. Constant-rate cover hides the volume
but the class is a routing property. A user who selects `Prompt` is in a smaller
anonymity set than one who does not, and clients must say so at the point of choice
rather than in documentation.

---

## 5. What this does not protect

Stated flatly, because an anonymity system that oversells itself gets people hurt.

1. **The endpoint.** Malware, compelled unlock, or someone taking the device. No layer
   reaches this.
2. **Your own behaviour.** Posting under an identity that is linkable to you, writing in
   an identifiable style, being online only in one timezone, or having a socially
   distinctive peer set. L4 protects packets, not judgement.
3. **The gateway to today's internet.** Traffic leaving for the ordinary web is outside
   every guarantee here, and clients must mark it.
4. **The moment you join.** Constant-rate cover defeats statistical disclosure for a
   participant and not for the act of becoming one, because arriving is exactly the
   before-and-after boundary the attack needs. Measured in §8. An adversary who was already
   watching gets full attribution.
5. **The device profile.** Constrained devices are exempt from constant-rate cover
   because a battery-powered sensor cannot emit continuously. **Exempt devices are not
   anonymous.** This is a hole and we know it is a hole. See WHITEPAPER §6.11.
6. **The value layer, partially.** Paying for capacity is a correlation surface if payment and
   traffic are linkable. L14 separates acquisition from spending so they are not, but the
   *timing* of acquisition remains one: obtaining credentials immediately before a burst of
   activity narrows the field. See `14-value-and-anonymity.md`.

---

## 6. Why not just use onion routing

Because the requirement was anonymity against a serious adversary, and onion routing
does not attempt that. The choice is between a fast system with a documented gap and a
slow system without one. Given that the stated requirement is anonymity, and given that
`Deferred` covers publishing, fetching, messaging and agent work (which is most of what
this stack does), the latency is affordable in a way it was not for a system designed to
carry interactive web browsing in 2004.

The workload changed. Content addressing means most fetches are prefetchable and
cacheable, agents work asynchronously by nature, and media is streamed from a swarm
rather than pulled interactively from one origin. Those are the workloads a mix network
suits.

---

## 7. Simulated results

`crates/karst-mix` implements the packet format and a global passive adversary simulator.
200 clients, 3 mix layers, 1500 ticks, 0.5% duty cycle. The adversary observes every link,
knows the delay distribution, and computes the set of clients it cannot rule out as the
sender of each delivered message.

| Configuration | Volume leak | Anonymity set | Adversary gain | Bandwidth |
|---|---|---|---|---|
| Onion routing (no cover, no delay) | 0.356 | 2.0 | **126.6x** | 1x |
| Mixing only (no cover) | 0.333 | 64.9 | **3.2x** | 1x |
| Cover only (no delay) | 0.000 | 200.0 | 1.0x | 199x |
| KARST (cover + mixing) | 0.000 | 200.0 | 1.0x | 193x |

*Adversary gain of 1.0x means the attacker does no better than guessing at random.*

**Onion routing is trivially broken here**, which is not news since Tor documents the gap
itself. Volume alone narrows the sender to two candidates out of two hundred.

**Constant rate cover is the mechanism doing the work.** Poisson delay on its own still
leaves a 3.2x advantage, because without cover only the clients who were actually talking
transmit at all, and that set is small.

### What the passive result does not show

**Cover alone scores identically to cover plus delay.** Uniform emission at every tick is
effectively a synchronous batch mix, and a batch mix is strong against an observer who only
watches. Passive evidence alone therefore does not justify the Poisson delay mechanism. §8
does.

The adversary's timing window has to be a tight quantile of the real latency distribution. A
loose bound, say 480 ticks against a 24 tick mean, makes the attacker weak enough that every
configuration looks safe. Overstating your own defences is the failure this harness exists to
prevent.

## 8. The patient adversary

The passive and active harnesses both measure **one message**. The long-run attack is the
statistical disclosure attack (Danezis 2003, extending Kesdogan): difference the recipient
population in rounds where a target is sending against rounds where they are not, and the
excess is theirs. Against a steady-state mix network it is slowed but still succeeds.

`karst-mix::intersection` runs it against 200 users over 4,000 rounds. The metric that matters
is **attribution**: how much better the adversary does at finding the target's contacts than a
stranger's, from identical observations. A target's contacts being popular is not a secret;
the adversary knowing they are *the target's* is.

| Target behaviour | Attribution | Full recall at |
|---|---|---|
| Sends only when it has traffic | **+1.00** | round 500 |
| Constant-rate emission | 0.00 | never |
| Constant rate, joins at round 500 | +0.33 | never |
| Constant rate, joins at round 2,000 | **+1.00** | round 3,000 |

**Constant-rate emission removes the attack's input.** The differencing needs rounds in which
the target is absent, and there are none. Without it, the target is fully identified within
500 rounds.

### Joining is the hole, and everyone joins exactly once

The last two rows are the finding. Constant-rate cover protects a *participant*. It does not
protect the act of *becoming* one, because arriving creates exactly the before-and-after
boundary the attack is built on, and the longer the adversary watched beforehand the sharper
the boundary. Half an observation window of pre-join baseline identifies the target's contacts
completely.

Mitigations, none complete and none free:

- **Join before you need it.** Traffic-free participation costs the full constant rate, which
  is the point: the bandwidth bill starts when you join, not when you have something to say.
- **Never leave.** A departure is the same boundary in reverse.
- **Join in cohorts**, so an arrival is not individually timed. This needs coordination the
  rest of the design deliberately lacks.

A network you can be observed joining leaks at the moment you join. The research direction that
removes the boundary rather than padding it is **membership concealment**: Vasserman et al.,
*Membership-Concealing Overlay Networks* (CCS 2009), hide who is participating at all, so there
is no join event to observe. L5 already conceals membership from a directory; concealing it from
a network observer is the unfinished part. No MCON design has deployed, and the paper's three
proposals trade efficiency against churn robustness rather than dominating. See
`15-fundamental-limits.md`.

---

## 9. The active adversary

An adversary who can suppress traffic, not merely observe it. `karst-mix::active` mounts the
n-1 attack: block every other honest packet entering a mix, inject packets you can recognise,
and anything else departing is the target.

| Discipline | Anonymity set | Target isolated | Packets suppressed | Detected by loops |
|---|---|---|---|---|
| Batch mix (round 1) | 1.7 | **51.7%** | 10 | 65.1% |
| Poisson mix | 38.5 | 0.7% | 81 | **100.0%** |

**This reverses the passive conclusion.** A batch mix has a moment when it is empty but for
the target: the flush. Suppress one round of arrivals, ten packets, and the target walks out
alone half the time, cheaply and fairly quietly.

A Poisson mix has no such moment. Exponential residuals are **memoryless**, so the backlog
never ages out, it only drains. Draining from steady state to a single packet takes 35 ticks
and costs 351 suppressed packets, and loop cover traffic detects suppression at that volume
with certainty. The security property is not that the attack is impossible, it is that the
attack is expensive and loud.

Note the residual: isolation is 0.7% rather than zero. If the target draws a long delay and
every resident happens to leave first, it walks out alone. That is roughly one message in a
hundred and fifty. It is inherent to a probabilistic defence, and rounding it to "never" would
be exactly the overclaiming this harness exists to catch.

### Batching needs a clock, and continuous time does not

A synchronous batch mix requires every node to agree where a round begins. Under skew the
batches fragment, and a fragmented batch is a small anonymity set.

| Clock skew | Mean batch | Worst batch | Batches under 3 |
|---|---|---|---|
| 0 ticks | 10.0 | 2 | 0.5% |
| 0.5 ticks | 7.6 | 1 | 3.0% |
| 1 tick | 5.0 | **0** | **30.8%** |
| 2 ticks | 2.6 | 0 | 64.1% |

A Poisson mix has no row in that table, because it has no round boundary for anyone to
disagree about. A mechanism you cannot misconfigure is worth something that never shows up in
a passive measurement.

### Conclusion

Both mechanisms are load bearing, against different adversaries. Cover traffic defeats the
passive observer; Poisson delay defeats the active one and removes the synchronisation
requirement. Neither is redundant, and the passive harness alone would have led us to drop the
wrong one.

### The delay knob, with cover off

Delay only has measurable value when cover is absent, since with cover the candidate set is
already every client:

| Mean delay | Anonymity set | Adversary gain |
|---|---|---|
| 1 tick | 8.9 | 25.6x |
| 4 ticks | 35.6 | 5.8x |
| 16 ticks | 107.4 | 1.9x |
| 32 ticks | 154.2 | 1.3x |

Buying anonymity with latency, at a visible exchange rate.

### The cost

**Roughly 200x bandwidth at this duty cycle.** Constant rate emission means every client
transmits every tick forever whether or not it has anything to say. That is charged
continuously, to everyone, including everyone who never needed it, and it is why the device
profile is exempt and therefore not anonymous (§5.5). Any presentation of this design that
omits that number is selling something.

---

## 8. Implementation status

Nothing in this document is built. The PoC in `crates/` covers identity, objects,
capabilities and affordances, which are the layers above this one. L4 is specified
here and is the largest single piece of unbuilt work in the project.

See `08-roadmap.md`.
