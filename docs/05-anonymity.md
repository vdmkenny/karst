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

**Constraint:** hops must be drawn from standing-disjoint neighbourhoods, per L16. An
adversary aiming to hold both ends of a path must therefore infiltrate socially separate
parts of the graph rather than simply operating more machines.

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
4. **Long-term intersection attacks.** An adversary who observes the network over months
   and correlates who was online when a given identity was active still gains
   information. Constant-rate cover greatly slows this and does not stop it.
5. **The device profile.** Constrained devices are exempt from constant-rate cover
   because a battery-powered sensor cannot emit continuously. **Exempt devices are not
   anonymous.** This is a hole and we know it is a hole. See WHITEPAPER §6.11.
6. **The value layer.** L14 payments are a correlation surface. If who paid whom is
   observable, the anonymity above it is decorative. This is unresolved and it is the
   most serious open problem in the design.

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

## 7. Implementation status

Nothing in this document is built. The PoC in `crates/` covers identity, objects,
capabilities and affordances, which are the layers above this one. L4 is specified
here and is the largest single piece of unbuilt work in the project.

See `08-roadmap.md`.
