# 21 — A running network

Seven mixes in four layers on real UDP sockets, a thread each, and two clients who exchange
messages through them. `cargo run -p karst-net --bin karst-net-demo`.

This document records what the running version forced into the open. Design that survives
simulation and design that survives a socket are not the same design, and five things changed
on contact.

---

## What a node keeps

A packet is stateless. A node has a **clock** and a **queue**, and both are attack surface that
no packet-level test can reach.

`karst-node` holds exactly that: what it was given, when each thing leaves, what it has already
seen. It is transport-agnostic, so the same logic runs over UDP or over a bearer at L0 that
does not exist yet.

### Release order is not arrival order

Any node polls for due packets on an interval, so every poll emits a **batch**, and a batch in
arrival order is a FIFO at the granularity of the poll. An observer watching both sides of the
node recovers the pairing directly.

Kesdogan, Egner and Büschkes model the queue as M/M/∞ where simultaneous expiry has probability
zero, so their analysis never needs a tie-break rule and does not supply one. Quantised time
introduces a case the 1998 paper does not cover. Das, Diaz, Kiayias and Zacharias (PoPETs
2024(4)) name the leak it creates: the **FIFO attack**, where an adversary simply guesses that
messages entering earlier leave earlier, and they prove this leakage is inherent even against
an ideal trusted third party with Erlang end-to-end delay.

Batches are shuffled. The per-packet delay decorrelates across polls; the shuffle decorrelates
within one.

### The clock is internal, monotonic, and clamped

A node reads time from one source and **cannot detect that source lying**. An adversary who
pushes a node's time forward releases everything it holds with no delay, which is a mixing
bypass obtained without touching a packet. NTP is attacker-influenceable (Malhotra, Cohen,
Brakke, Goldberg, NDSS 2016), so the reading must be monotonic rather than wall time.

That is a requirement on somebody else's code, so the node clamps regardless. Time never runs
backwards and never advances more than 5s per reading, so a hostile reading costs throughput
rather than anonymity. The same clamp stops a forward jump from aging out the replay window.

The reference is the **highest reading ever presented**, not the most recent. Measuring against
the most recent lets a source rewind to reset the baseline and jump forward again,
manufacturing a full clamped step per cycle and draining a queue as fast as it can call. That
defect existed in the first version of the clamp and was found by the test written to confirm
the obvious property.

What remains is that internal time advances at most one clamped step per reading, and the node
decides when to read. The bound is the node's own poll rate, which is the one input in this
chain an adversary does not supply.

### Eviction, not refusal

The first version refused arrivals when the queue was full. **That is the defence Tor tried and
withdrew.** Jansen, Tschorsch, Johnson and Scheuermann (*The Sniper Attack*, NDSS 2014) found a
size cap exploitable rather than merely insufficient: an adversary holds many entries so memory
sits just below the limit, and honest traffic is what trips it. The adversary's entries survive
and everyone else's are turned away. Tor replaced the cap with age-ordered killing.

A mix cannot evict by age, because waiting is what a mix is for and the packet waiting longest
is often closest to leaving. The equivalent here is **remaining hold**: queue occupancy is
delay, so the packet costing the queue most is the one with the longest time still to serve,
and that is exactly what a squatter maximises. Evicting it makes occupancy cost proportional to
volume. An adversary who instead draws delays from the honest distribution gains nothing per
packet and is merely flooding, which costs them what it costs everyone.

A new arrival that is itself the longest-held is the one dropped, so the rule cannot be turned
into a way to push others out for free.

`delay_ms` is sender-chosen and a `u32`, so before the bound one packet bought a queue slot for
49 days. It is capped at 30s, below the replay epoch so a packet cannot outlive the memory of
having seen it. Katzenpost carries the same parameter as `MuMaxDelay`.

---

## What the wire does

**A link that sends when it has something to send is a traffic analysis oracle**, and it makes
every guarantee above decorative. Timing alone links sender and receiver (Danezis, *Statistical
Disclosure Attacks*, 2003).

`karst-wire` draws its schedule with no reference to the queue. When an emission comes due it
takes a real packet if one is waiting and a cover packet otherwise. The property is asserted
**exactly** rather than statistically: two pacers with the same schedule seed, one saturated and
one silent, emit at identical instants.

Emission is Poisson rather than a fixed tick. Danezis (*The Traffic Analysis of Continuous-Time
Mixes*, PET 2004) proves by calculus of variations that for a fixed mean latency the exponential
maximises entropy, so it is optimal rather than convenient, and superposition of Poisson
processes is Poisson, so a mix's output is the same analytic object as its input.

### The cost this cannot hide

Offering more than the schedule carries does not produce more packets. It produces a longer
queue. **Volume above the cover rate is visible as latency rather than concealed**, which is the
honest form of the anonymity trilemma (Das, Meiser, Mohammadi, Kate, S&P 2018): bandwidth here
is fixed by choice, so load shows up in delay.

### Membership concealment, for free and only partly

Nothing in the transport ever transmits in response to a receive. A probe therefore changes
nothing an observer can measure, because the emission schedule was drawn without reference to
anything received. Concealment against active scanning falls out of the anti-oracle design
rather than needing a mechanism, which is worth noting because Tor's public consensus concedes
this by design and membership-concealing overlays (Vasserman, Jansen, Tyra, Hopper, Kim, CCS
2009) treat it as a hard problem.

The concealment is against an adversary who can **probe** but not **watch**. One who can see
the host's own outbound stream sees a constant-rate flow and knows. That exposure is #56 and is
not addressed.

---

## What is on the wire, and what it weighs

Everything is one size. A one-byte message and a full one are indistinguishable at every point.

Getting there required a fix that simulation would not have surfaced: a Sphinx payload carries
a **length prefix**, so the hop where a packet terminates learns how many bytes the sender
meant. For a provider holding someone's mail that is message length across a whole
conversation, which is a strong fingerprint. Fragments therefore always fill the payload, and
padding lives **inside** the sealed blob where a provider can neither see it nor strip it.

What this does not hide is the **number** of fragments, which is message length rounded up. A
sender wanting that concealed pads to a fixed fragment count, and that belongs higher up
because only the sender knows what it is worth.

Fragments of one message take **independent routes**. A single route would give every node on
it a view of the whole message's timing. The cost is that losing any one fragment loses the
message, which is the price of not concentrating exposure.

---

## Sealing, and why it is not the identity key

L2 identities are Ed25519. Converting one to X25519 is possible and is the tempting shortcut.
Joint security of a signature scheme and a KEM under one key is a property that must be proved
rather than assumed (Degabriele, Lehmann, Paterson, Smart, Strefler, CT-RSA 2011), and sharing
a key **welds the two suites together**, so retiring one forces retiring the other. That is
precisely what the algorithm evolution work at L2 exists to avoid.

`karst-seal` is HPKE base mode (RFC 9180) with DHKEM(X25519) and ChaCha20-Poly1305. The mailbox
tag is authenticated as associated data, so a sealed blob cannot be lifted into another box.

**No forward secrecy against compromise of the recipient.** The ephemeral is the sender's, so a
sender whose machine is seized cannot decrypt what they sent, but a recipient's static key opens
every message ever addressed to it. A ratchet is the answer and is not built.

---

## Providers, and what they are trusted for

A recipient who must be online when a message is sent is a recipient whose presence is the
network's business. Mail waits in a box and is collected later, so being offline is not
observable to the sender.

A provider sees a mailbox tag and a fixed-size sealed blob. It does not see content, sender,
message length, or conversation size. It does see how much traffic a tag receives and when it
is collected, and it can withhold or discard. **A provider is trusted for availability and not
for confidentiality.**

Tags are 32 random bytes handed out with a contact's sealing key, not derived from an identity,
so a stranger cannot find a box to flood. The residual gap is that a **correspondent** can
flood a box they legitimately know. The answer is to gate deposit on a capability the recipient
issues, spendable anonymously so presenting one does not identify the sender. L9 and L14 hold
both halves and are not wired together.

### A full box is reported

When a box is full, new mail is refused and the refusal is counted, and the collector is told
how much was lost. Evicting instead would discard mail nobody has read, silently. This is the
same choice the design keeps arriving at: an adversary who causes loss should cause a loss that
is **visible** rather than deniable.

### Collection is not anonymous

Retrieval runs on its own port between a client and its own provider, and that link is
identified by construction. What it hides is **whether anything was there**: every response is
the same size whether it carries mail or nothing, and polling runs at a fixed rate. A provider
learns a client is online. It does not learn from the link when that client received something.

Concealing the collector from the provider is what private information retrieval is for, and it
is not built. That is #53.

---

## Two disciplines, not one

A **client** paces, because client activity is what an adversary most wants and what is
otherwise most visible.

A **mix** forwards on its delay schedule and does not pace. Its outputs are already Poisson,
being a superposition of exponentially delayed Poisson inputs, so a second scheduler would add
latency without adding uncertainty. That an observer sees which link a packet leaves on is not
a new leak, because the topology is public and the next hop is visible either way. What must
stay hidden is which *incoming* packet it was, and that is the delay's job.

---

## A claim withdrawn

An earlier version of this work asserted that a continuous mix is immune to the n-1 attack.
**That is wrong**, and the literature is unanimous about it.

Kesdogan, Egner and Büschkes note in their own paper that random delay alone does not stop the
attack, because an adversary can flood and keep flooding until the real packet emerges.
Serjantov, Dingledine and Syverson (*From a Trickle to a Flood*, IH 2002) explicitly decline to
clear stop-and-go mixes, deferring the analysis because "the precise details of parts of the
protocol crucial to the security of the system have not yet been worked out". Loopix treats n-1
as live and answers it with **detection** rather than structure, following Danezis and Sassaman
(*Heartbeat Traffic to Counter (n-1) Attacks*, WPES 2003).

The correct claim: a continuous mix has no batch boundary an adversary can force, so the attack
is not exact on demand. Flooding still works as dilution, and blocking still works if the
adversary can outlast the tolerance. **A continuous mix converts an exact attack into a
probabilistic one; it does not eliminate it.** The residue is handled by loop cover at L4.

---

## Not built

- **Stop-and-Go time windows.** Kesdogan's design has each packet carry an arrival window and a
  mix discard anything outside it, which counters the *blocking* half of n-1. The security
  condition is that the window be shorter than the time an adversary needs to drain the mix.
  The tension with the clock work above is real and unresolved: windows need a synchronised
  wall clock, and the defended clock deliberately does not track wall time. An adversary who
  shifts a mix's clock past the sync tolerance turns the window into a targeted drop primitive.
  No paper appears to write that attack up.
- **Loop cover in the running node.** `karst-mix::loops` detects dropping and is not wired into
  `karst-node`, so the n-1 residue above is currently undefended in the running network.
- **Guards.** Selection is uniform within a layer. Whether persistent entry guards are right
  here is open, and guard placement attacks defeat Counter-RAPTOR, DeNASA and LASTor, with
  0.216% of bandwidth reaching 18.22% of guard selections (Hanley, Sun, Wagh, Mittal, PoPETs
  2019).
- **A ratchet**, **PIR for collection**, and **capability-gated deposit**, all named above.

---

## References

- Kesdogan, Egner, Büschkes. *Stop-and-Go MIXes: Providing Probabilistic Anonymity in an Open
  System.* Information Hiding 1998.
- Das, Diaz, Kiayias, Zacharias. *Are continuous stop-and-go mixnets provably secure?* PoPETs
  2024(4). <https://petsymposium.org/popets/2024/popets-2024-0136.pdf>
- Serjantov, Dingledine, Syverson. *From a Trickle to a Flood: Active Attacks on Several Mix
  Types.* Information Hiding 2002.
- Danezis, Sassaman. *Heartbeat Traffic to Counter (n-1) Attacks.* WPES 2003.
- Danezis. *The Traffic Analysis of Continuous-Time Mixes.* PET 2004.
- Piotrowska, Hayes, Elahi, Meiser, Danezis. *The Loopix Anonymity System.* USENIX Security 2017.
- Jansen, Tschorsch, Johnson, Scheuermann. *The Sniper Attack.* NDSS 2014.
- Malhotra, Cohen, Brakke, Goldberg. *Attacking the Network Time Protocol.* NDSS 2016.
- Vasserman, Jansen, Tyra, Hopper, Kim. *Membership-Concealing Overlay Networks.* CCS 2009.
- Degabriele, Lehmann, Paterson, Smart, Strefler. *On the Joint Security of Encryption and
  Signature Schemes.* CT-RSA 2011.
- Barnes, Bhargavan, Lipp, Wood. *Hybrid Public Key Encryption.* RFC 9180.
- Hanley, Sun, Wagh, Mittal. *DPSelect / guard placement attacks.* PoPETs 2019.
