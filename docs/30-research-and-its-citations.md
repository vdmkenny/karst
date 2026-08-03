# Research on six open questions, and what its citations turned out to be worth
Six open design questions were researched in parallel, each write-up then handed to an
independent agent whose only job was to check its citations against the literature.

**The check found 22 citations wrong, 23 unconfirmable, and 46 specific claims
carrying no citation at all.**

That is the finding worth recording. The write-ups read as authoritative, cite real papers by
real authors at real venues, and get the details wrong in ways that survive a careful reading:
figure numbers off by one, paraphrases presented inside quotation marks, a side condition
dropped from a theorem, a date a day out. This project has twice shipped a wrong citation
already, and both times it was this shape rather than an invented paper.

**Nothing here is quoted into the whitepaper without independent verification of the specific
claim being used.** L0 Bearer was written from this research and cites only RFC 9171, RFC 9172
and RFC 9758, each fetched and checked separately, because those are the load-bearing facts and
the rest is architecture that stands on its own.

The write-ups are recorded in full because the *reasoning* is sound and worth having. Treat
every number in them as unverified until checked.


---

## L0-bearer
**Question.** Design L0 Bearer to implementable detail: multi-bearer with delay tolerance as the base case. What does KARST take and refuse from DTN (BPv7, RFC 4838, LTP, custody transfer), which store-carry-forward routing scheme fits sender-composed paths and free identities, what do real mesh deployments actually deliver, what does §6.2 concede about spectrum and fibre, and what must L0 guarantee upward for L4's cover traffic and L3's absence of handshake to survive on a 300 bit/s link at 1% duty cycle?
### Answer

Build L0 as a **frame service, not a network**: one upward interface that delivers exactly one 1024-byte frame to one adjacent endpoint per bearer-declared emission interval, with no ordering, no reliability, no acknowledgement, no handshake and no connection state, plus a signed bearer descriptor distributed exactly like an L1 segment. Every bearer, from a 10 ms UDP socket to a 24-hour courier carrying a directory of frames on a USB stick, presents that identical interface, and the only thing that varies between them is one number, `egress_interval`. Delay tolerance is then not a mode: it is what happens when that number is large. The single invariant L0 owes upward is that **the emission slot is unconditional and content-independent**: at every interval a frame leaves, cover or payload, and no timing, power, spreading factor, coding rate, retry, channel choice or acknowledgement varies with what is in it. That one rule is what L4's constant-rate cover reduces to at the physical layer, and it is testable without radio hardware.

From DTN, take the store-carry-forward architecture, the contact-plan idea and binary Spray and Wait. Refuse Bundle Protocol 7 as a wire format outright: RFC 9172 says a Block Confidentiality Block **MUST NOT** target the primary block, so source EID, destination EID, creation timestamp and lifetime travel in cleartext past every custodian, which is a sender-recipient-time tuple handed to exactly the parties L4 exists to blind. Refuse the `ipn` scheme, because RFC 9758 makes IANA the Default Allocator of node numbers, which is error 01 and error 03 in a single field. Refuse custody transfer, because a custody signal is an end-to-end acknowledgement whose timing is determined by delivery, which is the correlation channel Loopix removes; L4's loop cover already provides drop detection that a custody signal would provide worse and observably. Refuse epidemic routing, because its documented failure is contention collapse and KARST's constant-rate cover puts the channel at full load permanently. Refuse PRoPHET, because delivery predictability is computed from encounter history keyed by stable node identity, and L2 identities are free and L4 forbids recognition across encounters, so a node either has no input to the equations or has recreated the linkability the stack removed.

### Mechanism

## 1. The upward interface

A bearer driver implements exactly three operations. Nothing else crosses the boundary.

```
trait Bearer {
    fn descriptor(&self) -> BearerDescriptor;
    fn emit(&mut self, frame: [u8; FRAME_BYTES]) -> Result<(), BearerError>;
    fn poll(&mut self) -> Option<[u8; FRAME_BYTES]>;
}
```

`FRAME_BYTES = 1024`, equal to `karst_mix::packet::PACKET_BYTES`. This is not configurable.
A bearer whose medium cannot carry 1024 bytes atomically fragments and reassembles **below**
L0 and never exposes a fragment count upward, because a variable fragment count is a length
signal and L4 spent its entire bandwidth budget removing length signals.

`poll` returns whole frames or nothing. A frame that fails Sphinx header MAC verification at
L4 is dropped silently. There is no negative acknowledgement, because a negative
acknowledgement is a handshake with one message, and L3's guarantee is that no handshake
exists to fingerprint.

## 2. The bearer descriptor

A signed L6 object, distributed by the same unbuilt mechanism that distributes L1 segments.

| Field | Type | Meaning |
|---|---|---|
| `operator` | L2 address | key that signs this descriptor; address must equal hash of the key |
| `frame_bytes` | u16 | must equal 1024; any other value invalidates the descriptor |
| `egress_interval_ms` | u64 | wall clock period between emission opportunities |
| `jitter_bound_ms` | u64 | maximum deviation the driver may introduce; must be 0 for shared media |
| `medium` | enum | `PointToPoint` or `Broadcast` |
| `window` | (u64, u64) | validity window in absolute time; a descriptor outside its window is refused |
| `cell_peers` | u16 | for `Broadcast`, the count of L0 peers the driver observes in range |

Validation is the same shape as `karst-path`: the operator's verifying key is inside the
signed bytes and the address must be that key's hash. Checking the signature alone admits a
descriptor that **names a victim** and presents the attacker's key, which is the exact bug
`docs/27-path.md` records finding by mutation.

Two nodes holding different descriptors for the same operator, with non-overlapping windows,
are both correct. There is no convergence, and nothing is announced onward.

## 3. The three invariants L0 owes upward

**I1. The emission slot is unconditional.** At every `egress_interval` the driver requests a
frame from the L4 scheduler and transmits whatever it gets, including an all-cover frame. The
driver never inspects the frame. Failure behaviour: if the scheduler returns nothing within
`egress_interval / 4`, the driver transmits a locally generated cover frame rather than
skipping the slot. A skipped slot is an event and events are the input to statistical
disclosure.

**I2. No transmit parameter varies with content.** Transmit power, spreading factor, coding
rate, bandwidth, channel, retry count and acknowledgement policy are fixed for the lifetime of
a descriptor window. Concretely, on LoRaWAN this means adaptive data rate is **disabled** and
only unconfirmed uplinks are used, because ADR responds to acknowledgement patterns and
confirmed uplinks are acknowledgements. A driver that cannot disable ADR is not a conforming
bearer.

**I3. Bearer-layer identifiers rotate on the schedule, never on activity.** MAC address,
DevAddr, Bluetooth address and any other link-layer name are drawn fresh per descriptor
window, independently per bearer, and the rotation instant is a function of the window
boundary alone. Rotating on activity makes the rotation itself the event. This buys
separation from an infrastructure operator's logs and buys **nothing** against an adversary
with a receiver; see costs.

## 4. Composition with L1: segments gain time and rate

This is the one change L0 forces on a built crate.

An L1 segment today is a signed claim of willingness to carry. It becomes a signed claim of
willingness to carry **during a window at an interval**:

```
Segment { operator, next, window: (u64, u64), egress_interval_ms: u64, sig }
```

`Path::assemble` gains two refusals on top of `MAX_SEGMENTS` and loop refusal:

1. **Window continuity.** Segment *i*'s window must still be open when a frame emitted at
   composition time can plausibly arrive, computed as the sum of upstream intervals. A path
   whose later segments expire before the frame can reach them is not constructible.
2. **Rate feasibility.** The path's rate is `min(egress_interval)` inverted. A sender may not
   compose a path whose slowest segment cannot carry the rate the sender intends to emit at.

Rate feasibility is where congestion control goes. It is a **sender-side composition
constraint**, not a network-side feedback loop, because feedback is a channel and this design
does not get to have one. A relay that is oversubscribed drops, and dropping is detected by
L4 loop cover, and the sender recomposes. That is attribution rather than prevention, which is
the shape this design keeps arriving at.

## 5. Composition with L4: the delay floor

L4 draws an independent exponential per-hop delay with mean `mu`. On a bearer with emission
interval `T`, any delay below `T` is unrealisable and quantises to `T`, and quantisation to a
known grid reintroduces the batch boundary that `karst-mix::active` exists to avoid. So:

> **`mu` for every hop on a path is `max(egress_interval)` over all hops on that path**,
> with the delay still drawn independently per hop.

The fast hops give up their speed. This is not optional: a mixed-rate path leaks at the rate
boundary, because a bridging node that emits at 100 frames per second on one side and one
frame per 45 minutes on the other must discard, and its discard policy is information about
what it discarded.

The direct consequence, stated so nobody has to discover it later: **the anonymity set on a
mixed-rate path is the population of the slowest bearer, not the population of the network.**

## 6. Store-carry-forward: binary Spray and Wait, bounded to signed segments

The sender picks `L`, hands `⌊n/2⌋` copies to each carrier it hands off to and keeps `⌈n/2⌉`,
and switches to direct transmission at one copy. Two properties make this the only one of the
three candidates that composes with the rest of the stack:

- **The sender decides `L` in advance and no node in the middle makes a decision based on
  anything it learned.** That is L1's shape exactly. Epidemic and PRoPHET both require the
  middle to decide.
- **`L_min` is independent of network size and radio range** (Spyropoulos et al., Lemma 4.3),
  so a sender can choose it without a directory, a consensus or a census, none of which exist
  here.

Each copy is an independently generated Sphinx packet to a distinct first hop drawn from L1
segments the sender already holds. Copies are unlinkable to each other, so replication does
not announce that these are the same message.

**The bandwidth cost of `L` copies is zero at the margin.** Under constant-rate emission the
copies displace cover rather than adding to it. What `L` costs is goodput, not bandwidth,
which is the one place the roughly 200x cover overhead pays for something it was not bought
for.

**Sybil bound.** Binary spraying hands half your copy count to whoever you met, and L2
identities are free, so an adversary presenting a thousand faces absorbs the whole spray.
Handoff is therefore restricted to parties holding a valid signed L1 segment. That reduces the
carrier set to one the sender already vetted, and it reduces delivery probability
correspondingly. It is a real reduction, not a free one.

## 7. Custody, replaced rather than implemented

No custody signals exist. Retention is local, unilateral and silent: a node stores what it
chose to store, under a declared byte budget, for as long as it chose, and owes nobody a
signal. Bundle lifetime is replaced by the Sphinx packet's own expiry, which lives inside the
encrypted header rather than in a cleartext primary block.

- **Reliability** is end to end, via L4 loop cover. `karst-mix::loops` already puts a sample
  count on it against a ratcheted baseline.
- **Incentive**, which is the half of custody transfer that actually did work, moves to L14: a
  carrier earns a capacity credential for frames carried, with earning already separated from
  spending. It carries L14's existing leak, §6.14, and no new one.
- **Denial of service**, which RFC 4838 concedes is created by making long-term storage
  architectural, is bounded by the byte budget and by the fact that a node accepts frames only
  along paths whose segments it signed.

## 8. Bearer drivers, in build order

`karst-bearer` depends on L2 (descriptor keys), L6 (descriptor encoding) and L4 (the scheduler
whose invariant it must satisfy). It is built after L4, not before, because I1 can only be
tested against a real scheduler.

1. **Core**: the trait, the descriptor, the unconditional-slot scheduler, the `mu` floor rule.
2. **`udp` driver**, `egress_interval_ms = 10`. Replaces the current implicit bearer with an
   explicit one and changes no behaviour, which is how it gets tested.
3. **`courier` driver**, a directory of 1024-byte frames on a filesystem, interval
   configurable to hours or days. No hardware. This is the one that matters: it makes delay
   tolerance the base case in code rather than in prose.
4. **Time-scoped and rate-scoped L1 segments**, in `karst-path`.
5. **Binary Spray and Wait** over those segments, `L` as a sender parameter.
6. **Radio drivers last**, because they need hardware, per-region regulatory review, and they
   are where the RF-fingerprint and direction-finding costs land.

**The falsifying test.** Run `karst-net-demo` with the `courier` driver at a 24-hour interval
and assert that the same messages arrive under the same keys along the same paths. Any layer
above L0 that fails has an embedded latency assumption, and the claim that delay tolerance is
the base case is false until it passes.

## 9. Sneakernet as a bearer, not an anecdote

A courier is a bearer with a very large interval and very large capacity. Nothing above L0
changes. Two constraints that do not arise on radio:

- **Pad the frame count, not only the frame size.** The number of frames on the drive is a
  volume signal that fixed-size frames do not remove. A courier drive carries a fixed count
  per window, cover-filled.
- **A seized drive is a corpus for later decryption.** The drive overwrites on a schedule
  rather than on delivery, so possession time is bounded by the schedule and not by whether
  anybody collected anything.

### Costs

**The arithmetic on a slow radio bearer, which is worse than the trilemma and for a different reason.**

A Sphinx packet is 1024 bytes, so 8,192 bits. At 300 bit/s with a 1% duty cycle the sustained
rate is 3 bit/s and one packet takes about **45 minutes**. At LoRaWAN DR0, which is SF12 over
125 kHz at 250 bit/s, it is about **55 minutes**, and DR0's 51-byte application payload cap
means the packet is 21 fragments each paying its own preamble. Per hop. A three-hop `Deferred`
path is a few hours before any mixing delay, and the `mu` floor rule adds at least one
interval per hop, so call it half a day end to end.

**Anonymity does not break, and saying so precisely matters.** Das, Meiser, Mohammadi and Kate
state the necessary condition in **rounds**: no protocol achieves strong anonymity if
`2ℓβ < 1 − ε(η)`. Constant-rate emission sets the per-user send probability to 1 by
construction, so the condition holds at `ℓ = 1` round and a slow bearer does not push KARST
onto the wrong side of the theorem. The theorem says nothing about what a round costs in
seconds, and that is the whole problem.

**The channel is the problem, and the trilemma does not model it.** On a point-to-point link,
one user's cover traffic costs that user's bandwidth. On a shared broadcast medium it costs
everyone's, because every participant in radio range contends for one channel. Bor, Roedig,
Voigt and Alonso measure the ceiling directly: with default LoRaWAN settings, a 20-byte packet
every 16.7 minutes per node, and a delivery ratio above 0.9, a single sink supports **120 nodes
in 3.8 hectares** at roughly 100 m range in a built-up environment. Twenty bytes every 16.7
minutes is about 1.7 kB per node per day, so **a single Sphinx packet is about fourteen hours
of one node's entire allocation**. Note that the raw duty-cycle allowance is about 32 kB per
day, roughly twenty times more. The gap is contention, not regulation.

So on a broadcast bearer the anonymity set and the throughput trade against each other
directly, which they do not on fibre. The 121st participant does not enlarge the anonymity set
at constant cost, it takes capacity from the other 120. **The cost of anonymity on a broadcast
bearer is O(N) in a channel of fixed capacity, and KARST's answer everywhere else, that the
anonymity set is everyone, has no analogue here.** This is unsolved and no mitigation is
claimed.

**What KARST is on this bearer.** A messaging network for a few hundred people per radio cell
at hours of latency. It is not a web. The `Prompt` traffic class does not exist there, because
prompt forwarding at 3 bit/s is prompt in name only, and clients must refuse to offer it
rather than offer it slowly. Everything above L6 that assumes fetch-on-demand does not run.
And §6.11's device exemption from cover traffic, filed as a hole, becomes the **majority case**
on constrained bearers, so the anonymity-set segmentation that §6.11 calls a mistake is what
radio deployment normally looks like.

**Constant-rate emission is a direction-finding beacon.** §6.13a already records that a
metronomic emitter is separable by its own ISP with a byte counter. On radio it is worse: a
transmitter emitting on a fixed schedule at fixed power is the easiest possible target for
direction finding, and L4's central defence is what creates it. The mitigations are a lower
duty cycle, which costs anonymity, and mobility, which breaks schedules. There is no good
answer, and the least bad one is that mesh bearers are for places where the adversary is not
yet running direction-finding sweeps, which is a statement about a window rather than a
property.

**Identifier rotation buys nothing against a receiver.** Sankhe et al. classify 16 bit-similar
USRP X310 radios at 99% accuracy from IQ samples alone. Randomising DevAddr and MAC address
defeats an operator reading logs. It does not defeat an adversary with an SDR and a training
set, and every KARST radio is emitting continuously to train on.

**The concession in §6.2, stated precisely.** Licensed fibre and licensed spectrum are
property and permission is revocable, which is what Egypt 2011 and Iran 2019 demonstrate.
Unlicensed spectrum is not property and is also not a right: 47 CFR 15.5 says operators have
"no vested or recognizable right to continued use of any given frequency", must accept
interference, and "shall be required to cease operating the device upon notification by a
Commission representative". ETSI EN 300 220 caps duty cycle and ERP. So an unlicensed bearer
is legal to build and trivially legal to outlaw, and lawful operation is a per-device
conformance claim rather than a per-network entitlement.

**What survives the concession, and for how long.** Every documented shutdown since 2019 has
preserved domestic connectivity in some form, because cutting your own economy off is
expensive, and Iran's own minister put it at $35.7 million a day. That argues the bearer that
matters is the one crossing the last mile inside a city, not the one crossing the border,
which is exactly where unlicensed radio and couriers work and where a national route
withdrawal does nothing. Then the honest counter, from the same country five years later: in
2026 the reported measures included disabling mobile antennas, cutting phone lines, jamming
GPS, seizing satellite terminals, and disconnecting the domestic National Information Network
internally. Jamming does not care about your protocol and a seizure does not care about your
key. **L0 buys graceful degradation, and degradation has a floor set by physics and by
someone else's transmitter.**

### Rejected

**Bundle Protocol version 7 as the wire format (RFC 9171).** Loses on a single verified
sentence in RFC 9172: "A BCB MUST NOT target the primary block." The primary block carries
source EID, destination EID, creation timestamp and lifetime, so those travel in cleartext past
every node that handles the bundle, forever, with no BPSec configuration that changes it. That
is a sender-recipient-time tuple handed to exactly the parties L4 blinds. BPv7 also does not
have a variant that fixes this, because CRC omission and block targeting both depend on the
primary block being readable.

**The `ipn` URI scheme (RFC 9758).** Loses because it establishes an allocation authority.
IANA is the Default Allocator of node numbers, with Allocator Identifier zero. An address in
KARST is the BLAKE3 hash of a locally generated Ed25519 key and there is nobody to allocate
from. Adopting `ipn` would reintroduce error 01 and error 03 in one field, in the one layer
whose entire purpose is that no allocation happened.

**Custody transfer (RFC 4838, and BIBE / the Bundle Retransmission Mechanism as its BPv7
successor).** Loses on two counts. First, a custody signal is an end-to-end acknowledgement
travelling backwards at a time determined by delivery, which is the correlation channel Loopix
removes and which no amount of Sphinx layering fixes, because the signal's existence and
timing are the leak rather than its contents. Second, custody is a promise by a named party
with something to lose, and L2 identities are free, so a custodian who accepts everything and
drops everything pays nothing and can be a thousand parties by lunchtime. RFC 4838's own
security discussion concedes the denial-of-service surface that architectural long-term storage
creates.

**Licklider Transmission Protocol (RFC 5326) as the reliability layer.** Loses on its own
text: it has no flow control and no congestion control and is "not intended or appropriate for
ubiquitous deployment in the global Internet", and it requires the data link layer to signal
link up and link down for each destination. That per-link state signalling is precisely the
stable handshake L3 exists to not have. The red-part / green-part split is a good idea and is
kept in spirit, as `Deferred` and `Prompt` already are.

**Epidemic routing (Vahdat and Becker).** Loses on contention. Spyropoulos et al. measure
epidemic routing's delivery ratio dropping below 50% at high traffic due to severe contention
while every other scheme they test stays above 90%. KARST's constant-rate cover means the
channel is at full load permanently by construction, so epidemic routing's documented failure
mode is KARST's normal operating point rather than an edge case. It is also unbounded in
copies, which on a duty-cycle-limited medium means unbounded in other people's airtime.

**PRoPHET (RFC 6693).** Loses structurally rather than on performance. Delivery predictability
`P(A,B)` is computed from encounter history keyed by node identity, aged by `gamma^K`, and
propagated transitively through `beta`. All three equations require that a node recognise a
peer it has met before. L2 identities are free and L4 forbids recognition across encounters,
so a KARST node either keeps a stable recognisable identity, which discards the property the
stack was built for, or it has no input to the equations at all. RFC 6693 also concedes that
malicious parameter settings disrupt delivery in a PRoPHET zone with no cryptographic defence,
and with free identities the black-hole attack costs nothing.

**A global contact plan.** Loses for the same reason a global routing consensus loses at L1:
one document that everyone must agree on is one document to seize. Schedules are per-operator
signed claims inside descriptors, distributed like segments, and two senders holding different
schedules are both correct.

**FireChat's model, meaning a mesh chat app with public unencrypted rooms.** Loses on the
record. It reached real scale under real pressure, in Hong Kong in 2014 and Iraq in 2014, and
its own users complained that opponents could read the traffic, because the nearby mode was
public and unencrypted by design. It shipped one-to-one encryption in 2015 and was
discontinued. The lesson KARST takes is that the mesh part was never the hard part.

**Commotion Wireless's model, meaning a routed community mesh over OLSR.** Loses on the same
record from the other direction: $2M of State Department funding, a 1.0 release, development
inactive after 2016, the site offline by 2024. A routed mesh needs convergence, and convergence
needs everyone to be present at once, which is the assumption L0 exists to remove.

**Serval's Rhizome.** Closest prior art and the one KARST resembles: a store-and-forward
bundle layer with a Mesh Extender bridging Wi-Fi clusters over 915 MHz. Not rejected on
design, rejected as a dependency: last stable release 0.93 in 2016. Its architecture is worth
copying and its codebase is not worth adopting.

### Citations as given

Every entry below was checked this session. "Read source" means I extracted and read the
primary text. "Fetched page" means I read the publisher's or standards body's own page.

**Shutdowns**

1. Dainotti, Squarcella, Aben, Claffy, Chiesa, Russo, Pescapé. *Analysis of Country-wide
   Internet Outages Caused by Censorship.* ACM IMC 2011; extended version IEEE/ACM
   Transactions on Networking 22(6), 1964-1977, December 2014.
   **VERIFIED**: read the full extended-version PDF from CAIDA
   (`caida.org/catalog/papers/2014_outages_censorship/outages_censorship.pdf`); author list and
   affiliations read from page 1; venue confirmed by the paper's own self-citation of the IMC
   '11 version at reference [29] and by search of the ACM DL record for TNET.2013.2291244.
   **Says, verbatim from the PDF**: first loss of BGP connectivity seen by RouteViews and RIS
   on 27 January 2011 at 20:24:11 GMT for 15 IPv4 prefixes of one Egyptian AS; further losses
   over the next two hours "summing up to 236 withdrawn IPv4 prefixes"; the main event has
   "the initial step at 22:12:26 GMT, after which roughly 2500 prefixes disappear within a 20
   minute interval"; "At 23:30:00 GMT only 176 prefixes remain visible"; the outage "lasted for
   more than five days"; restoration began at 09:29:31 GMT and "by 09:56:11 GMT more than 2500
   Egyptian IPv4 prefixes are back in BGP tables around the world". For Libya, "within a few
   minutes, 12 out of the 13 IPv4 prefixes" delegated to Libya were withdrawn, and the paper
   reports "the use of packet filtering as well as BGP route withdrawals to effect the
   disruption". **This is the citation to use for Egypt 2011, not the Renesys blog.**

2. Cowie (Renesys). *Egypt Leaves the Internet.* 27 January 2011.
   **VERIFIED**: read the reproduced text at `lwn.net/Articles/425385/`. Says "At 22:34 UTC
   (00:34am local time), Renesys observed the virtually simultaneous withdrawal of all routes
   to Egyptian networks" and "Approximately 3,500 individual BGP routes were withdrawn", and
   that Noor "lost just 2 of their 85 routes into the country". **Use with care**: Dainotti et
   al. measure the same event as a 20-minute sequence beginning at 22:12:26 GMT rather than a
   simultaneous withdrawal, and they are the peer-reviewed measurement. The whitepaper's
   current phrase "within hours" is right in spirit and imprecise; "roughly 2,500 prefixes in
   20 minutes, four providers, on order" is the accurate version.

3. OONI. *Iran's nation-wide Internet blackout: Measurement data and technical observations.*
   2019. **VERIFIED**: fetched `ooni.org/post/2019-iran-internet-blackout`. Says the blackout
   began 16 November 2019 around 14:00 UTC, cellular operators disconnected first with "almost
   all other providers in Iran" following "over the next 5 hours", the initial BGP signal
   dropped by 33% representing about 15,000 fewer globally visible /24 blocks, that operators
   "used diverse mechanisms" including RST injection rather than pure withdrawal, and that
   measurements from 49 Iranian networks show "the internet blackout was not total".

4. Cloudflare. *Shutdown season: the Q2 2025 Internet disruption summary.* 2025.
   **VERIFIED**: fetched `blog.cloudflare.com/q2-2025-internet-disruption-summary/`. Gives
   three distinct Iranian shutdowns in June 2025 with per-network timestamps: 13 June
   07:15-09:45 UTC; 17 June from 14:00 UTC with staggered restoration through 18 June; and
   18 June 12:50 UTC through 25 June 05:00 UTC, with partial recovery at 02:00 UTC on 21 June
   and traffic "remaining well-below pre-shutdown volumes".

5. Meng, Bischof, Dainotti (Georgia Tech IODA). *A Comparative Look at Internet Shutdowns in
   Iran: 2019, 2022, 2025, and 2026.* 21 January 2026. **VERIFIED**: fetched the IODA report
   page; authors and date stated there. Characterises 2019 as BGP withdrawal, 2022 as selective
   mobile shutdowns plus application blocking over roughly two weeks with about 100 hours of
   mobile shutdowns, 2025 as leaving BGP largely unimpacted and using whitelisting to permit
   access to the domestic National Information Network, and 2026 as the same whitelisting
   approach. **Use this rather than the news coverage** for the claim that shutdown technique
   moved from route withdrawal to service-level filtering with the domestic network preserved.

6. Access Now / #KeepItOn. *Lives on hold: internet shutdowns in 2024.* 2025.
   **VERIFIED**: fetched `accessnow.org/internet-shutdowns-2024/`. 296 shutdowns in 54
   countries in 2024, against 283 in 39 countries in 2023; 103 conflict-related shutdowns in
   11 countries; 47 shutdowns still active at the end of 2024, 35 of them running over a year.

7. FCC. *47 CFR 15.5, General conditions of operation.* **VERIFIED**: read the regulation text
   reproduced on ARRL's Part 15 page. (a) operators have no "vested or recognizable right to
   continued use of any given frequency"; (b) operation is "subject to the conditions that no
   harmful interference is caused and that interference must be accepted"; (c) the operator
   "shall be required to cease operating the device upon notification by a Commission
   representative that the device is causing harmful interference".

**Delay-tolerant networking**

8. Burleigh, Fall, Birrane. *Bundle Protocol Version 7.* RFC 9171, Standards Track, January
   2022. **VERIFIED**: fetched `rfc-editor.org/rfc/rfc9171.html`. Confirmed authors, date and
   status; confirmed the document does not define custody transfer; confirmed the `dtn` and
   `ipn` endpoint identifier schemes and that a node's administrative endpoint EID uniquely
   identifies the node.

9. Birrane, McKeever. *Bundle Protocol Security (BPSec).* RFC 9172, Standards Track, January
   2022. **VERIFIED**: fetched `rfc-editor.org/rfc/rfc9172.html`. Contains, verbatim, "A BCB
   MUST NOT target the primary block." This single sentence is the load-bearing reason KARST
   refuses BPv7 as a wire format, and it should be quoted in the whitepaper rather than
   paraphrased.

10. *Updates to the 'ipn' URI Scheme.* RFC 9758, Standards Track, May 2025.
    **VERIFIED**: fetched the IETF Datatracker record. Establishes Allocator Identifiers, with
    IANA as the Default Allocator holding Allocator Identifier zero.

11. Cerf, Burleigh, Hooke, Torgerson, Durst, Scott, Fall, Weiss. *Delay-Tolerant Networking
    Architecture.* RFC 4838, Informational (IRTF), April 2007. **VERIFIED**: fetched
    `rfc-editor.org/rfc/rfc4838.html`. Confirmed the eight-author list, date and status.
    Defines custody transfer as transferring responsibility for reliable delivery, with a
    custodian required to avoid discarding bundles it has accepted custody of. Concedes that
    long-term storage as an architectural element creates congestion-management and
    denial-of-service problems.

12. Ramadas, Burleigh, Farrell. *Licklider Transmission Protocol: Specification.* RFC 5326,
    Experimental, September 2008. **VERIFIED**: fetched `rfc-editor.org/rfc/rfc5326.html`.
    Confirms the red-part / green-part split, the requirement that the data link layer signal
    link up and down per destination, and, verbatim, that because "no mechanisms for flow
    control or congestion control are included in the design of LTP, this protocol is not
    intended or appropriate for ubiquitous deployment in the global Internet".

13. Lindgren, Doria, Davies, Grasic. *Probabilistic Routing Protocol for Intermittently
    Connected Networks.* RFC 6693, IRTF Experimental, August 2012. **VERIFIED**: fetched
    `rfc-editor.org/rfc/rfc6693.html`. Confirmed authors, affiliations, date and status.
    Confirmed the three delivery-predictability equations (encounter update with `P_encounter`,
    aging by `gamma^K`, transitivity scaled by `beta`), the requirement that "a node needs to
    know the identity of its neighbors", and the security text conceding that malicious
    parameter settings disrupt delivery, with black-hole and identity-spoofing attacks
    enumerated and no cryptographic defence given.

14. Spyropoulos, Psounis, Raghavendra. *Spray and Wait: An Efficient Routing Scheme for
    Intermittently Connected Mobile Networks.* Proc. ACM SIGCOMM 2005 Workshops (WDTN '05),
    Philadelphia, 22-26 August 2005. **VERIFIED**: downloaded and read the full PDF from
    `chants.cs.ucsb.edu/2005/papers/paper-SpyPso.pdf`; venue confirmed from the paper's own
    copyright block. Definition 3.2 gives binary spraying, handing `⌊n/2⌋` to the encountered
    node and keeping `⌈n/2⌉`. **Theorem 3.1**: "When all nodes move in an IID manner, Binary
    Spray and Wait routing is optimal, that is, has the minimum expected delay among all spray
    and wait routing algorithms." **Lemma 4.3**: the minimum number of copies is "independent
    of the size of the network N and transmission range K, and only depends on `a` and the
    number of nodes M". Also, verbatim, under high traffic it "outperforms all other protocols,
    in terms of delay, by a factor of 1.8 − 3.3", and "the delivery ratio of almost all schemes
    in this scenario was above 90% for all traffic loads, except that of Seek and Focus which
    was about 70%, and that of Epidemic routing which plummeted to less than 50% for very high
    traffic, due to severe contention".

15. Vahdat, Becker. *Epidemic Routing for Partially Connected Ad Hoc Networks.* Technical
    Report CS-2000-06, Duke University, 2000. **PARTIALLY VERIFIED**: the citation string
    "Technical Report CS-200006, Duke University, Apr. 2000" appears at reference [27] of the
    Spyropoulos et al. PDF I read. I could **not** read the technical report itself; Duke's
    project page failed with a TLS certificate mismatch. Cite it only for the mechanism, which
    is described by Spyropoulos et al., and take the contention-collapse result from
    Spyropoulos et al. rather than from Vahdat and Becker. See unverified.

16. Pentland, Fletcher, Hasson. *DakNet: Rethinking Connectivity in Developing Nations.* IEEE
    Computer 37(1), 78-83, January 2004, doi:10.1109/MC.2004.1260729. **CITATION VERIFIED**
    across multiple independent bibliographic records including the ACM DL record and the NASA
    ADS abstract entry. **Content not verified**: the MIT tech report PDF would not extract.
    Cite only as prior art for vehicle-carried store-and-forward. Do not attach numbers.

17. Dye, Nemer, Mangiameli, Bruckman, Kumar. *El Paquete Semanal: The Week's Internet in
    Havana.* CHI 2018, Paper 639, doi:10.1145/3173574.3174213. **CITATION VERIFIED** from the
    ACM DL record and the first author's own hosted copy. **Content not verified**: I did not
    read the paper. Cite for the existence of a large hand-carried offline distribution system,
    not for a figure.

**Radio**

18. LoRa Alliance, *LoRaWAN Regional Parameters*, EU863-870 band, via The Things Network's
    regional parameters documentation. **VERIFIED**: fetched
    `thethingsnetwork.org/docs/lorawan/regional-parameters/eu868/`. Data rates: DR0 SF12/125
    kHz 250 bit/s; DR1 SF11 440; DR2 SF10 980; DR3 SF9 1760; DR4 SF8 3125; DR5 SF7 5470; DR6
    SF7/250 kHz 11000; DR7 FSK 50 kbps. Application payload 50 to 222 bytes depending on data
    rate. Three mandatory channels at 868.10, 868.30 and 868.50 MHz.

19. ETSI EN 300 220 sub-band duty cycles, via The Things Network's regional limitations page.
    **VERIFIED as TTN's summary**, not from the standard itself: K (863-865 MHz) 0.1% at 25 mW
    ERP; L (865-868) 1%; M (868-868.6) 1%; N (868.7-869.2) 0.1%; P (869.4-869.65) 10% at 500
    mW; Q (869.7-870) 1%. The "36 seconds per hour" figure is my arithmetic on 1% of 3600 s,
    not a quotation.

20. Bor, Roedig, Voigt, Alonso. *Do LoRa Low-Power Wide-Area Networks Scale?* Proc. ACM MSWiM
    2016, Malta, 59-67, doi:10.1145/2988287.2989163. **VERIFIED**: downloaded and read the full
    PDF from Uppsala's DiVA repository; authors, affiliations and venue read from page 1.
    Abstract, verbatim: "Our experiments show that a typical smart city deployment can support
    120 nodes per 3.8 ha, which is not sufficient for future IoT deployments." Body, verbatim:
    "With typical LoRaWAN settings (SF12, 125 kHz bandwidth, CR 4/5), the assumption of a 20
    byte packet is sent by each node every 16.7 min and a DER > 0.9 requirement, N = 120 nodes
    can be supported"; "The modelled communication range here is around 100 m (as observed in
    our experiments in a built up environment)"; with airtime-minimising dynamic settings "well
    over N = 1600 nodes can be supported", which the authors themselves call "not practical"
    and reliant on "quite optimistic assumptions". **This is the citation that carries the
    broadcast-contention argument.**

21. Georgiou, Raza. *Low Power Wide Area Network Analysis: Can LoRa Scale?* IEEE Wireless
    Communications Letters 6(2), 162-165, April 2017, doi:10.1109/LWC.2016.2647247.
    **CITATION VERIFIED** from the IEEE record. Reported finding, from the publisher's
    abstract: coverage probability drops exponentially as the number of end devices grows, in a
    stochastic geometry model that explicitly includes the duty cycle limit and ALOHA access.
    Cite as corroboration of Bor et al.; I did not read the full text.

22. Meshtastic project documentation. **VERIFIED**: fetched `meshtastic.org/docs/overview/
    radio-settings/`, `/docs/configuration/radio/lora/` and `/docs/overview/mesh-algo/`. Modem
    presets: Long Fast 1.07 kbps at SF11/250 kHz/CR 4/5; Long Slow 0.18 kbps at SF12/125 kHz/CR
    4/8; Short Turbo 21.88 kbps. Hop limit: "Maximum number of hops. This can't be greater
    than 7. Default is 3". Maximum 237 bytes of packet data. Managed flooding with an
    SNR-dependent contention window so that distant nodes rebroadcast first. Broadcast
    intervals scale above 40 online nodes by `Interval * (1.0 + ((N - 40) * 0.075))`.

23. Meshtastic project blog, *Is LongFast Holding Your Mesh Back?*. **VERIFIED as
    self-reported community figures**, fetched from `meshtastic.org/blog/`: the Wellington
    Region Mesh grew past 150 active nodes on LongFast with "channel utilisation peaks at busy
    sites hitting over 65%"; the Bay Area group runs over 150 nodes on MediumSlow; the project
    suggests changing preset above about 60 nodes in close proximity. These are operator
    reports, not measurements.

24. Sankhe, Belgiovine, Zhou, Riyaz, Ioannidis, Chowdhury. *ORACLE: Optimized Radio
    clAssification through Convolutional neuraL nEtworks.* IEEE INFOCOM 2019, Paris,
    doi:10.1109/INFOCOM.2019.8737463. **CITATION VERIFIED** from the IEEE/ACM record and the
    arXiv preprint 1812.01124. Reported result: 99% classification accuracy over a 16-node USRP
    X310 testbed of bit-similar devices using only physical-layer IQ samples. I read the
    abstract, not the full paper.

**Prior mesh deployments**

25. Commotion Wireless. **VERIFIED as Wikipedia-sourced**: $2 million grant from the US
    Department of State in 2011; built on OLSR, OpenWrt, OpenBTS and Serval; Detroit testing in
    late 2012; Commotion 1.0 released 30 December 2013; development inactive after 2016; site
    offline around September 2024. No primary source consulted.

26. Serval Project. **VERIFIED as Wikipedia-sourced**: Rhizome is a store-and-forward / DTN
    layer with bundles as the transport unit; the Mesh Extender links Wi-Fi clusters over ISM
    915 MHz; based at Flinders University; latest stable release 0.93, 15 May 2016. The Mesh
    Extender productisation paper (Gardner-Stephen, Challans, Lakeman et al., IEEE GHTC 2017)
    exists; I did not read it.

27. Briar. **VERIFIED**: fetched `briarproject.org/how-it-works/`. Syncs "via Bluetooth, Wi-Fi
    or memory cards" when the internet is down and via Tor when it is up; messages "are
    synchronized directly between the users' devices". The site states its adversary has "a
    limited ability to monitor short-range communication channels". Briar's own pages state no
    range figures and no battery figures; see unverified.

28. FireChat. **PARTIALLY VERIFIED**: launched March 2014 on iOS, April 2014 on Android;
    discontinued, with apps not updated since 2018 and the site returning 404 (Wikipedia).
    Roughly 40,000 downloads in Iraq in 2014 during government internet restrictions
    (corroborated across Wikipedia and contemporaneous reporting). Hong Kong 2014 figures
    conflict across sources; see unverified. Multiple contemporaneous accounts state the
    nearby mode carried no encryption and that rooms were publicly readable, and that
    end-to-end encryption for one-to-one private messages arrived only in July 2015.

**Anonymity**

29. Das, Meiser, Mohammadi, Kate. *Anonymity Trilemma: Strong Anonymity, Low Bandwidth
    Overhead, Low Latency, Choose Two.* IEEE S&P 2018. **VERIFIED**: downloaded and read the
    full 26-page PDF from `freehaven.net/anonbib/cache/trilemma-oakland2018.pdf`; authors and
    affiliations read from page 1 (Das and Kate at Purdue, Meiser at UCL, Mohammadi at ETH
    Zurich). The bound, verbatim from the paper: against a global network-level adversary "no
    protocol can achieve strong anonymity if `2βℓ < 1 − 1/poly(η)` even when all the protocol
    parties are honest", and with `c` of `K` parties passively compromised, "strong anonymity
    is impossible if `2(ℓ − c)β < 1 − 1/poly(η)`". Lemma 1 (Informal Trilemma) states it as
    `2ℓβ < 1 − ε(η)`. `ℓ` is defined as "the number of rounds a message can be delayed by the
    protocol before being delivered" and `β` as "the number of noise messages per user that the
    protocol can create in every round". Their own Loopix analysis computes `(p' + β)ℓ = 1` and
    concludes "the trilemma does not exclude" strong anonymity for Loopix. **The critical point
    for L0: the bound is in rounds and says nothing about the wall-clock or channel cost of a
    round.** `docs/15-fundamental-limits.md` already states the theorem correctly and does not
    need changing, only extending.

### What the author could not verify

Things I wanted to claim and could not confirm. Do not put any of these in the whitepaper
without further work.

1. **Vahdat and Becker's technical report number and date.** Sources give both "CS-2000-06"
   and "CS-200006", and both April 2000 and July 2000. The only form I read directly is
   "Technical Report CS-200006, Duke University, Apr. 2000", in Spyropoulos et al.'s
   bibliography. Duke's project page failed with a TLS certificate mismatch and I never read
   the report. I have **not** verified any number attributed to epidemic routing by that
   report, including delivery rate and buffer behaviour. The contention-collapse figure below
   50% comes from Spyropoulos et al. measuring epidemic routing, not from Vahdat and Becker.

2. **Author list of *Characterizing Iran's Phased National Internet Shutdown in 2025: A
   Progressive and Distributed Action*, ACM Web Conference 2026, doi 10.1145/3774904.3792699.**
   The ACM DL returned 403 twice and no preprint surfaced. The findings I saw in search
   snippets of the ACM abstract, that the blockade reached 98 of the top 100 ASes and 49 of
   the top 50 network services across four phases, are plausible and unread by me. **Do not
   cite this paper.** Use the IODA report (Meng, Bischof, Dainotti) and the Cloudflare Radar
   timeline instead, both of which I verified.

3. **Iran 2026 Starlink jamming figures.** The claims that jamming degraded 30% of Starlink
   uplink and downlink and escalated past 80%, that GPS L1 denial was the primary mechanism,
   and that possession of a satellite terminal carries up to ten years' imprisonment, come
   entirely from news and trade outlets. No measurement paper, no primary legal source. The
   qualitative claim, that a state jammed satellite service at national scale during a
   shutdown, is corroborated across many outlets; the numbers are not.

4. **Iran 2026 shutdown end date, connectivity percentages and economic cost.** The dates
   8 January to 26 May 2026, the roughly 1% connectivity level, and the $35.7 million per day
   ministerial figure come from Wikipedia aggregating NetBlocks and press reports. I could not
   find a peer-reviewed measurement of the 2026 event. Attribute to NetBlocks by name, or use
   the 2025 event where I have Cloudflare's per-network timestamps.

5. **Bluetooth mesh numbers.** I could not verify the 29-byte Network PDU or the 384-byte
   maximum access payload against the Bluetooth Mesh Profile specification, and the arXiv
   scalability paper (*Understanding the Performance of Bluetooth Mesh*) would not extract. The
   TTL maximum of 127 and the 32,767 node cap appear consistently across secondary tutorials
   only. **I have therefore written no Bluetooth mesh throughput or scalability claim.** If
   Bluetooth mesh is to appear in the whitepaper it needs the specification read directly.

6. **Briar's battery cost and Bluetooth range.** The "four times faster battery drain" and
   "10 to 30 metres" figures circulate on a low-quality blog. Briar's own pages state neither.
   The qualitative claim, that an app with no server must run continuously and therefore costs
   more battery, is uncontroversial; the multiplier is not sourced.

7. **FireChat's Hong Kong 2014 usage.** Contemporaneous reporting gives 200,000 downloads over
   three days, 100,000 in 24 hours after Joshua Wong's post, 500,000 downloads over 27
   September to 10 October, and 800,000 total users by early October, from different outlets
   with different windows. These are not necessarily inconsistent but I could not reconcile
   them. Use "hundreds of thousands of downloads in the first weeks" or cite one outlet
   explicitly. I also could not verify the more interesting claim I wanted to make, that most
   FireChat traffic in Hong Kong actually travelled over the internet rather than over the
   mesh, because mesh mode needs device density that a dispersed protest does not have. It is
   widely asserted in secondary commentary and I found no measurement.

8. **El Paquete's reach.** "Roughly 5 million Cubans" and "about 1 TB per week" come from
   journalism, not from the CHI 2018 paper, which I did not read. Cite the paper for the
   phenomenon and drop the numbers, or read the paper.

9. **DakNet's performance.** No throughput, cost-per-village or coverage figure verified; the
   MIT tech report PDF would not extract. Citation is sound, numbers are absent.

10. **Commotion and Serval end dates.** Both from Wikipedia. "Development inactive after 2016"
    and "last stable release 0.93, May 2016" are consistent with what I could see of the
    projects' public artefacts but I did not check the repositories.

11. **My LoRa arithmetic.** The 45-minute and 55-minute per-packet figures, the 36 seconds per
    hour, the 3 bit/s and 2.5 bit/s sustained rates, the 32 kB per day, the 21 fragments at DR0
    and the "fourteen hours of one node's allocation" are **my arithmetic** on verified inputs
    (1024-byte Sphinx packets from `karst-mix::packet::PACKET_BYTES`, LoRaWAN data rates and
    payload caps from the regional parameters, Bor et al.'s 20 bytes per 16.7 minutes). They
    are not quoted from any source and nobody has checked them but me. They should be recomputed
    by hand before publication, and the airtime figures ideally checked against a LoRa airtime
    calculator including preamble and header overhead, which my figures omit and which makes
    them optimistic.

12. **The claim that shutdowns preserve domestic connectivity because it is expensive not to.**
    The pattern is documented (IODA, Cloudflare) and the cost figure is Iran's own minister
    quoted in the press. The **causal** claim, that cost is why domestic connectivity survives,
    is my inference and is not established by anything I read. State it as a pattern, not a
    mechanism.

13. **RF fingerprinting against a duty-cycled LoRa transmitter specifically.** ORACLE is
    Wi-Fi and USRP at high sample rates. I found nothing verifying that the same accuracy holds
    against narrowband sub-GHz transmissions at low duty cycle. The direction-finding argument
    stands on its own and does not need ORACLE; the identifier-rotation-is-useless argument
    currently rests on a transfer of results across a modulation and band it was not measured
    on. Say so, or find a sub-GHz result.

14. **Anonymity in delay-tolerant networks.** There is a literature on anonymous DTN routing. I
    did not search it properly and consequently do not know whether the broadcast-contention
    problem in "costs" is already named and solved somewhere. That gap is the most likely place
    this design is reinventing something badly.

### Independent citation check

**Wrong:**

- #5 IODA (Meng, Bischof, Dainotti, 21 Jan 2026) — the 2026 characterisation is wrong, and it is wrong in the direction that matters for the claim it is cited to support. The write-up says '2026 as the same whitelisting approach' and recommends the report be used for 'the claim that shutdown technique moved from route withdrawal to service-level filtering WITH THE DOMESTIC NETWORK PRESERVED'. The report says the opposite for 2026: the January 2026 shutdown 'took down the NIN and whitelisted SIM cards', i.e. the National Information Network was NOT preserved, and the report describes 2026 as more severe and more rushed than 2025, not the same. CORRECTION: restrict the 'domestic network preserved' claim to 2019, 2022 and 2025. For 2026, say the whitelisting mechanism was retained but applied at the SIM level with the domestic NIN itself taken down. Everything else in this entry is correct — author list and order (Amanda Meng, Zachary Bischof, Alberto Dainotti), date 21 January 2026, 2019 as BGP withdrawal ('withdrawal of routing announcements', a 'blunt force tool', 16-21 November), 2022 as ~two weeks of nightly mobile-only shutdowns with 'around 100 hours of mobile shutdowns' plus application blocking, and 2025 as 'BGP or Routing Announcements were not used ... BGP was largely un-impacted' with whitelisting to the NIN.

- #20 Bor et al. — the passage presented as 'Body, verbatim' is not verbatim. It is a reconstruction that stitches together three separate statements and silently expands a symbol. The write-up gives: 'With typical LoRaWAN settings (SF12, 125 kHz bandwidth, CR 4/5), the assumption of a 20 byte packet is sent by each node every 16.7 min and a DER > 0.9 requirement, N = 120 nodes can be supported'. No such sentence exists in the paper. What the paper actually says, in three places: the Figure 4 caption reads 'With typical LoRaWAN settings (SN 3) and a typical DER > 0.9 requirement N = 120 nodes can be supported'; the body reads 'If we would assume that an application requires a DER > 0.9 to provide useful functionality we would be able to support N = 120 nodes with the default LoRaWAN configuration (SN 3)'; and the packet rate comes from a different sentence, 'In all settings we assume a 20 byte packet is sent by each node every 16.7 min representing a realistic application'. The expansion of SN 3 into 'SF12, 125 kHz, CR 4/5' is factually correct — Table 2 gives SN 3 as TP 14 dBm, CF 868 MHz, SF 12, BW 125 kHz, CR 4/5, B 20 bytes — but it is the write-up's substitution, not the paper's words. CORRECTION: either quote the Figure 4 caption exactly and gloss SN 3 in square brackets, or drop the 'verbatim' label and present it as a paraphrase. No number in it is wrong; only the claim that it is a quotation is wrong. This matters because the entry is explicitly marked 'This is the citation that carries the broadcast-contention argument', so it is the one most likely to be quoted onward.

**Unconfirmed:**

- #15 Vahdat & Becker, Duke TR CS-2000-06 — remains unconfirmed for content, and the write-up's own account of why is accurate rather than an excuse. I independently reproduced the exact failure: http://issg.cs.duke.edu/epidemic/epidemic.pdf returns 'Hostname/IP does not match certificate's altnames: Host: issg.cs.duke.edu is not in the cert's altnames: DNS:nlplab.cs.duke.edu'. The citation string itself is confirmed to exist, both independently and at reference [27] of the Spyropoulos PDF. Keep the current handling: cite for mechanism only, take contention collapse from Spyropoulos et al. No change needed.

- #19 ETSI ERP figures — the two power figures are not on the cited page. The write-up attributes to TTN's regional-limitations page 'K (863-865 MHz) 0.1% at 25 mW ERP' and 'P (869.4-869.65) 10% at 500 mW'. The page carries the six duty cycles and frequency ranges but no ERP column at all. The 25 mW and 500 mW values are correct as a matter of ETSI EN 300 220, but they do not come from the source cited for them. CORRECTION: either drop the ERP figures from this citation or add a citation to EN 300 220-2 itself (or to the ERC/REC 70-03 annex) for them. The write-up already correctly labels this entry 'VERIFIED as TTN's summary, not from the standard itself', so this is a scoping slip rather than a substantive error.

- #29 omitted side condition — the compromised-party bound is quoted without its guard. The write-up gives 'with c of K parties passively compromised, strong anonymity is impossible if 2(ℓ - c)β < 1 - 1/poly(η)'. The paper states this for c < ℓ only, and gives a separate case for c >= ℓ: '2βℓ < 1 - 1/poly(η) and ℓ ∈ O(1)'. Quoted unconditionally, the expression goes negative and becomes vacuous once c exceeds ℓ. CORRECTION: append '(for c < ℓ)'. If docs/15-fundamental-limits.md is being extended rather than changed, as the entry proposes, this is the thing to add.

- #14 basis-of-verification slip — the write-up says the WDTN '05 venue was 'confirmed from the paper's own copyright block'. The copyright block reads only 'SIGCOMM'05 Workshops, August 22-26, 2005, Philadelphia, PA, USA' and contains no 'WDTN' string. The venue claim is correct and I confirmed it via the ACM DL record (doi 10.1145/1080139.1080143, 'Proceedings of the 2005 ACM SIGCOMM workshop on Delay-tolerant networking'), but the stated evidence does not support the stated claim.

**Claims with no citation:**

- Sphinx is load-bearing and never cited anywhere. The write-up depends on it structurally, not decoratively: 'FRAME_BYTES = 1024, equal to karst_mix::packet::PACKET_BYTES'; 'A frame that fails Sphinx header MAC verification at L4 is dropped silently'; 'Each copy is an independently generated Sphinx packet to a distinct first hop'; 'Bundle lifetime is replaced by the Sphinx packet's own expiry, which lives inside the encrypted header rather than in a cleartext primary block'. That last one is the entire positive half of the Refuse-BPv7 argument — RFC 9172 supplies the negative half and is cited, but the claim that Sphinx puts expiry inside the encrypted header has no source. Add Danezis & Goldberg, 'Sphinx: A Compact and Provably Secure Mix Format', IEEE S&P 2009.

- Loopix is invoked three times as an authority and never cited. 'Refuse custody transfer, because a custody signal is an end-to-end acknowledgement whose timing is determined by delivery, which is the correlation channel Loopix removes'; 'L4 draws an independent exponential per-hop delay with mean mu'; 'L4's loop cover already provides drop detection'. The exponential per-hop delay and the loop-cover drop-detection mechanism are both specific technical claims about a named published system. Citation #29 discusses Loopix but is not a citation OF Loopix. Add Piotrowska, Hayes, Elahi, Meiser, Danezis, 'The Loopix Anonymity System', USENIX Security 2017.

- 'the roughly 200x cover overhead' (§6) — a specific quantitative figure with no citation and no derivation shown. It also does load-bearing work, since the paragraph's conclusion ('The bandwidth cost of L copies is zero at the margin ... What L costs is goodput, not bandwidth') depends on the overhead being large enough that L copies fit inside it. Either derive it inline from the emission interval and payload rate, or cite the internal doc that does.

- 'adaptive data rate is disabled and only unconfirmed uplinks are used, because ADR responds to acknowledgement patterns and confirmed uplinks are acknowledgements' (I2) — a substantive factual claim about LoRaWAN MAC-layer mechanics, and the basis for declaring a driver non-conforming. Citation #18 covers only the EU868 regional data-rate table and carries nothing about ADR semantics or confirmed-uplink behaviour. Cite the LoRaWAN 1.0.4/1.1 specification (ADR is defined in the MAC layer spec, not the regional parameters document).

- 'the anonymity set on a mixed-rate path is the population of the slowest bearer, not the population of the network' (§5) — flagged in the text as a direct consequence 'stated so nobody has to discover it later', but no derivation and no citation. Given it is the sharpest security claim in the document, it should either point at the trilemma treatment in docs/15-fundamental-limits.md or carry a short proof sketch.

- 'Radio drivers last, because ... they are where the RF-fingerprint and direction-finding costs land' (§8) — RF fingerprinting is covered by #24 (ORACLE), but direction finding has no citation at all and is presented as a known cost class. Either cite something for RF geolocation of low-power transmitters or drop it to a named open question.

- 'a bridging node that emits at 100 frames per second on one side and one frame per 45 minutes on the other must discard' (§5) — the two rates are presented as concrete illustrative figures but neither maps to any bearer defined in the document (the udp driver is 10 ms = 100/s, so that half is consistent; the 45-minute figure appears nowhere else and does not match the courier driver's stated hours-to-days range). Minor, but if these are meant as the udp and courier drivers, use their actual declared intervals.

---

## access-link
**Question.** What does a KARST user's access link look like to their own ISP, and can anything be done about it? (Issues #56, #46, #9; WHITEPAPER §6.13a and §6.11a; docs/05-anonymity.md.)
### Answer

The problem as posed has no solution, and the design should stop looking for one and start bounding it instead. Constant-rate emission is unhideable from the party that meters your line, because that party sees the aggregate byte counter and nothing you do inside the tunnel changes it. Every escape route in issue #56 either fails against statistical disclosure or reintroduces coordination that the rest of KARST deliberately refuses. The recommendation is to split the claim, not to defend it: state that KARST provides anonymity against a global network observer and does not provide unobservability against the subscriber's own access provider, put that sentence in §3 L3 where the contradicted claim currently sits, and surface it in the client at first run.

Three things then follow that are cheap, defensible and currently missing. First, make the absolute emission rate an explicit parameter of the threat model. The anonymity trilemma constrains the product of latency overhead and per-round noise rate, not the wall-clock byte rate, so the same anonymity is purchasable at a far smaller ISP footprint by duty-cycling the whole network on a public, loosely synchronised envelope and paying in latency. `Deferred` is the traffic class that can afford it. Second, emit as a Poisson process at fixed rate rather than as a metronome. This is what Loopix, which docs/09 says L4 is, actually specifies, it costs nothing in statistical-disclosure resistance because the rate parameter remains payload-independent, and it removes the exactly-zero variance that `karst-mix::exposure` currently reports. Third, for the join event, adopt policy-driven suppression in the manner of Buddies rather than trying to conceal the arrival: the join is a special case of churn, churn is the general problem, and the published trace-based upper bounds say long-lived identities cannot be protected from churn by padding at any price.
### Mechanism

## 1. What the ISP actually measures, and why the current framing is slightly wrong

The unit of observation is not a flow. It is a subscriber, over months. That distinction matters
because it inverts the base-rate argument that protects circumvention tools against censors.

Wang et al. (CCS 2015) analyse exactly that base rate for a censor: at a 99% true-positive rate,
a 1% false-positive rate and a base rate of one obfuscated flow in a billion, only about 1 in
10,000,000 flagged flows is really obfuscated. Per-flow classification is drowned by the base
rate. An access provider asked "which of your subscribers emits at a fixed rate continuously"
is not running a per-flow test. It is running a per-subscriber test over an unbounded
observation window, and evidence accumulates linearly in that window while the population stays
fixed. A signal that is present in every five-minute bin, every day, for months, is not subject
to the base-rate fallacy in any useful way.

So the honest statement of the exposure is:

- **Not:** "a classifier separates KARST from ordinary traffic at above 99%."
- **But:** "a permanent, stationary emission rate with no diurnal structure is a per-subscriber
  property, observable in ordinary flow telemetry, and it accumulates evidence without bound."

The second is stronger and it is defensible. The first is a claim about `karst-mix::exposure`'s
synthetic generator, not about residential traffic (see `unverified`).

## 2. Rate is a free parameter and the threat model does not contain it

`docs/05-anonymity.md` §7 reports roughly 200x bandwidth at a 0.5% duty cycle. That is a ratio.
The absolute rate is unspecified anywhere in the design, and it is the only quantity the ISP
sees.

Two configurations with identical anonymity properties:

| Configuration | Emission | Goodput | Subscriber-visible |
|---|---|---|---|
| A | 100 pkt/s x 1024 B = 819 kbit/s, always | 4.1 kbit/s | Saturated line, 24/7, unmistakable |
| B | 1 pkt/s x 1024 B = 8.2 kbit/s, always | 41 bit/s | Sits under a residential idle floor |

Both are 200x. Both give volume-carries-zero-information. They are not remotely equally
exposed. The design currently specifies neither, which means it has been arguing about a
property it never fixed.

Vuvuzela is the calibration point: 256 bytes per client per round, rounds of tens of seconds,
which is single-digit bytes per second, and it is a messaging system with strong metadata
privacy at two million users. A mixnet carrying only messaging, control and small fetches has
an ISP problem measured in tens of kbit/s. A mixnet carrying media and bulk fetch has an ISP
problem measured in Mbit/s. **KARST's ISP exposure is a consequence of L7 Streams and L6 bulk
fetch riding the same anonymous default, not of L4.**

Concrete rule: the anonymous default carries messaging, capability invocation, index queries and
objects below a stated size. Everything above that size is a separate, explicitly labelled
transfer over a path with a weaker and stated guarantee, in the same way `Prompt` already is.

## 3. Duty cycling on a global envelope

Das, Meiser, Mohammadi and Kate define latency overhead `l` as the number of rounds a message
may be delayed and bandwidth overhead `b` as the number of noise messages per user per round.
Their informal trilemma: strong anonymity is impossible if `2*l*b < 1 - eps(eta)`. They
separately analyse *synchronised* user distributions, where users globally synchronise their
messages, and *unsynchronised* ones, where each user decides locally.

Take a public function `L(t)` of wall-clock time, identical for every participant, with duty
cycle `d`. During on-periods a client emits at the full instantaneous rate. During off-periods
it emits nothing. Then:

- **Statistical disclosure gets nothing new.** SDA differences rounds where the target is
  sending against rounds where it is not. Under a global envelope, absence is universal:
  there are no rounds in which the target is absent and other users are present. Off-periods
  are dead time for everyone, including the attacker.
- **The trilemma constraint does not tighten.** The per-round noise rate `b` during on-rounds
  is unchanged, and wall-clock latency rises to `l/d`, so the product `l*b` rises. The
  constraint is satisfied more easily, not less.
- **The average bandwidth bill falls by `d`,** which is the number the subscriber pays and the
  number the ISP meters.

Validation rules for `L(t)`:

1. `L(t)` is a published constant of the protocol version, not a per-user choice. A per-user
   schedule is an unsynchronised user distribution: it creates rounds where the target is
   absent and others are present, which is precisely the join event repeated every off-period,
   and SDA converges at a rate proportional to `d`.
2. `L(t)` requires global time agreement at the granularity of the envelope, minutes to tens of
   minutes, not at packet granularity. This does **not** reintroduce the failure mode in
   `docs/05-anonymity.md` §9: that table is about batch boundaries at tick granularity, where a
   one-tick skew puts 30.8% of batches under three members. An envelope with a fifteen-minute
   period tolerates minutes of skew with no effect. The design's clock-free property is
   preserved where it was load bearing.
3. `L(t)` should be shaped to a plausible residential diurnal curve, low at 04:00, high at
   21:00, and its amplitude chosen so the trough sits under the subscriber's ordinary idle
   floor.

**Failure behaviour, stated plainly:** rule 3 does not make the subscriber unremarkable. It
changes the classifier's job from "threshold on variance" to "correlate against a known public
template", which is a matched filter and is *easier* if the template is followed exactly.
Adding per-user jitter to defeat the matched filter breaks rule 1. This is the trilemma
appearing as a design constraint rather than a bound: per-user rate variability is exactly what
the ISP needs to see less and what the global adversary needs to see more.

The envelope is therefore worth doing for the bandwidth bill and for the latency-for-bandwidth
trade it makes available. It is not worth doing as a concealment mechanism, and it should not be
sold as one.

## 4. Poisson emission instead of a metronome

`docs/05-anonymity.md` §3.1 specifies a fixed rate. Loopix specifies a Poisson process:
"regardless of whether a user actually wants to send a message or not, there is always a stream
of messages being sent according to a Poisson process Pois(lambda_P)", plus independent Poisson
loop and drop streams at rates `lambda_L` and `lambda_D`. The aggregate is Poisson.

Change `karst-mix` to emit Poisson at fixed rate. Justification:

- The rate parameter stays payload-independent, so sender online unobservability, which is what
  Loopix proves and what defeats SDA, is unaffected.
- Per-interval counts become Poisson rather than constant, so the coefficient of variation over
  an interval containing `n` packets is `1/sqrt(n)` rather than exactly zero.
- It aligns the implementation with the paper `docs/09-references.md` says L4 *is*.

**Honest bound on the benefit:** over a five-minute flow-record bin at 100 pkt/s, `n = 30000`
and the coefficient of variation is about 0.006. That is not meaningfully different from zero
to a byte counter. The change removes an artefact of the simulation, not the exposure. Do it
because the current code contradicts the cited paper, not because it fixes anything.

## 5. The join event

Reframe it. Joining is not a special hazard; it is the first instance of churn, and churn is the
general problem. Wolinsky, Syta and Ford measured the ceiling directly on month-long IRC traces
of 1207 users: pseudonyms used for up to about an hour reliably reach anonymity sets of at least
250 members, between 20% and 30% of the observed population, and "achievable anonymity under
these assumptions falls off rapidly as pseudonym lifetime increases further". That is an upper
bound independent of mechanism. No padding scheme beats it, because the constraint is who was
continuously online, not what they sent.

Buddies' answer is a Policy Oracle: a component with access only to public information that, in
each round, filters the set of users permitted to transmit under a pseudonym, suppressing
transmission when it would shrink the anonymity set below a per-pseudonym policy. The oracle
is architecturally denied private information so that its decisions cannot leak.

Applied to KARST, minimally:

- A client tracks its own participation continuity and exposes it. An identity used across a
  join boundary carries a measured, not asserted, anonymity-set estimate.
- The client refuses to bind a long-lived L1 identity to traffic emitted before a configurable
  continuous-participation threshold has elapsed. Ephemeral identities are unaffected.
- On resume after an interruption longer than the tolerance window, the client warns that
  identities carried across the gap have lost anonymity set, and offers rotation.

Costs: this is availability traded for anonymity, it needs no coordination and no rendezvous, and
it does not conceal anything. It makes the loss legible instead of silent, which is the same
move `docs/05-anonymity.md` §4 already makes for `Prompt`.

Berthold and Langos' scheme, sending pregenerated dummy messages during a user's offline periods,
is the direct ancestor of "join before you need it, never leave" and should be cited where that
option is recorded.

## 6. If ISP-unobservability is genuinely required

There is exactly one shape that works, and KARST cannot adopt it without giving something up:
the constant-rate emitter must sit upstream of the subscriber line. Herd is the published
instance. Herd clients emit at a constant rate to a superpeer or service provider inside a
trust zone; the links from those providers to the mixes carry padded traffic at a rate that is
uniform across the zone and changes only on the scale of hours, orchestrated by a zone directory
using aggregate utilisation, so that individual call activity is not revealed. Herd's other
insight is the one KARST cannot use: it "exploits the constant-rate, low-bandwidth nature of
VoIP traffic", so its client links look like what they are pretending to be. The subscriber link
is still constant-rate; it is just constant-rate in a context where that is unremarkable.

For KARST this means a community-relay deployment: one node serving many subscribers, with the
constant-rate obligation borne by the relay's uplink. It reintroduces a party that knows who its
users are, which is what L5 exists to avoid, and it is the only construction in the literature
that removes the subscriber-line signature. Record it as a deployment option with its cost
stated, not as an architectural change.

### Costs

**What the recommendation costs.**

- Retiring the L3 claim costs the whitepaper a property it currently advertises in §3. The
  wire-image claim is true of bytes and false of shape, and §6.13a already says so, so what is
  being paid is consistency, not a defence.
- Capping the anonymous default's object size pushes media and bulk fetch onto a labelled
  weaker path. That is a visible amputation of L7's headline use case, and it will read as a
  retreat. It is the honest consequence of the rate analysis in §2 of the mechanism.
- A global duty-cycle envelope multiplies wall-clock latency by `1/d`. At `d = 0.25`, seconds
  become tens of seconds and the `Deferred` class moves from "seconds to minutes" to "tens of
  seconds to tens of minutes". Interactive-adjacent workloads that were tolerable become
  intolerable, and `Prompt`, which is already documented as not resisting a global passive
  adversary, absorbs them.
- The envelope needs loose global time agreement. That is a new protocol constant and a new way
  to be wrong, even though it is far weaker than batch-mix synchronisation.
- Buddies-style suppression costs availability at exactly the moments a user most wants to
  publish, which is a hostile interaction design and has the same shape as the consent-fatigue
  problem in §6.8.

**What none of it solves.**

- **The subscriber is still identifiable.** Every measure above reduces amplitude, moves the
  classifier's decision boundary, or makes the loss legible. None makes a KARST subscriber
  indistinguishable from a non-subscriber to their own access provider. If the deployment
  population on one provider is small, the provider can produce the list.
- **The join is still observable.** Suppression does not hide arrival; it stops the arriving
  user from spending an identity that arrival has already devalued.
- **Departure is the same boundary reversed** and `karst-mix::intersection` still does not model
  it, per issue #46.
- **The matched-filter problem is unsolved.** A public envelope that everyone follows is a
  template, and templates are easier to detect than variance thresholds. There is no construction
  in the literature that gives per-user rate variability and resistance to statistical
  disclosure at the same time without coordination.
- **The device profile exemption (§6.11) gets worse, not better.** Under a duty-cycle envelope a
  constrained device could plausibly participate during on-periods only, which is the first
  argument for closing that hole. It is also a per-device deviation from the envelope, which is
  rule 1 violated. This is a genuine open question and this analysis does not resolve it.

### Rejected

**Issue #56 option 1, variable-rate cover with a shaped envelope (per-user).** Loses. A per-user
schedule is Das et al.'s unsynchronised user distribution. Every off-period is a round in which
the target is absent and other users are present, which is the absent-population baseline that
statistical disclosure needs. `karst-mix::intersection` already measures the degenerate case:
one join boundary at round 2,000 gives +1.00 attribution by round 3,000. A schedule with
recurring off-periods supplies that boundary many times per day. The attack slows by roughly the
duty cycle and converges. The variant that survives is the *globally synchronised* envelope in
the mechanism section, which is a different proposal.

**Issue #56 option 2, run over a bearer where constant rate is normal.** Partially survives, as
Herd. Rejected as an architectural answer because the only bearer where the aggregation happens
upstream of the subscriber line requires a party that knows its users, which is L5's problem
reintroduced. Retained as a deployment option.

**Issue #56 option 3, accept it and gate on adoption.** This is the recommendation, minus the
gate. A numeric adoption threshold cannot be honestly stated because the anonymity set is
per-provider and per-jurisdiction, not global, and the design has no way to measure it. Saying
"safe above N users" invites a user to assume N has been reached. Say what the exposure is and
let the user reason about their own provider.

**Issue #56 option 4, tunnel inside a cover application.** Loses, and the literature on this is
unusually decisive. Houmansadr, Brubaker and Shmatikov's *The Parrot Is Dead* established that
imitating a protocol fails because imitation is never complete. Wang et al. then measured it:
against real campus traffic, obfs3 and obfs4 are detected with a true-positive rate of 1.0 and a
false-positive rate of 0.002 using an entropy and length test on the first packet alone, and
meek, "broadly considered the most secure current proposal", falls to decision trees at 0.98
true positive and 0.0002 false positive. Their summary is the sentence to quote: "having 'no
fingerprint' is itself a fingerprint". This also disposes of issue #9's stated plan, which is
to be indistinguishable from uniform random: the GFW has blocked fully encrypted traffic in
real time since November 2021 using a popcount test that exempts payloads with fewer than 3.4 or
more than 4.6 bits set per byte, which is precisely a filter for "looks random".

**Aqua's k-sets.** The one published construction that gives a genuinely variable client-link
rate with traffic-analysis resistance. Clients announce intended flows to an edge mix; mixes
collect roughly `k + delta` announcements and instruct all members of the resulting k-set to
raise their client-link rate simultaneously by a common amount, and to lower it simultaneously
later, so "all rate changes coincide on at least k client links". Reported cost: k-anonymity
among 100 BitTorrent users at a median 15% additional bandwidth and 20% longer download time.
Rejected for KARST because it needs mixes that collect announcements, form sets, run
time-synchronised epochs of about 30 seconds and orchestrate coordinated rate changes, which is
the rendezvous and coordination infrastructure the design refuses in `docs/05-anonymity.md`
§3.4. Note also that Aqua does not remove the floor: "In Aqua, all clients send and receive at a
low constant baseline rate."

**Piggybacking on the user's other traffic.** Loses immediately and it is worth writing down
why, because it is the intuitive proposal. If KARST emits only when the subscriber is already
emitting, the adversary can see the subscriber's ordinary traffic too, so the adversary is
handed the emission schedule for free. Differencing on "ordinary traffic active" is
differencing on the KARST schedule. This is worse than a random per-user schedule, because the
schedule is not merely observable, it is predictable from public behaviour.

**Adaptive padding and its descendants.** WTF-PAD fills statistically unlikely gaps rather than
padding to a constant, which is the "variable rate that still resists analysis" family. Sirinam
et al. broke it: their CNN attack reaches over 90% accuracy against WTF-PAD and over 98% on
undefended Tor. Rejected as a defence to build on.

**Decoy joins (issue #46 option 3).** Charges every participant permanent bandwidth to conceal
an event that happens once per user, and a decoy join is only convincing if it is followed by
sustained participation, at which point it is not a decoy, it is a second user. No literature
supports it.

**Cohort joins (issue #46 option 2).** Needs the same coordination Aqua needs and yields a
cohort of known size, which is an anonymity set the adversary can enumerate. Kept only as a
recorded option, not recommended.

**Membership-concealing overlay networks (Vasserman et al.).** Already correctly cited in
`docs/15-fundamental-limits.md` as a direction with no deployment. Nothing has changed. It
remains the right research pointer and the wrong engineering plan.

**Refraction networking (Conjure, TapDance, Cirripede).** Genuinely provides covert
registration, which is the closest thing in the literature to an unobservable join. Rejected
because it requires a cooperating ISP on the path to operate a station, which is an
infrastructure dependency of exactly the kind error 03 names, and because Conjure was among the
protocols disrupted by the GFW's fully-encrypted-traffic blocking from November 2021.

### Citations as given

All items below were retrieved and read in full text during this task unless the verification
note says otherwise. Where a number is quoted, the sentence containing it was located in the
source.

**Liang Wang, Kevin P. Dyer, Aditya Akella, Thomas Ristenpart, Thomas Shrimpton. *Seeing
through Network-Protocol Obfuscation.* ACM CCS 2015.**
<https://pages.cs.wisc.edu/~liangw/pub/ccsfp653-wangA.pdf>
Says: Figure 1 reports best attacks against deployed Tor pluggable transports: obfsproxy3 and
obfsproxy4 detected by an entropy-plus-length test at TPR 1.0, FPR 0.002; FTE at 1.0 and
0.00003; meek-amazon and meek-google by decision tree at 0.98 with FPR 0.0002 and 0.00006.
Table 5 gives the entropy distribution test at block size 8 with 0% false negatives on obfs3
and obfs4 and 0.02% false positives on SSL. Section 6 reports ML classifiers at 97.0% TPR /
0.19% FPR for obfsproxy4 on validation, with 0.98% total false positives across 14M real campus
flows, and the trees requiring 6 to 13 integer comparisons over the first 30 packets.
Portability is poor: cross-operating-system training and testing drops TPR to 52% and raises
FPR to 12%. Section 7 works the base rate: at 99% TPR, 1% FPR and one obfuscated flow per
billion, about 1 in 10,000,000 flagged flows is genuinely obfuscated. The paper's own summary of
the randomizer result is "having 'no fingerprint' is itself a fingerprint".
VERIFIED: full text extracted from the author-hosted PDF; all figures read from Figure 1,
Tables 5, 8, 9, 10, and Sections 6.1, 6.2 and 7.

**Mingshi Wu, Jackson Sippe, Danesh Sivakumar, Jack Burg, Peter Anderson, Xiaokang Wang, Kevin
Bock, Amir Houmansadr, Dave Levin, Eric Wustrow. *How the Great Firewall of China Detects and
Blocks Fully Encrypted Traffic.* USENIX Security 2023.**
<https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi>
Says: the GFW blocks fully encrypted traffic in real time on passive analysis alone, using
exemption rules. Ex1 exempts a connection if `popcount(pkt)/len(pkt) <= 3.4` or `>= 4.6` bits
set per byte. Further exemptions cover six or more leading printable ASCII bytes, more than half
printable bytes, more than twenty contiguous printable bytes, and explicit TLS and HTTP
fingerprints. The inferred algorithm would block roughly 0.6% of all connections on the
authors' campus network tap. Blocking began 2021-11-06. Shadowsocks, VMess, obfs4, Outline,
Lantern, Psiphon and Conjure were affected. UDP traffic was not affected; the system was
limited to TCP. Residual censorship holds a blocked tuple for 120 or 180 seconds.
VERIFIED: prepublication PDF downloaded and text extracted; Ex1 thresholds read from Section 4
and Algorithm 1, the 0.6% figure from the abstract and Section 1, the TCP-only finding from
Section 6.

**Roya Ensafi, David Fifield, Philipp Winter, Nick Feamster, Nicholas Weaver, Vern Paxson.
*Examining How the Great Firewall Discovers Hidden Circumvention Servers.* ACM IMC 2015.**
<https://conferences.sigcomm.org/imc/2015/papers/p445.pdf>
Says: 56% of probing connections arrived less than one second after the decoy connection, median
552 ms, so the censors had abandoned the 15-minute queue Wilde observed in 2011 and operated in
real time. Vanilla Tor connections from China succeeded 12% of the time on CERNET and 2% on
Unicom, while obfs2 and obfs3 succeeded 86% to 98% of the time.
VERIFIED: full text extracted; figures read from Table 3 and Section 5.2.

**Cecylia Bocovich, Arlo Breault, David Fifield, Serene, Xiaokang Wang. *Snowflake, a
censorship circumvention system using temporary WebRTC proxies.* USENIX Security 2024.**
<https://www.usenix.org/system/files/usenixsecurity24-bocovich.pdf>
Says, on what happened when states blocked, with dates:
Russia, 2021-12-01, a coordinated block of many Tor-related protocols including Snowflake, meek
and obfs4. Snowflake blocking keyed on a `supported_groups` extension the Pion DTLS
implementation emitted in Server Hello. Fixed and shipped in a few weeks; Russian users grew
from about 400 to over 4,000 during December 2021. A second rule in May 2022 targeted Client
Hello contents and was withdrawn by the censor before the mitigation shipped. A third rule, from
July 2022, keyed on Hello Verify Request; the mitigation did not ship until February 2023. Both
the first and third distinguishers had been published by MacMillan et al. in 2020.
Iran, from 2022-09-16 protests: share of Snowflake users rose from 1% on 2022-09-20 to 67% on
2022-09-24, then collapsed on 2022-10-04 when a Go `crypto/tls` fingerprint used by the client
was blocked. uTLS camouflage had been implemented but not enabled by default. The default
rendezvous front domain was SNI-blocked in some Iranian ISPs between 2023-01-16 and 2023-01-24.
China: no sustained interference. IP blocking of the few static proxies in May 2019, blocking of
the single default STUN server the same month, three days of domain-fronting disruption
2023-05-12 to 2023-05-14 that halved the user count and then ceased.
Turkmenistan: users dropped to zero at least twice. Broker front domain blocked by DNS injection
and TCP RST injection from 2021-10-24; an alternative front was not confirmed working until
August 2022. UDP port 3478 blocked for STUN, with the 3479 workaround functioning in AGTS and
not in Turkmentelecom.
Also: domain-fronting rendezvous was broken twice by CDN policy rather than by any censor, on
2023-09-20 and 2024-03-01, the latter causing an immediate 30% decline in users and bandwidth.
VERIFIED: full text downloaded and extracted; all dates and mechanisms read from Sections 4.1,
5.1, 5.2, 5.3 and 5.4.

**Diwen Xue, Reethika Ramesh, Arham Jain, Michalis Kallitsis, J. Alex Halderman, Jedidiah R.
Crandall, Roya Ensafi. *OpenVPN is Open to VPN Fingerprinting.* USENIX Security 2022.**
<https://www.usenix.org/system/files/sec22-xue-diwen.pdf>
Says: evaluated in partnership with a million-user ISP, the two-phase passive-then-active
framework identifies over 85% of OpenVPN flows with only negligible false positives, and
identified connections to 34 out of 41 "obfuscated" VPN configurations.
VERIFIED: PDF downloaded, abstract read directly. This is the strongest available evidence that
the access provider vantage point is not hypothetical.

**Michelina Hanlon, Gerry Wan, Anna Ascheman, Zakir Durumeric. *Detecting VPN Traffic through
Encapsulated TCP Behavior.* FOCI 2024.**
<https://www.petsymposium.org/foci/2024/foci-2024-0016.pdf>
Says: a protocol-agnostic heuristic that detects TCP tunnelled inside UDP VPNs achieves a false
positive rate of 0.11% on real-world traffic, an order of magnitude below ML-based methods.
VERIFIED: PDF downloaded, abstract and Section 3 read.

**Ania M. Piotrowska, Jamie Hayes, Tariq Elahi, Sebastian Meiser, George Danezis. *The Loopix
Anonymity System.* USENIX Security 2017.**
<https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-piotrowska.pdf>
Says: a sender checks its buffer at intervals drawn from an exponential distribution with
parameter `1/lambda_P`, sending a real message if one is queued and a drop cover message
otherwise, so "regardless of whether a user actually wants to send a message or not, there is
always a stream of messages being sent according to a Poisson process Pois(lambda_P)". Users
additionally emit independent Poisson loop and drop streams at rates `lambda_L` and `lambda_D`.
Providers respond to a pull request with a constant number of messages, padding with dummies.
VERIFIED: full text extracted; read from Section 3.2. This is the basis for the claim that
Loopix specifies Poisson emission, not metronomic emission.

**Debajyoti Das, Sebastian Meiser, Esfandiar Mohammadi, Aniket Kate. *Anonymity Trilemma:
Strong Anonymity, Low Bandwidth Overhead, Low Latency, Choose Two.* IEEE S&P 2018.**
<https://www.freehaven.net/anonbib/cache/trilemma-oakland2018.pdf>
Says: latency overhead `l` is the number of rounds a message may be delayed; bandwidth overhead
`b` is the number of noise messages per user per round. Lemma 1, the informal trilemma: no
protocol can achieve strong anonymity if `2*l*b < 1 - eps(eta)` where `eps(eta) = 1/eta^d`. The
paper analyses synchronised user distributions, where users globally synchronise their messages,
separately from unsynchronised ones, where each user decides locally with per-round probability
`p`; the non-compromising bounds are `delta >= 1 - f_b(l)` and `delta >= 1 - [1/2 + f_p(l)]`
respectively.
VERIFIED: full text extracted; definitions from Section II.A and Theorems 1 and 2 read directly.
The corollary about duty cycling is mine, not theirs; see `unverified`.

**Debajyoti Das, Sebastian Meiser, Esfandiar Mohammadi, Aniket Kate. *Comprehensive Anonymity
Trilemma: User Coordination is not enough.* PoPETs 2020(3), 356-383, DOI
10.2478/popets-2020-0056.**
<https://petsymposium.org/popets/2020/popets-2020-0056.php>
Says: extends the 2018 result to protocols where users proactively coordinate, shows such
protocols can achieve better anonymity, and then presents a stronger impossibility result
covering all ACNs the authors are aware of.
VERIFIED: authors, venue, year, pages and DOI confirmed from the PoPETs proceedings page. The
paper body was not read in full; the summary above is from the publisher's abstract.

**Stevens Le Blond, David Choffnes, Wenxuan Zhou, Peter Druschel, Hitesh Ballani, Paul Francis.
*Towards Efficient Traffic-analysis Resistant Anonymity Networks.* ACM SIGCOMM 2013.**
<https://people.mpi-sws.org/~druschel/publications/aqua-sigcomm13.pdf>
Says: at the edges, Aqua forms ksets of clients and requires that "any target rate adjustment on
a client link must coincide with an equivalent adjustment by a set of clients that form a
anonymity set called a kset". Mixes wait for about `k + delta` flow announcements or a timeout,
then instruct all kset members to raise their client link rate simultaneously by a common kset
rate, and all must lower it simultaneously later; clients whose flows end early continue to send
chaff. The implementation runs in time-synchronised epochs of about 30 seconds. "In Aqua, all
clients send and receive at a low constant baseline rate." Reported cost: k-anonymity within
k = 100 BitTorrent users at a median 15% additional bandwidth utilisation and 20% longer
download time.
VERIFIED: full text extracted; read from the abstract and Section 3.3.2.

**Stevens Le Blond, David Choffnes, William Caldwell, Peter Druschel, Nicholas Merritt. *Herd: A
Scalable, Traffic Analysis Resistant Anonymity Network for VoIP Systems.* ACM SIGCOMM 2015.**
<https://conferences.sigcomm.org/sigcomm/2015/pdf/papers/p639.pdf>
Says: Herd "exploits the constant-rate, low-bandwidth nature of VoIP traffic to resist traffic
analysis while achieving low delay". On client links Herd maintains constant chaffing at a rate
sufficient for a small number of calls, substituting payload for chaff when a call is made. On
provider-to-mix links all links in a zone carry the same rate at any time, changed only on the
scale of hours by a zone directory acting on aggregate utilisation, "but do not reveal individual
call activity". Also reports that a start-and-end-time attack alone would trace 98.3% of calls in
a real voice workload if made over Tor.
VERIFIED: full text extracted; read from Sections 1, 3.4, 3.4.1 and 3.4.2.

**Jelle van den Hooff, David Lazar, Matei Zaharia, Nickolai Zeldovich. *Vuvuzela: Scalable
Private Messaging Resistant to Traffic Analysis.* ACM SOSP 2015.**
<https://pdos.csail.mit.edu/papers/vuvuzela:sosp15.pdf>
Says: privacy covers "whether she's communicating at all (or just running an idle client)".
Vuvuzela operates in rounds during which each user can send and receive one message, and "the
degree of privacy depends on how many rounds Alice participated in". Typically configured for
epsilon = ln 2 and delta = 10^-4 over 200,000 rounds. Each client sends and downloads a 256-byte
message per round, rounds being tens of seconds.
VERIFIED: full text extracted; read from Sections 2.1, 3.2 and 5.
NOTE: author list taken from the paper's title page as hosted at MIT PDOS; the four names above
were read from the PDF.

**David Isaac Wolinsky, Ewa Syta, Bryan Ford. *Hang With Your Buddies to Resist Intersection
Attacks.* ACM CCS 2013.**
<https://dedis.cs.yale.edu/dissent/papers/buddies.pdf>
Says: Buddies is "the first systematic design for intersection attack resistance in practical
anonymity systems", grouping users into buddy sets and using a Policy Oracle, architecturally
denied private information, to filter the set of users permitted to transmit in each round.
Trace-based ideal-anonymity analysis on a 1207-user month-long IRC dataset: pseudonyms used for
up to about one hour reliably achieve anonymity sets of at least 250 members and sometimes up to
375, between 20% and 30% of the observed population, with achievable anonymity falling off
rapidly as pseudonym lifetime increases. Long-lived pseudonyms require tolerating offline
periods, whose main cost is increased communication latency up to that tolerance period.
VERIFIED: full text extracted; read from the abstract, Sections 3 and 5.2.

**Oliver Berthold, Heinrich Langos. *Dummy Traffic against Long Term Intersection Attacks.* PET
2002, LNCS 2482, 110-128.**
<https://www.freehaven.net/anonbib/cache/langos02.pdf>
Says: intersection attacks are possible when not all users are active all the time and some
messages are linkable; the proposal is to send pregenerated dummy messages to the communication
partner during the user's offline periods.
VERIFIED: title, authors, venue, volume and page range confirmed from SpringerLink and the
anonbib cache listing. The paper body was not read; the mechanism summary is from the
publisher's abstract and should be checked before it is used for anything load bearing.

**Payap Sirinam, Mohsen Imani, Marc Juarez, Matthew Wright. *Deep Fingerprinting: Undermining
Website Fingerprinting Defenses with Deep Learning.* ACM CCS 2018.**
<https://arxiv.org/abs/1801.02265>
Says: the CNN attack reaches over 98% accuracy on undefended Tor traffic and over 90% against
WTF-PAD, and is held to 49.7% against Walkie-Talkie.
VERIFIED: authors, title, venue and year confirmed from dblp and the arXiv record; the accuracy
figures are from the abstract as returned by search and by the arXiv listing. The full paper
was not read.

**Milad Nasr, Alireza Bahramali, Amir Houmansadr. *DeepCorr: Strong Flow Correlation Attacks on
Tor Using Deep Learning.* ACM CCS 2018.**
<https://people.cs.umass.edu/~amir/papers/CCS18-DeepCorr.pdf>
Says: collecting about 900 packets of a target Tor flow gives 96% flow correlation accuracy
against 4% for RAPTOR in the same setting.
VERIFIED: authors, title, venue and year confirmed from dblp; the figures are from the abstract
as returned by search. The full paper was not read.

**Eric Jollès, Simon Wicky, Ania M. Piotrowska, Harry Halpin, Carmela Troncoso. *Website
fingerprinting on Nym: Attacks and Defenses.* PoPETs 2026, issue 2.**
<https://petsymposium.org/popets/2026/popets-2026-0055.php>
Says: Nym's current cover traffic strategy is not effective against website fingerprinting
unless it imposes large overhead; a bursty-matching cover defence reaches F1 0.39 against 0.65
for comparable Tor defences; channelling web traffic through Nym's constant traffic capability
reaches F1 0.06 at a bandwidth cost; and mix delays make the attack more effective rather than
less, by making incoming and outgoing packets easier to separate.
VERIFIED: exact title, full author list, volume and issue confirmed from the PoPETs proceedings
page. The paper body was not read; the F1 figures are from the published abstract.
This matters because `docs/05-anonymity.md` §3.1 asserts that website fingerprinting fails under
L4. That is true only under literal saturating constant rate, and the only deployed Loopix
descendant does not achieve it in its default configuration.

**David Fifield, Chang Lan, Rod Hynes, Percy Wegmann, Vern Paxson. *Blocking-resistant
communication through domain fronting.* PoPETs 2015(2), 46-64.**
<https://petsymposium.org/popets/2015/popets-2015-0009.php>
Says: domain fronting uses different domain names at different layers of an HTTPS connection;
implemented as the Tor pluggable transport meek.
VERIFIED: authors, title, venue, year and page range confirmed from the PoPETs proceedings page
and freehaven's anonbib. The paper body was not read.
Related and separately relevant: Google disabled domain fronting on Google App Engine in April
2018 and Amazon followed at the end of that month. See `unverified` for the status of that.

**Sadia Nourin, Van Tran, Xi Jiang, Kevin Bock, Nick Feamster, Nguyen Phong Hoang, Dave Levin.
*Measuring and Evading Turkmenistan's Internet Censorship: A Case Study in Large-Scale
Measurements of a Low-Penetration Country.* ACM Web Conference (WWW) 2023.**
<https://www.cs.umd.edu/~dml/papers/tm_www23.pdf>
Says: applied to 15.5M domains, Turkmenistan censors more than 122K domains using different
blocklists per protocol, and 6K over-blocking rules incidentally filter more than 5.4M domains.
Turkmenistan's mechanisms include DNS response injection and TCP RST injection, and the firewall
is bidirectional, which is what let the Snowflake authors measure it from outside.
VERIFIED: authors, title and venue confirmed from the ACM DL entry and the author-hosted PDF
URL; the domain counts are from the abstract as returned by search. The full paper was not read.
The bidirectionality and injection mechanisms are independently confirmed in the Snowflake
paper Section 5.4, which cites this paper for them.

**Alice, Bob, Carol, Jan Beznazwy, Amir Houmansadr. *How China Detects and Blocks Shadowsocks.*
ACM IMC 2020.**
<https://gfw.report/publications/imc20/en/>
Says: the GFW uses the length and entropy of the first data packet to identify probable
Shadowsocks traffic, then sends seven different types of active probe in stages to confirm.
VERIFIED: authors, title, venue and year confirmed from the ACM DL entry and the project's own
publication page; the mechanism summary is from the published abstract. The full paper was not
read.

**Sergey Frolov, Jack Wampler, Sze Chuen Tan, J. Alex Halderman, Nikita Borisov, Eric Wustrow.
*Conjure: Summoning Proxies from Unused Address Space.* ACM CCS 2019.**
<https://jhalderm.com/pub/papers/conjure-ccs19.pdf>
Says: clients send a covert registration signal to a station at a cooperating ISP using
chosen-ciphertext steganography inherited from TapDance, and then use phantom hosts in unused
address space as proxies.
VERIFIED: authors, title, venue and year confirmed from the ACM DL entry and the author-hosted
PDF URL; the mechanism summary is from the abstract. The full paper was not read. Note that
Conjure appears in the USENIX Security 2023 GFW paper's list of protocols disrupted from
November 2021, which is verified.

**Amir Houmansadr, Chad Brubaker, Vitaly Shmatikov. *The Parrot Is Dead: Observing Unobservable
Network Communications.* IEEE S&P 2013.**
Cited for the general result that protocol imitation fails because imitation is incomplete.
NOT INDEPENDENTLY VERIFIED IN THIS TASK beyond its appearance as reference [16] in Wang et al.
2015, which attributes the semantics-based attack class to it and measures its false positive
rates. Treat the bibliographic details as confirmed by that citation and verify the venue before
publication.

**US Patent 10,938,682 B2, *System and method for detecting constant-datagram-rate network
traffic*, Research Electronics International LLC, inventors Bruce R. Barsumian, Thomas H. Jones,
Ross Alan Binkley, priority 30 December 2014.**
<https://patents.google.com/patent/US10938682B2/en>
Says: divide a period into equal slices, count datagrams per slice, take an FFT, and threshold
for peaks in the frequency domain; stated applications include VoIP detection for
counter-surveillance and distinguishing constant-rate video from VoIP.
VERIFIED: title, assignee, inventors, priority date and method read from the patent text.
This is a patent and not peer-reviewed literature. It is worth citing for exactly one reason:
constant-datagram-rate detection is a productised commercial capability with a 2014 priority
date, not a research idea.

### What the author could not verify

Listed completely, because this is the part of the exercise that matters.

**1. The "above 99% with a byte counter" figure in §6.13a and `docs/18-documented-attacks.md` §2
is a self-generated simulation artefact and should not be presented as a measurement.**
`crates/karst-mix/src/exposure.rs` computes it as follows: `bursty_profile` is a hand-written
xorshift generator that returns 0 for six of ten outcomes, a small value for three, and a value
between 200 and 1000 for one; `constant_rate_profile` returns the same value every interval; and
`classifier_accuracy` thresholds the coefficient of variation at 0.5. The constant profile has a
coefficient of variation of exactly 0 by construction and the bursty generator was written to
exceed 0.8. The test asserts the separation it was built to produce. It is a tautology, not a
result. No real residential traffic was involved, no real classifier was trained, and the
accuracy figure is a property of the generator's parameters. The claim's *direction* is
supported by the literature; the *number* is not, and it should be removed or restated as "this
harness demonstrates the separability in principle".

**2. "Every access provider already runs that measurement for billing" is not verified.**
Residential billing is typically monthly aggregate bytes, which is not the per-interval time
series the argument requires. What is standard is flow telemetry, NetFlow and IPFIX, deployed
for capacity planning and DDoS detection, at one to five minute granularity. I did not find a
citable measurement of how widely per-subscriber flow records are retained by consumer ISPs, or
for how long, and retention regimes vary by jurisdiction. The claim should be narrowed to
something like "the per-interval byte counts this requires are ordinary operational telemetry",
and even that needs a source before it ships. Xue et al. 2022 is the closest available evidence
that an ISP-scale vantage point supports this class of analysis, and it is about flow
fingerprinting rather than subscriber-level rate profiling.

**3. There is no published classifier for constant-rate anonymity traffic on a residential access
link.** I looked for it specifically and it does not exist. The adjacent literature is either
per-flow protocol fingerprinting (Wang 2015, Xue 2022, Hanlon 2024), website fingerprinting
inside a tunnel (Sirinam 2018, Jollès 2026), or flow correlation between two vantage points
(Nasr 2018). None of them is the experiment the design needs, which is: given per-subscriber
five-minute byte counts from a real residential population, how well does a threshold separate a
constant-rate emitter, and what is the false positive rate against the ordinary always-on
devices already present on those lines. **That experiment has not been run by anyone and running
it is the single highest-value piece of work available on this issue.** It would also settle
whether the low-rate configuration in the mechanism section actually hides under the noise floor
or not, which is currently an assumption.

**4. The residential idle floor is asserted and not measured.** The claim that a few tens of
kbit/s of constant traffic disappears under ordinary keepalives, telemetry, NTP, DNS and IoT
chatter is plausible and I found no measurement of its magnitude or its variance across
subscribers. Everything in the mechanism section that depends on a low rate being unremarkable
depends on this. Do not ship it as fact.

**5. The duty-cycle corollary to the trilemma is mine, not Das et al.'s.** Their paper defines
`l` and `b` and proves `2*l*b < 1 - eps(eta)` rules out strong anonymity. It does not analyse a
globally synchronised on/off envelope, does not state that duty cycling preserves or improves
the constraint, and does not discuss the wall-clock bandwidth bill at all. My argument is read
off the shape of the bound and it may be wrong in ways the full model would expose. The claim
that a globally synchronised envelope defeats statistical disclosure is likewise an argument
from the structure of the attack, not a cited result, and `karst-mix::intersection` has not been
run against it. Both should be simulated before either is written down as a property.

**6. The Poisson-versus-metronome coefficient of variation figures are my arithmetic.** The
`1/sqrt(n)` relation for Poisson counts is elementary, and the 0.006 figure at 100 packets per
second over five minutes follows from it, but no source measures the detectability difference
and I am fairly confident it is negligible. Stated in the mechanism section as negligible for
that reason.

**7. Domain fronting's death in April 2018 is reported by press only.** Google App Engine
stopped supporting it around 2018-04-13 and Amazon followed around 2018-04-30, according to
several contemporaneous reports. I found no measurement paper documenting it. The Snowflake
paper does document two later, independent CDN-driven breakages, 2023-09-20 and 2024-03-01, and
those are verified. If the whitepaper wants a citable instance of "the countermeasure died
without a censor doing anything", use the 2024-03-01 event from Bocovich et al., not the 2018
one.

**8. Iran's 2011 blocking of Tor by TLS handshake DPI and its SSH throttling, and Russia's TSPU
architecture, were not verified.** I had these in mind as supporting material and did not confirm
them against measurement papers within this task. Aryan, Aryan and Halderman (FOCI 2013) and
Ramesh et al. (IMC 2020) are the likely sources. Do not cite either without reading them.

**9. `The Parrot Is Dead` bibliographic details were not independently confirmed,** only inferred
from Wang et al.'s reference list. Verify venue and year before use.

**10. Berthold and Langos was not read.** Title, authors, venue, volume and pages are confirmed;
the mechanism description is from the publisher's abstract.

**11. I could not find any literature on making entry to an anonymity network unobservable, as
distinct from making traffic within it unlinkable.** Refraction networking's covert registration
is the nearest thing and it solves a different problem: it hides *which* proxy you are reaching
from a censor, not *that* you have joined from your own provider. Membership-concealing overlay
networks, already cited in `docs/15-fundamental-limits.md`, remains the correct pointer and
remains undeployed. Buddies is the only systematic treatment of the churn problem that the join
event is an instance of. If someone has published on unobservable entry specifically, I did not
find it, and I searched for it directly.

**12. I did not verify any figure about how many residential lines already carry a constant-rate
emitter.** IoT device classification literature exists and I chose not to cite it because I could
not confirm the accuracy figures against the source within this task. The question "what fraction
of home links already look constant-rate" is important to the adoption argument and is
unanswered here.

### Independent citation check

**Wrong:**

- CLAIM-LEVEL, §2 of the write-up: "Vuvuzela is the calibration point: 256 bytes per client per round, rounds of tens of seconds, which is single-digit bytes per second" — and the conclusion drawn from it, "A mixnet carrying only messaging, control and small fetches has an ISP problem measured in tens of kbit/s." The cited paper contradicts this on its own terms. Vuvuzela §1 states: "clients use an average of 12 KB/sec (adding up to 30 GB over a month of continuous use, which may be high for a mobile phone with metered data service)", plus a further "12 KB/sec per user" for distributing dialing information via the untrusted CDN. That is roughly 96-192 kbit/s per client, one to two orders of magnitude above the write-up's "single-digit bytes per second". The 256-byte-per-round figure covers only the conversation protocol; the dialing protocol dominates the byte counter, and the ISP meters the total. CORRECTION: Vuvuzela's per-client ISP footprint is ~12 KB/sec (~96 kbit/s) for conversation plus ~12 KB/sec for dialing dead drops, not single-digit bytes per second. The argument in §2 survives only if the paragraph is rewritten around Vuvuzela's actual reported 12 KB/s, which weakens (though does not destroy) the case that a messaging-only mixnet has a small ISP problem. This matters because §2 is the section the whole recommendation rests on.

- CLAIM-LEVEL, §3 of the write-up: "The trilemma constraint does not tighten. The per-round noise rate `b` during on-rounds is unchanged, and wall-clock latency rises to `l/d`, so the product `l*b` rises." Das et al. define `l` as a count of communication rounds, not wall-clock time (Lemma 2: "Messages are delivered within l steps"). If off-periods contain no rounds, `l` in rounds is unchanged and `l*b` does not rise; only wall-clock delay rises, which the trilemma does not measure. The write-up does self-flag this as "my corollary, not theirs", but as written the sentence asserts a consequence of the cited theorem that the cited theorem does not give. Suggest restating as: the trilemma is indifferent to duty cycling, since it constrains rounds and not wall-clock time — which is the point the section actually needs.

**Unconfirmed:**

- Berthold & Langos (PET 2002) paper body. The anonbib-cached PDF at freehaven.net uses a custom Type 3 font encoding and extracts as unreadable glyph soup under pypdf; no plaintext version was locatable. SpringerLink 403s behind an IdP redirect and the ACM DL page 403s. Bibliographic details (title, both authors, LNCS 2482, pp. 110-128, PET 2002 San Francisco, DOI 10.1007/3-540-36467-6_9) and the abstract-level mechanism claim ARE confirmed via search, dblp, Semantic Scholar and the ACM listing. The write-up's own caveat on this item is accurate and should be kept: do not make it load-bearing without reading it.

- The phrase "chosen-ciphertext steganography" attributed to Conjure. It does not appear in the Conjure CCS 2019 PDF. Conjure §2 says the covert registration signal is embedded in the encrypted HTTPS request body, citing TapDance [59]; "chosen-ciphertext steganography" is TapDance's own term (Wustrow et al.). Substantively correct, terminologically imported. Either cite TapDance directly for the term or drop it.

- "Google disabled domain fronting on Google App Engine in April 2018 and Amazon followed at the end of that month." Appended to the Fifield citation with no source and self-deferred to `unverified`. Not checked in this pass. If it stays in the document it needs its own citation — the Fifield PoPETs 2015 paper predates the events and cannot support them.

- "the only deployed Loopix descendant" (said of Nym, in the note on the Jollès et al. citation). Not verifiable as stated; no source supports an exclusivity claim. Soften to "the most prominent deployed Loopix descendant" or cite something.

**Claims with no citation:**

- §3 and §4 reason repeatedly about the statistical disclosure attack — "SDA differences rounds where the target is sending against rounds where it is not", "Statistical disclosure gets nothing new", "it costs nothing in statistical-disclosure resistance", "sender online unobservability, which is what Loopix proves and what defeats SDA" — and NO SDA source is cited anywhere in the document. Danezis (Statistical Disclosure Attacks, SEC 2003) or Danezis & Serjantov (Statistical Disclosure or Intersection Attacks on Anonymity Systems, IH 2004) is missing. This is the single largest citation gap: SDA is the mechanism the whole §3 argument turns on.

- §3, validation rule 1: "SDA converges at a rate proportional to `d`." A specific quantitative convergence claim about a named attack, with no citation and no derivation. Either derive it or drop the rate and keep the qualitative point.

- §1: "evidence accumulates linearly in that window while the population stays fixed" and "A signal that is present in every five-minute bin, every day, for months, is not subject to the base-rate fallacy in any useful way." The base-rate half is cited to Wang §7 and is correct; the linear-accumulation half is an uncited assertion about sequential detection. A sequential-hypothesis-testing reference (Wald's SPRT — which Wang et al. themselves use in Table 5) would carry it.

- §6: "it is the only construction in the literature that removes the subscriber-line signature." An exclusivity claim over the whole literature, uncited. Herd is cited as an instance; Aqua (also cited) and ISDN-MIXes (cited inside Herd §2) are adjacent constructions. Weaken or survey.

- §2: "A mixnet carrying media and bulk fetch has an ISP problem measured in Mbit/s." No source and no derivation, presented alongside the (incorrect) tens-of-kbit/s figure. See `wrong`.

- §4: the coefficient-of-variation argument is uncited but is straightforward Poisson arithmetic and I checked it — n = 300 s x 100 pkt/s = 30,000 and 1/sqrt(30000) = 0.0058, so "about 0.006" is right. The §2 table arithmetic also checks out: 100 pkt/s x 1024 B = 819.2 kbit/s with 4.096 kbit/s goodput at 200x, and 1 pkt/s x 1024 B = 8.192 kbit/s with 40.96 bit/s goodput. No action needed on either; noted so they are not re-derived.

- Internal-doc references (docs/05-anonymity.md §7 "roughly 200x bandwidth at a 0.5% duty cycle", §9 "one-tick skew puts 30.8% of batches under three members", karst-mix::exposure) were spot-checked against /Users/vdmkenny/karst/docs/05-anonymity.md and both figures are present at lines 346 and 316. Not literature citations, no action needed.

---

## mix-parameters
**Question.** Derive L4's delay and cover-rate parameters instead of defaulting them (karst issue #51): what mean per-hop delay, what loop and drop cover rates, how many layers, and what happens when the real user population is an order of magnitude smaller than assumed.
### Answer

Stop treating delay and cover rate as two independent knobs. Both adversaries L4 defends against are governed by the same product, r·d, where r is the constant emission rate per client and d is the mean per-hop delay. Two rules fix it. The passive rule is Little's law: r·k·d >= 1, meaning every client has at least one packet in flight at all times, with k the number of delayed hops. The active rule is the n-1 isolation probability, which is exactly the reciprocal of the mean pool occupancy: P(isolation) = (1 - e^-Omega)/Omega with Omega = N·r·d/W, for N clients and W mixes per layer. Set r from the bandwidth a phone can sustain forever, then solve for d. At r = 0.2 packets/s (one 1024-byte packet every 5 s, 1.64 kbit/s, 0.53 GB/month per direction), k = 4 delayed hops (3 mix layers plus the terminal provider), W = 4 mixes per layer and a 1% isolation target, the answer is d = 2.0 s mean per-hop, giving 8 s mean end-to-end latency, 4 s standard deviation and a 20 s 99th percentile. Mix loop rate lambda_M = 1.0/s per mix, client loop rate lambda_L = 1.33/min, drop cover is the residual of the constant rate. That assumes N = 1,000 simultaneously online clients.

Two corrections fall out, and both matter more than the numbers. First, the "KARST pays both costs where the theorem requires one" self-challenge in `docs/15-fundamental-limits.md` and `frontier.rs` is an artefact of the simulator, not a property of the design. `sim.rs` makes the tick both the emission period and the delay unit, so cover-on silently pins r = 1 packet per tick and r·k·d = 3 is always satisfied; the passive failure mode cannot be exhibited. Separate the two and constant-rate cover at minimal delay collapses: at an emission interval of 200 ticks and one tick of per-hop delay, with cover fully on, the adversary's gain is 24.9x and the anonymity set is 9.1 of 200. KARST is not overpaying. Second, the delay is required by the trilemma itself, not merely by the n-1 attack. Das et al. 2018 Theorem 4 and Das et al. 2020 Theorems 5 to 7 prove that against a passive adversary that also compromises nodes, strong anonymity is impossible for constant latency overhead regardless of how much bandwidth you spend. The current doc understates KARST's own position.
### Mechanism

## Notation

- `N` clients simultaneously online.
- `r` packets per second per client, constant rate, both directions. Emission interval `T = 1/r`.
- `d` mean per-hop delay, exponential, seconds.
- `k` delayed hops on a path. KARST uses 3 mix layers plus the terminal provider, so `k = 4`. `MAX_HOPS = 5` in `packet.rs` caps this.
- `W` mixes per layer.
- `Omega = N·r·d/W`, the mean number of packets resident in one mix. This is Loopix's `lambda/mu` (Lemma 1: pool occupancy is Poisson(lambda/mu)).

## Rule 1, the passive rule: r·k·d >= 1

End-to-end latency is Erlang(k, d): mean `k·d`, standard deviation `sqrt(k)·d`. A global passive observer seeing a packet leave at time `t` takes as candidates everyone who emitted in `[t - (k·d + z·sqrt(k)·d), t - k]`. With constant-rate emitters at interval `T` and uniformly distributed phases, the number of distinct candidates is `N · min(1, window/T)`.

By Little's law, packets in flight per client = `r · k · d`. Requiring at least one gives `r·k·d >= 1`, which is the same statement as "the mean end-to-end latency covers at least one emission interval".

Measured (extended sim, 200 clients, 3 delayed hops, uniform phases, 20,000 ticks). `hard.set` is the window adversary `karst-mix::sim` implements; `bayes.eff` is `1/P(truth)` for an adversary that weights every emission by the Erlang density instead of using a hard cutoff:

| T | d | k·d/T | hard.set | hard gain | bayes.eff | bayes gain |
|---|---|---|---|---|---|---|
| 200 | 2 | 0.03 | 18.9 | 11.29x | 10.3 | 19.33x |
| 200 | 8 | 0.12 | 78.2 | 2.57x | 41.6 | 4.81x |
| 200 | 32 | 0.48 | 199.9 | 1.00x | 159.6 | 1.25x |
| 200 | 64 | 0.96 | 200.0 | 1.00x | 196.0 | 1.02x |
| 50 | 8 | 0.48 | 199.9 | 1.00x | 156.0 | 1.28x |
| 50 | 16 | 0.96 | 200.0 | 1.00x | 197.6 | 1.01x |
| 10 | 2 | 0.60 | 200.0 | 1.00x | 174.9 | 1.14x |
| 10 | 4 | 1.20 | 200.0 | 1.00x | 198.6 | 1.01x |

The rule holds across three emission intervals. At `k·d = T` the likelihood-weighting adversary is held to 1.01x to 1.02x; at `k·d = T/2` it still has 25% to 28% advantage while the window adversary already reports 1.00x. **The window adversary in `sim.rs` overstates anonymity by roughly a factor of two in required delay.** `frontier.rs::strong()` (gain < 1.05) is measuring the weaker of the two.

This rule is independent of `N`. That is the good news: the passive guarantee degrades gracefully, the set shrinks with the population but the adversary's gain does not rise.

## Rule 2, the active rule: P(n-1 isolation) = (1 - e^-Omega)/Omega

Because exponential residuals are memoryless, when the target enters a mix holding `Omega` other packets, all `Omega + 1` are equally likely to leave last. The target walks out alone with probability `1/(Omega+1)`. Averaging over `Omega ~ Poisson(Omega_bar)` gives `(1 - e^-Omega_bar)/Omega_bar`, which is `1/Omega_bar` for any `Omega_bar` worth having.

Verified against `karst-mix::active::n_minus_one` at 20,000 trials per point. The harness warms in integer ticks, so its effective occupancy is `arrival · q/(1-q)` with `q = e^(-1/d)` rather than `arrival · d`:

| arrival | d | Omega_eff | predicted | measured | ratio |
|---|---|---|---|---|---|
| 1 | 8 | 7.5 | 0.1331 | 0.1323 | 0.99 |
| 1 | 32 | 31.5 | 0.0317 | 0.0316 | 0.99 |
| 10 | 1 | 5.8 | 0.1713 | 0.1709 | 1.00 |
| 10 | 8 | 75.1 | 0.0133 | 0.0131 | 0.98 |
| 10 | 32 | 315.0 | 0.0032 | 0.0032 | 1.01 |
| 100 | 4 | 352.1 | 0.0028 | 0.0025 | 0.88 |
| 100 | 8 | 751.0 | 0.0013 | 0.0014 | 1.01 |

Three orders of magnitude of occupancy, ratio 0.88 to 1.08. The law is exact and the constant is 1.

Inverting for a target isolation probability `eps`: `d >= W / (N · r · eps)`.

## Which rule binds

Passive needs `r·d >= 1/k`. Active needs `r·d >= W/(N·eps)`. The active rule dominates when `N < k·W/eps`. At `k = 4`, `W = 4`, `eps = 0.01` that threshold is `N = 1600`. Below 1,600 simultaneous clients the n-1 attack sets the delay; above it, the passive correlation attack does.

## The recommendation, derived

Step 1. Fix `r` from what every device can sustain forever, in both directions, including a phone on a metered plan. One 1024-byte packet every 5 seconds is 1.64 kbit/s and 0.53 GB per month per direction. `r = 0.2/s`.

Step 2. `k = 4`. Three mix layers plus the terminal provider, one hop of Sphinx header budget spare.

Step 3. Assume `N = 1000`, `W = 4`, `eps = 0.01`.
- Passive: `d >= 1/(r·k) = 1/(0.2·4) = 1.25 s`.
- Active: `d >= W/(N·r·eps) = 4/(1000·0.2·0.01) = 2.0 s`.
- Take the max: **`d = 2.0 s`**.

Step 4. Consequences, all computed rather than asserted.
- `Omega = 1000·0.2·2.0/4 = 100`. `P(n-1 isolation) = 1.0%`.
- End-to-end latency Erlang(4, 2 s): mean 8.0 s, sd 4.0 s, median 7.3 s, p90 13.4 s, p99 20.1 s, p99.9 26.1 s.
- Delay truncation at the existing `MixNode::MAX_DELAY_MS = 30_000` is 15 mean delays, cutting `e^-15 = 3·10^-7` of draws. No change needed.
- Bandwidth overhead against a user sending 100 real messages a day: 17,280 packets emitted for 100 carried, 173x. The "roughly 200x" in the whitepaper is `1/real_rate` and is a property of the user, not of the design.

Step 5. Mix loop rate `lambda_M`. Draining a Poisson mix to occupancy 1 takes `d·ln(Omega) = 2·ln(100) = 9.2 s`. `karst-mix::loops::samples_to_detect(0.05, 0.5, 1e-3)` returns 8: a 50% suppression against a 5% baseline at a 0.001 false alarm rate is called after 8 completed loops. So `lambda_M >= 8/9.2 = 0.87` loops/s. **Ship `lambda_M = 1.0/s` per mix**, which is 2% of that mix's 50 packets/s throughput.

Step 6. Client loop rate `lambda_L`. `samples_to_detect(0.05, q, 1e-3)` is 80 loops at q = 0.15, 20 at q = 0.30, 8 at q = 0.50. To call a 30% path suppression within a window `tau`, `lambda_L >= 20/tau`. **Ship `lambda_L = 1.33/min`** (15-minute detection of a 30% suppression), which is 11% of the emission budget. A 15% suppression then takes 60 minutes, and a suppression at or below the ambient loss rate is never called; `loops.rs` already returns `None` for that case and has a test asserting it.

Step 7. Drop cover `lambda_D` is the residual, `r - lambda_P - lambda_L`, not a free parameter. It is what keeps the emission constant when nothing is due, and separately it is the only thing that makes the *destination* distribution uniform: loops return to the sender, so without drop cover the set of providers receiving traffic is the real recipient distribution.

## What each cover component defends, separately

- Constant emission rate `r`: removes volume as a signal, and satisfies the trilemma's necessary condition trivially (`p = 1`). Defends against the passive observer's volume channel. Does nothing about timing.
- Client loops `lambda_L`: detect suppression on the client's own path, including the access link. Defend against the active adversary. Do not help the passive one beyond being cover.
- Mix loops `lambda_M`: detect the n-1 drain at the mix under attack. This is the only component that fires inside an n-1 attack, because a client sees only its own share of loops through that mix.
- Drop cover `lambda_D`: makes the recipient-side distribution uniform. Defends receiver unobservability, which loops cannot because loops come home.

## Layers and path length

`P(every hop compromised)` under uniform selection within each layer, with adversary share `f` of each layer:

| layers | f=0.05 | f=0.10 | f=0.20 | f=0.33 | f=0.50 |
|---|---|---|---|---|---|
| 2 | 2.5e-3 | 1.0e-2 | 4.0e-2 | 1.1e-1 | 2.5e-1 |
| 3 | 1.3e-4 | 1.0e-3 | 8.0e-3 | 3.6e-2 | 1.3e-1 |
| 4 | 6.3e-6 | 1.0e-4 | 1.6e-3 | 1.2e-2 | 6.3e-2 |
| 5 | 3.1e-7 | 1.0e-5 | 3.2e-4 | 3.9e-3 | 3.1e-2 |

3 mix layers holds the fully-compromised path below 1% for `f <= 0.20`. A fourth layer buys 5x for a 33% latency increase and would exhaust the Sphinx header. **3 mix layers plus the terminal provider is justified and should stay.** The supporting citation is Loopix's own conclusion, verified: "We consider a number of 3 or more layers to be a good choice."

## The scaling rule the code needs

Hold `Omega` fixed as the network moves:

```
r · d >= max( 1/k , W/(N·eps) )
W    <= N · r · d · eps
```

`W` is currently a deployment accident. It must be a function of `N`. Adding mixes to a layer divides the arrival rate per mix and therefore divides `Omega`, so **stratified width is an anonymity cost, not free scaling**. This follows directly from Loopix's own Lemma 1 and sits in tension with the abstract's claim that nodes can be added to scale throughput without sacrificing anonymity. The resolution is that `r` or `d` must rise with `W`.

## What the running code currently does

`karst-net::directory::Directory::new(mu_ms)` is instantiated with 10.0 to 50.0 ms across the demos and tests. At `d = 0.02 s`, `N = 1000`, `r = 0.2`, `W = 4`, the pool occupancy is 1.0 and the n-1 isolation probability is 63%. The deployed delay parameter is two orders of magnitude below the derived value. `sim.rs`'s `mean_delay = 8.0` is not wrong so much as dimensionless: it is 8 emission intervals, which satisfies the passive rule with 24x margin and says nothing at all about the active one, because the tick has no duration.

## An independent cross-check

The Katzenpost administration documentation gives example values `Mu = 0.005` (mean per-hop delay 200 ms), `LambdaP = 0.001` (mean 1 s), `LambdaL = LambdaD = LambdaM = 0.0005` (mean 2 s each). Total client emission is `1 + 0.5 + 0.5 = 2` packets/s at `d = 0.2 s`, so `r·d = 0.4`. The derivation above lands on `r·d = 0.2 · 2.0 = 0.4`. The same product, reached from opposite ends of the latency/bandwidth split. Katzenpost spends bandwidth to buy latency; the recommendation here spends latency to buy bandwidth. The security quantity is identical.
### Costs

**Latency.** 8 s mean, 20 s at the 99th percentile, for every `Deferred` message. That is the cost of `d = 2.0 s` at 4 hops. It is not negotiable downward without raising `r`, and the exchange rate is exactly linear: halving the latency doubles the bandwidth.

**Bandwidth.** 1.64 kbit/s per direction continuously, forever, on every device, 0.53 GB per month each way. Against a user sending 100 real messages a day that is 173x overhead. A device that cannot sustain this is not anonymous, which is the `device` profile hole the whitepaper already admits.

**11% of the emission budget goes to client loops.** That is the price of calling a 30% suppression within 15 minutes. Detection is not free cover; those packets carry nothing.

**The isolation bound is 1%, not zero.** One n-1 attempt in a hundred isolates the target. The attack is detected with near certainty, so the adversary pays for each attempt, but a patient adversary that accepts being seen gets a target roughly every hundred tries.

**A suppression at or below the ambient loss rate is never detected.** `loops.rs` returns `None` and has a test that asserts it. This is a permanent limit of a statistical detector, not a tuning problem.

**The population assumption is the weak point, and it will not hold.** At `N = 100` instead of 1,000:
- `Omega` falls from 100 to 10 and the n-1 isolation probability rises from 1.0% to 10.0%.
- Restoring 1% requires `d = 20 s` (80 s mean end-to-end, 200 s at p99, unusable), or `r = 2.0/s` (16.4 kbit/s, 5.3 GB/month, unaffordable on mobile), or `W = 1` (one mix per layer, no throughput headroom, and every path in the network shares the same three nodes).
- The passive gain stays at 1.0x, but the anonymity set is 100 people. Set size is the guarantee, and a set of 100 is a set a subpoena can enumerate.
- The intersection attack gets dramatically easier and none of this measures it. `karst-mix::intersection` scores +1.00 attribution for a client that joins mid-run at any population; the number of rounds to full recall falls with `N`, and that has not been swept.

**The honest position at N = 100: KARST cannot hold a 1% isolation bound at usable latency.** The least bad option is to accept a higher `eps`, state it, and lean on loop detection making every attempt visible. A 10% isolation probability where every attempt is detected within 8 loops is a different security story from a 10% probability of silent success, but it is a weaker story than the one the docs currently tell.

**Two figures in the repository are wrong and this work found them.**
1. The Poisson mix isolation rate is reported as 0.7% in `WHITEPAPER.md` (line 415, 437), `docs/05-anonymity.md` (lines 290, 302) and `docs/15-fundamental-limits.md` (line 53). That is a 300-trial artefact. At 300,000 trials the value is **1.344%**, and the analytic prediction `(1 - e^-75.1)/75.1` is 1.331%. Across seeds 1 to 12 at the shipped 300 trials the figure ranges 0.33% to 3.00%. The batch-mix 51.7% is stable (51.713% at 300,000 trials) and stands. The correct contrast is 51.7% against 1.3%, a factor of 38, not 74. `ActiveConfig::default().trials = 300` should be raised.
2. `frontier.rs::the_shipping_configuration_pays_both_costs` and `bandwidth_alone_buys_anonymity_immediately` assert a result that only holds because `sim.rs` pins the emission interval to one tick. Both should be reframed once `emit_interval` exists.

**What this does not solve.** Nothing here addresses the join boundary, the ISP-visible constant-rate signature (`exposure.rs`), long-run intersection at realistic populations, or a Bayesian adversary that also compromises mixes. The Bayesian passive adversary is implemented here only against uncompromised mixes.
### Rejected

**Keeping delay and cover rate as independent knobs.** They are not independent. Both the passive rule (`r·k·d >= 1`) and the active rule (`N·r·d/W >= 1/eps`) are functions of the product `r·d`. Sweeping one against a fixed value of the other, which is what issue #51 proposes, measures a slice through a surface and cannot find the frontier. The correct object is a budget on `r·d` plus a split rule.

**Adopting Loopix's published rule `lambda/mu >= 2` directly.** Verified quote: "We consider values lambda/mu >= 2 to be a good choice in terms of anonymity." `lambda/mu` is exactly `Omega`, so this says a pool of 2 packets suffices. Under the isolation law that is `P(n-1) = 43%`. The rule is calibrated against a two-challenge-sender likelihood-difference metric under a *passive* adversary (their Figure 5, `lambda = 2`, 3 layers of 3, no corruption), not against n-1 isolation. It is 50x too weak for the property KARST claims. Cite Loopix for the mechanism and the topology, not for this constant.

**Setting the delay from the trilemma.** With constant-rate emission `p = 1`, Das et al. 2018 Theorem 7's necessary condition `2·l·p > 1 - eps(eta)` is satisfied at `l = 1`, and Theorem 6's bound `delta >= 1/2 - f_p(l)` is identically zero because `f_p(l) = min(1/2, 1 - 0^l) = 1/2`. Against a *non-compromising* global passive adversary the trilemma places no lower bound on KARST's delay at all. It is a statement about the bandwidth, exactly as `docs/15` says. The delay must come from elsewhere, and it does: from the compromise cases of the same theorems, and from the n-1 law.

**Applying the synchronised bound (`U_B`).** Issue #51 is right that the unsynchronised distribution applies, but for a more specific reason than "KARST has no synchronisation". `U_B` is defined as "over the course of N rounds, exactly one user per round sends a message, following a random permutation". That is a deliberately protocol-friendly artificial distribution the authors introduce to get an upper bound on what any protocol could do, not a description of a system with a clock. KARST is `U_P` with `p = 1`. The two necessary conditions have the same algebraic form (`2·l·beta` versus `2·l·p`, and the 2020 paper unifies them as `l_hat·(p' + beta) < 1 - eps`), so the unsynchronised bound is not "the harder one" in the sense of a tighter inequality. It is harder in the sense of sufficiency: the paper's own worked case `p = 1/(2·eta), l = eta` gives `delta >= 0.05` under `U_P` where `U_B` admits strong anonymity, and the authors say so explicitly. The whitepaper should state that distinction rather than the current qualitative one.

**Raising `W` to scale throughput.** `Omega = N·r·d/W`. Every mix added to a layer divides the pool. Scaling width without scaling `r·d` scales the isolation probability linearly.

**Using the window adversary as the acceptance criterion.** `sim.rs` gives the adversary a hard interval `[mean - k, mean + 4·sd]` and has it guess uniformly inside. A real adversary weights by the Erlang density. The measured gap is a factor of two in required delay and it is largest exactly where the design is marginal. The module comment in `sim.rs` already warns against loose bounds for this reason; the bound is tight but the *decision rule* is not.

**Four mix layers.** 3 layers hold full-path compromise below 1% at `f = 0.20`. A fourth costs 33% more latency, buys 5x, and leaves no Sphinx header budget (`MAX_HOPS = 5`). Justified only if the believed adversary share of each layer exceeds 0.2, which should be an explicit deployment statement rather than a default.

**Lowering `MAX_DELAY_MS` from 30,000.** At `d = 2.0 s` the cap is 15 mean delays and truncates 3·10^-7 of draws. Katzenpost's example `MuMaxDelay = 1000 ms` against a 200 ms mean is a 5x cap truncating 0.67%, which is a visibly truncated exponential. KARST's cap is the more conservative of the two and should stay.
### Citations as given

**VERIFIED. Ania M. Piotrowska, Jamie Hayes, Tariq Elahi, Sebastian Meiser, George Danezis. "The Loopix Anonymity System." 26th USENIX Security Symposium (USENIX Security 17), 2017.**
Verified by fetching https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-piotrowska.pdf and reading the extracted text directly. Affiliations on the paper: Piotrowska, Hayes, Meiser, Danezis at University College London; Elahi at KU Leuven.
What it actually says, quoted or closely paraphrased from the text I read:
- Table 1 notation: `lambda_L` user loop rate, `lambda_D` user drop cover rate, `lambda_P` user payload rate, `l` path length, `mu` mean delay at mix, `lambda_M` mix loop rate.
- Lemma 1: "The mean number of messages in the Poisson Mix with input Poisson process Pois(lambda) and exponential delay parameter mu at a steady state follows the Poisson distribution Pois(lambda/mu)."
- Delay guidance, Section 4.3.1: "For mu = 2.0 and lambda/mu = 1, Loopix still provides a weak form of anonymity" and "We consider values lambda/mu >= 2 to be a good choice in terms of anonymity."
- Layers, Section 4.3.1: "We consider a number of 3 or more layers to be a good choice." The evaluation topology is 3 layers of 3 nodes with `lambda = 2` (Figures 5, 6, 7).
- Evaluation rates, Section 5: simulations start at `lambda_L = lambda_D = 1` and `lambda_P = 3` messages per minute per client, `lambda_M` from 1. Figure 9 uses `lambda_P = lambda_L = lambda_D = 10` per minute and `lambda_M = 10` per minute, 50 to 500 users. Figure 10 uses 500 users at `lambda_P = lambda_L = lambda_D = 60` per minute and `lambda_M = 60` per minute, per-hop delay drawn from `Exp(2)`, end-to-end latency fitting a Gamma with mean 1.93 and standard deviation 0.87.
- Throughput: the body says a mix node's bandwidth "increases linearly until it reaches around 225 messages per second"; the abstract says "upwards of 300 messages per second". Both figures are in the paper and they do not agree. Do not cite either without saying which.
- Note the internal inconsistency in `mu`: Table 1 calls it "the mean delay at mix Mi", but Lemma 1, Figure 4's caption ("for different delays with mean 1/mu") and Figure 10 ("the mean delay 1/mu sec") all use it as the exponential *rate*. Mean delay is `1/mu`.

**VERIFIED. Debajyoti Das, Sebastian Meiser, Esfandiar Mohammadi, Aniket Kate. "Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead, Low Latency - Choose Two." 39th IEEE Symposium on Security and Privacy (IEEE S&P), 2018.**
Verified by fetching https://www.freehaven.net/anonbib/cache/trilemma-oakland2018.pdf, extracting the text with pypdf, and reading the theorem statements. Affiliations on the paper: Das and Kate at Purdue, Meiser at UCL, Mohammadi at ETH Zurich. Also on ePrint as 2017/954.
Theorem statements as printed:
- Theorem 1 (synchronised `U_B`, non-compromising): no protocol provides `delta`-sender anonymity for any `delta < 1 - f_beta(l)`, where `f_beta(x) = min(1, (x + beta·N·x)/(N-1))`.
- Theorem 2: for `U_B` with `l < N` and `beta·N >= 1`, no protocol achieves strong anonymity if `2·l·beta < 1 - eps(eta)`, `eps(eta) = 1/eta^d`.
- Theorem 4 (synchronised, `c >= l` compromised parties): no strong anonymity if `2·l·beta < 1 - eps(eta)` **or `l` in `O(1)`**. This is the one KARST needs and does not currently cite.
- Theorem 5 (synchronised, `c < l`, constant `c`): no strong anonymity if `2·(l-c)·beta < 1 - eps(eta)`.
- Theorem 6 (unsynchronised `U_P`, non-compromising): `delta < 1 - (1/2 + f_p(l))` with `f_p(x) = min(1/2, 1 - (1-p)^x)`.
- Theorem 7: for `U_P` and `p > 0`, no strong anonymity if `2·l·p < 1 - eps(eta)`. `p = p' + beta`, `p'` the genuine send rate, `beta` the noise rate.
- The paper's own placement of Loopix, Section X: "the trilemma does not exclude strong anonymity for Loopix", derived by assuming path length `sqrt(K)` with `K` in `theta(log eta)`, `beta + p' >= 1/sqrt(eta)` and per-hop expected delay `l' >= sqrt(eta)/sqrt(K)`, giving `(p'+beta)·l = 1`. Table I lists Loopix as latency `theta(sqrt(K)·l')`, bandwidth `theta(beta)`, strong anonymity "possible".
- The definitions of `U_B` and `U_P` are as I describe in the rejected-alternatives section, quoted from Sections V and VII.

**VERIFIED. Debajyoti Das, Sebastian Meiser, Esfandiar Mohammadi, Aniket Kate. "Comprehensive Anonymity Trilemma: User Coordination is not enough." Proceedings on Privacy Enhancing Technologies 2020 (3), pages 356-383. DOI 10.2478/popets-2020-0056.**
Verified by fetching https://petsymposium.org/popets/2020/popets-2020-0056.pdf and extracting the text. Volume, issue and page range read off the running head of page 1. Received 2019-11-30, accepted 2020-03-16.
What it says that KARST needs:
- Theorem 5 (`U_P`): "with `l_hat < N` and `B < (N-1) - eps(eta)`, no protocol can achieve strong anonymity if `p·l_hat < 1 - eps(eta)`. Moreover, strong anonymity can not be achieved if `l_hat` in `O(1)`."
- Theorem 6: with a constant compromised fraction `c/K` and `B < N-1`, no strong anonymity if `c > l_hat^2` and `l_hat^2` in `O(log eta)`. In their words, "the latency has to grow significantly with the security parameter".
- Theorem 7: given `B < (N-1) - eps(eta)`, no strong anonymity if `p · max{l_hat - c, l_hat/2} < 1 - eps(eta)`.
- Unified condition, Section 7.1: "we can represent them with a single unified impossibility condition `l_hat(p' + beta) < 1 - eps(eta)`".
- Table 1 rows, `0 < c <= l`: impossible if `(l - c)·p < 1 - eps(eta)`. Rows with `c > l`: impossible if `l` in `O(1)`.
- Explicitly relevant caveat, Section 7.1: "if the cardinality of such a partial set is known in advance our analysis can be easily adapted by reducing the set of all users to the partial set". This is how the bounds apply to a network with 100 users rather than `poly(eta)` users.

**VERIFIED. George Danezis. "The Traffic Analysis of Continuous-Time Mixes." 4th International Workshop on Privacy Enhancing Technologies (PET 2004), Toronto.**
Verified by fetching https://www.freehaven.net/anonbib/cache/danezis:pet2004.pdf and extracting the text. Section 2.3, "Optimal mixing strategies": "We prove that the optimal probability distribution f is the exponential probability distribution. This result was first proved by Shannon using techniques from the calculus of variations." The constraint is a fixed mean `a` on the half-line `[0, +inf)`, and the maximised quantity is the entropy of the delay distribution. Conclusion: "We proved that the optimal delaying strategy is the exponential mix, for which we calculate the anonymity and latency."
Attribution nuance worth fixing: `crates/karst-net/src/directory.rs` credits the calculus-of-variations proof to Danezis. Danezis credits it to Shannon and reproduces it. The paper's own contribution is applying the information-theoretic anonymity metric to continuous-time mixes and the streaming traffic-analysis attack, not the maximum-entropy result.

**VERIFIED (semantics), PARTIALLY VERIFIED (values). Katzenpost.**
Field semantics verified from source: https://raw.githubusercontent.com/katzenpost/katzenpost/main/core/pki/document.go, which documents `Mu` as "the inverse of the mean of the exponential distribution that the Sphinx packet per-hop mixing delay will be sampled from", `LambdaP` as the client inter-send interval for the FIFO egress queue or drop decoys, `LambdaL` as the client loop decoy interval, `LambdaM` as the mix loop decoy interval, `LambdaG` as the gateway decoy interval.
Example values verified from the Katzenpost administration documentation at https://katzenpost.network/docs/admin_guide/components.html: `Mu = 0.005`, `MuMaxDelay = 1000` ms, `LambdaP = 0.001`, `LambdaPMaxDelay = 1000` ms, `LambdaL = 0.0005`, `LambdaLMaxDelay = 1000` ms, `LambdaD = 0.0005`, `LambdaDMaxDelay = 3000` ms, `LambdaM = 0.0005`, `LambdaG = 0.0`. **These are documentation examples. I could not confirm they are what any production Katzenpost network runs.** Cite them as "the values Katzenpost's administration guide gives as examples", not as deployed parameters.

**Simulation results.** All measurements in this answer come from `/Users/vdmkenny/karst/crates/karst-mix` compiled unmodified as a path dependency of a throwaway crate at `/private/tmp/claude-501/-Users-vdmkenny-nephroflow-kubernetes-deployments/4cb75519-67b1-442d-8f1a-e29d81ee582e/scratchpad/l4sweep`. Nothing in the repository was modified. `active.rs`, `loops.rs` and `frontier.rs` were used as-is; the extended passive simulator with a configurable emission interval and a likelihood-weighting adversary is new code in that scratchpad crate (`src/main.rs`, `src/bin/two.rs`, `src/bin/three.rs`) and should be moved into `sim.rs` if the caller wants the results reproducible in CI.
### What the author could not verify

**Loopix page range 1199-1216.** Taken from a web search result summary, not read off the paper or the USENIX proceedings index. Confirm before printing it.

**Katzenpost's actual production parameters.** Only the documentation's example values are verified. I could not find a deployed network's PKI document or a dirauth config in the repository at the paths I tried (`docker/dirauth.template.toml`, `genconfig/main.go`, `authority/cmd/dirauth/main.go` all 404 or contain no values). The `r·d = 0.4` agreement between Katzenpost's examples and this derivation is a genuine and pleasing coincidence but it is an agreement with a documentation example, not with a running network.

**Danezis 2004's closed form for the anonymity of an exponential mix.** The PDF text extraction mangles the equation. Equation (13) reduces to something of the form `A = -log(mu/(e·lambda))`, which would make the effective anonymity set `e·lambda/mu`, agreeing with Loopix's `lambda/mu` occupancy to within a factor of `e`. **I could not read the equation cleanly enough to assert this.** Do not quote a formula from that paper without re-reading it in a proper viewer. The claim I do assert, that the exponential maximises entropy at fixed mean, is verified from clean prose.

**The isolation-probability constant.** I assert `P(n-1 isolation) = (1 - e^-Omega)/Omega` and verified it numerically against `n_minus_one` across `Omega` from 3.5 to 751 with ratios in 0.88 to 1.08. I did **not** find this result stated in Loopix or anywhere else in the literature. Loopix's Theorem 2 and its Section 4.2.1 formula `Pr(x = target) = s·mu/(s·lambda_M + lambda_R)` are a different quantity: the adversary's per-message linking probability under a *stealthy* blocking strategy constrained by the loop threshold `r`, not the probability that the target departs a drained mix with no honest company. **Treat the `1/Omega` law as this repository's own derivation, presented with its own evidence, not as a citation.** It is a one-line consequence of memorylessness and should be easy to defend, but I did not find prior art and did not search exhaustively for it.

**The `r·k·d >= 1` passive rule.** Same status. It is Little's law applied to a constant-rate emitter and the simulation confirms it across three emission intervals. I did not find it stated in this form in the literature. Do not attribute it to Loopix or to the trilemma papers.

**The "3T window" threshold for the Bayesian adversary.** The empirical crossover I measured is `k·d >= T` for gain <= 1.02 and `k·d = T/2` for gain around 1.25. That is four data points across three values of `T`. It is enough to justify the rule and not enough to claim the shape of the curve between them.

**`W = 4` mixes per layer.** This is what `SimConfig::karst` uses. I have not found any derivation for it in the repository or any argument for it in Loopix beyond the evaluation's "3 mix nodes per layer". The recommendation treats `W` as a constraint (`W <= N·r·d·eps`) rather than deriving a value, because the correct value depends on throughput per mix, which nobody has measured for `karst-node`.

**`N = 1000` as the design population.** Chosen because it is roughly the population at which the passive and active constraints cross at these `r`, `k`, `W` and `eps`, and because it is a plausible early deployment. It is not derived from anything. Every number downstream of it moves if it moves, and the costs section says by how much.

**`eps = 0.01` as the isolation target.** A choice, not a derivation. It is defensible only in combination with the loop detector firing inside every attempt. If the loop detector is disabled or poisoned, 1% silent success is far too weak.

**The Bayesian adversary I implemented assumes uncompromised mixes.** It weights emissions by the Erlang density of the full path. An adversary that also owns a mix on the path collapses the Erlang to a shorter one and does substantially better. That case is unmeasured, and it is precisely the case the 2018 Theorem 4 and 2020 Theorem 6 are about. This is the largest gap in the evidence.

**Intersection attack under small populations.** `karst-mix::intersection` exists and was not swept against `N`. Every statement I make about the `N = 100` case being worse for intersection is reasoning, not measurement.

**The claim that stratified width is an anonymity cost.** This follows from Loopix's Lemma 1 arithmetically. Loopix's abstract states that "many mix nodes can be securely added to a stratified topology to scale throughput without sacrificing anonymity". I read this as a claim about throughput under a fixed traffic rate per mix, not a contradiction, but I did not find a passage in the paper that resolves it explicitly. Present the tension as an observation, not as an error in Loopix.

**Whether `Prompt` class traffic breaks any of this.** Not analysed. `Prompt` packets forward immediately and therefore contribute to `Omega` for zero delay. Whether they help (more arrivals) or hurt (a distinguishable subpopulation) is unexamined and should be, because a mix carrying both classes has two populations in one pool.
### Independent citation check

**Wrong:**

- LOOPIX, figure reference 1 of 4. The write-up attributes the caption 'for different delays with mean 1/mu' to Figure 4. It is FIGURE 5. Figure 4 is the provider-inbox diagram ('Provider stores messages destined for assigned clients in a particular inbox...'). Figure 5 is 'Entropy versus the changing rate of the incoming traffic for different delays with mean 1/µ.' The substantive point (µ used as a rate, mean delay = 1/µ) is correct; only the figure number is wrong.

- LOOPIX, figure reference 2 of 4. The write-up says 'The evaluation topology is 3 layers of 3 nodes with lambda = 2 (Figures 5, 6, 7).' The correct set is FIGURES 6, 7, 8. Figure 5 is a single-mix-node entropy simulation with no topology and no lambda = 2. Figure 6: 'We use λ = 2, a topology of 3 layers with 3 nodes per layer and no corruption.' Figure 7: 'depending on the number of layers of mix nodes with 3 mix nodes per layer. We use λ = 2, µ = 1.' Figure 8: 'We use λ = 2, µ = 1 and a topology of 3 layers with 3 nodes per layer.' Additional precision point: Figure 7 SWEEPS the number of layers while holding 3 nodes per layer, so describing it as fixed at '3 layers' misstates that panel.

- LOOPIX, figure reference 3 of 4. The write-up says 'Figure 9 uses lambda_P = lambda_L = lambda_D = 10 per minute and lambda_M = 10 per minute, 50 to 500 users.' That is FIGURE 10: 'Latency overhead of the system where 50 to 500 users simultaneously send traffic at rates λP = λL = λD = 10 per minute and mix nodes generate loop cover traffic at rate λM = 10 per minute.' Figure 9 is 'Overall bandwidth and good throughput per second for a single mix node' — the bandwidth panel, which is where the λL = λD = 1, λP = 3, λM = 1 starting parameters belong. Worth noting for anyone citing Figure 10 as a latency source: that run deliberately sets a delay of 0.0 s on all hops to isolate system overhead, so it says nothing about mixing delay.

- LOOPIX, figure reference 4 of 4. The write-up says 'Figure 10 uses 500 users at lambda_P = lambda_L = lambda_D = 60 per minute and lambda_M = 60 per minute, per-hop delay drawn from Exp(2), end-to-end latency fitting a Gamma with mean 1.93 and standard deviation 0.87.' That is FIGURE 11: 'End-to-end latency histogram measured through timing mix node loops. We run 500 users actively communicating via Loopix at rates λP = λL = λD = 60 per minute and λM = 60 per minute. The delay for each hop is drawn from Exp(2)... fits the Gamma distribution with mean 1.93 and standard deviation 0.87.' Every parameter value is correct; only the figure number is wrong. Net: all four Loopix figure references are shifted one lower than the paper's actual numbering, which suggests they were assigned from a figure count rather than read off the captions.

- KATZENPOST, and this one affects a load-bearing conclusion. The write-up's cross-check computes 'Total client emission is 1 + 0.5 + 0.5 = 2 packets/s at d = 0.2 s, so r·d = 0.4' and concludes the derivation and Katzenpost land on 'the same product.' But LambdaD does not exist in the source the write-up cites for field semantics. Current core/pki/document.go declares Mu, LambdaP, LambdaL, LambdaM, LambdaG and LambdaR — there is no LambdaD field (I grepped: 13 'Lambda' occurrences, none of them LambdaD). LambdaP's own doc string already covers drop decoys: it is the interval 'between sending messages from it's FIFO egress queue OR drop decoy messages if the queue is empty.' So the 0.5/s LambdaD term is plausibly double-counting a rate LambdaP already includes. Drop it and client emission is 1.5/s, giving r·d = 0.3, not 0.4 — and the 'same product, reached from opposite ends' claim no longer holds exactly. This needs resolving before the cross-check is presented as independent confirmation.

- KATZENPOST, source-consistency defect. The write-up quotes MuMaxDelay = 1000, LambdaPMaxDelay = 1000, LambdaLMaxDelay = 1000 and LambdaDMaxDelay = 3000 alongside field semantics taken from current main. Those fields no longer exist in that file. document.go lines 48-52 state that schema v1 'drops the six *MaxDelay companion fields that previously accompanied Mu/LambdaP/LambdaL/LambdaM/LambdaG/LambdaR; sampling safety caps are derived programmatically inside the library now,' and the Mu comment adds 'there is no companion MuMaxDelay field.' The administration guide is out of sync with main. Citing both as though they describe the same version is inconsistent; either date the admin-guide values to the older schema or pin the document.go reference to a commit.

- TRILEMMA 2020, Theorem 6 precondition dropped. The write-up states Theorem 6 as 'with a constant compromised fraction c/K and B < N-1, no strong anonymity if c > l_hat^2 and l_hat^2 in O(log eta).' The paper's statement carries a third precondition the write-up omits: 'Given p < 1−ϵ(η), B < (N−1)−ϵ(η), c/K = const...'. The p < 1−ϵ(η) condition matters because a protocol at p = 1 (which is exactly what KARST's constant emission rate achieves, as the write-up itself notes under 'What each cover component defends') falls outside the theorem's scope. Restore the precondition before leaning on this theorem for a constant-rate design.

- TRILEMMA 2020, Table 1 summary is column-specific. The write-up says 'Rows with c > l: impossible if l in O(1).' That is right for the two without-user-coordination columns and for U_P with user coordination, but not for U_B with user coordination, where the l < c <= (B+1)l row reads l_hat(B+1) < N−eps(eta) rather than l_hat in O(1). Since the whole point of the 2020 paper is that user coordination changes the bound, the qualifier should be stated.

- KARST REPO, wrong function signature. The write-up twice calls 'karst-mix::loops::samples_to_detect(0.05, 0.5, 1e-3)' and 'samples_to_detect(0.05, q, 1e-3)' with three arguments. The function takes FOUR: crates/karst-mix/src/loops.rs:226 declares samples_to_detect(baseline: f64, attack_loss: f64, alpha: f64, max_samples: usize) -> Option<usize>. The omitted max_samples is not cosmetic — it is the cutoff that decides whether the function returns Some(n) or None, and the write-up's own Step 6 argument depends on the None case ('a suppression at or below the ambient loss rate is never called'). The returned values 8, 20 and 80 are correct, which I confirmed by reimplementing binomial_tail and samples_to_detect from source, but the call as written will not compile.

**Unconfirmed:**

- Every number in the two measured simulation tables. The Rule 1 table (T/d/hard.set/hard gain/bayes.eff/bayes gain, 8 rows) and the Rule 2 table (arrival/d/Omega_eff/predicted/measured/ratio, 7 rows) come from new code the write-up says lives at /private/tmp/claude-501/.../scratchpad/l4sweep (src/main.rs, src/bin/two.rs, src/bin/three.rs). That is a throwaway crate outside the repository, it is not in version control, and the likelihood-weighting adversary and configurable emission interval do not exist in karst-mix. I did not execute it. None of these figures are independently reproducible, and the write-up's own recommendation to move them into sim.rs should be treated as a precondition for citing them, not a follow-up.

- The headline correction figures '24.9x gain' and 'anonymity set 9.1 of 200' at an emission interval of 200 ticks with one tick of per-hop delay. Same provenance as above. This is the specific measurement used to overturn the 'KARST pays both costs' self-challenge in docs/15-fundamental-limits.md, so it carries more weight than any other number in the write-up and is the least verifiable. The supporting structural argument (sim.rs:177 pins one packet per tick when cover is on) I did confirm from source and it is sound; the magnitude is not confirmed.

- Whether the Katzenpost example values correspond to any deployed network. The write-up already flags this and its caveat is correct — I could not confirm it either. The values appear only in the administration guide's [Parameters] example block.

- The claim that a fourth mix layer 'would exhaust the Sphinx header.' MAX_HOPS = 5, and 4 mix layers plus the terminal provider is exactly 5 hops, so it fits precisely with zero spare rather than overflowing. Whether zero spare is unacceptable is a design judgement I cannot verify from the constant alone. The related k = 4 claim of 'one hop of Sphinx header budget spare' is arithmetically correct.

- The mean pool occupancy figure of 50 packets/s as 'that mix's throughput' used to compute the 2% loop overhead. It follows from N·r/W = 1000·0.2/4 and is arithmetically right, but no measurement or citation establishes that a KARST mix sustains 50 packets/s. Loopix's own measured figure is 225 or 300 messages/s depending on which part of that paper you read.

**Claims with no citation:**

- The n-1 attack isolation analysis carries no citation at all. 'Because exponential residuals are memoryless, when the target enters a mix holding Omega other packets, all Omega + 1 are equally likely to leave last' and the resulting P(isolation) = (1 - e^-Omega)/Omega are presented as original derivation. The n-1 / blending attack has canonical sources that should be cited: Serjantov, Dingledine and Syverson, 'From a Trickle to a Flood: Active Attacks on Several Mix Types' (IH 2002), and Kesdogan et al. on the stop-and-go mix. Loopix itself cites these at its refs [8,10,16] precisely when discussing n-1 resistance. This is the single largest uncited block in the write-up and it supplies Rule 2, which is the rule that actually binds at the recommended parameters.

- Little's law is invoked by name to justify Rule 1 ('By Little's law, packets in flight per client = r · k · d') with no reference. Standard queueing result, but it is named and load-bearing.

- The claim that end-to-end latency over k exponential hops is Erlang(k, d) with mean k·d and sd sqrt(k)·d is stated as fact in the Notation and Rule 1 sections without citation, even though the write-up separately verified that Loopix empirically confirms exactly this (its Gamma fit, mean 1.93, sd 0.87). The Loopix result should be cited at the point of use.

- The layers table P(every hop compromised) = f^L is presented with no citation and no statement of its assumption. It requires independent uniform selection within each layer and independence of compromise across layers. Loopix Figure 8 studies corrupted-mix impact empirically and is the natural citation; the independence assumption should be stated explicitly since it is what makes the 3-layer recommendation look strong.

- 'One 1024-byte packet every 5 seconds is 1.64 kbit/s and 0.53 GB per month per direction' and the framing 'what every device can sustain forever, including a phone on a metered plan.' The arithmetic is correct (I verified both figures), but the premise that 0.53 GB/month/direction is universally sustainable on a metered mobile plan is an empirical claim about real tariffs with nothing behind it. Step 1 anchors the entire derivation on this number, so it deserves a source.

- 'Bandwidth overhead against a user sending 100 real messages a day: 17,280 packets emitted for 100 carried, 173x. The roughly 200x in the whitepaper is 1/real_rate and is a property of the user.' The 100 messages/day figure is asserted with no source, and the whole 173x headline scales inversely with it.

- The assumption N = 1,000 simultaneously online clients, which sets the active bound and therefore d = 2.0 s directly (active bound 2.0 s vs passive 1.25 s — N is what makes active bind). No basis is given for 1,000, and the write-up's own crossover analysis shows the answer changes character above N = 1600.

- W = 4 mixes per layer and the 1% isolation target eps = 0.01. Both are inputs to the active bound and both appear without justification; the write-up itself observes that 'W is currently a deployment accident.'

- The 15-minute detection window tau in Step 6, which converts samples_to_detect's 20 loops into the shipped lambda_L = 1.33/min. The 20-loop figure I verified computationally; the choice of 15 minutes and of a 30% suppression as the target threat are unsourced design choices presented as derivation.

- 'Draining a Poisson mix to occupancy 1 takes d·ln(Omega)' in Step 5. Arithmetically 2·ln(100) = 9.21 s as claimed, but the drain model itself (deterministic exponential decay of occupancy to 1) is asserted without derivation or citation, and it sets lambda_M.

- The repo's existing line at crates/karst-net/src/directory.rs:20, 'Katzenpost's deployed directory carries the same parameter,' is an uncited claim about a deployed system that the write-up's own Katzenpost caveat contradicts — the values are administration-guide examples, and the MaxDelay truncation fields that comment alludes to have been removed from Katzenpost's current schema. Flagging it because the write-up touches this file for the Shannon fix and should correct both lines in one pass.

- 'Adding mixes to a layer divides the arrival rate per mix and therefore divides Omega, so stratified width is an anonymity cost, not free scaling.' The conclusion follows from Loopix's Lemma 1, which the write-up does cite nearby, but the specific assertion that this contradicts Loopix's abstract is an original argument. I confirmed the abstract does claim 'many mix nodes can be securely added to the stratified topology to scale throughput without sacrificing anonymity,' so the tension is real and correctly sourced — but the resolution offered ('r or d must rise with W') is the write-up's own and is not attributed to anyone.

---

## beacon
**Question.** Where does an unpredictable beacon for L6.1 placement come from, given that error 03 forbids global singletons? (KARST issue #79)
### Answer

This design cannot have a beacon, and the reason is a theorem rather than an engineering gap. Every deployed unbiasable beacon rests on an honest-majority assumption over a named set: drand's group is fixed by DKG and changes only by resharing ceremony, Tor's shared random value needs nine hardcoded directory authorities, RANDAO needs a stake-weighted validator set, and a VDF still needs an agreed input plus a group of unknown order that either has a trusted setup or an under-studied hardness assumption. Cleve (STOC 1986) proves no protocol agrees on a bit with negligible bias once half the parties are faulty, and Douceur (IPTPS 2002) proves that without a logically centralised authority an adversary can be half the parties whenever it wants to be. Open membership plus free identities therefore rules out distributed coin tossing, and every route back to it reintroduces exactly the privileged set error 03 exists to delete.

The route out is to stop asking for a shared beacon. Give each publisher a VRF keypair and let the placement value for epoch `e` be that publisher's own VRF output on `e`. It is unpredictable to everyone but the publisher, unique so the publisher cannot regrind it, verifiable by anyone holding the address, and there are as many of them as there are publishers, which is "zero or n, never one" satisfied literally. The cost is that the value has to reach the reader, so L6.1's claim that placement needs no announcement weakens to "placement needs one 144-byte unforgeable announcement per epoch, and degrades to today's grindable behaviour when it does not arrive". That is a real weakening and it should be written down rather than smoothed over. It also does not close the Sybil floor: it converts targeted capture into proportional capture, which is a large improvement and not a fix.
### Mechanism

## The beacon is per publisher, derived from the publisher's own key

Replace `Beacon` as a shared value with `Beacon` as a per-publisher value.

**Key material.** A publisher's identity record gains a VRF public key, `pk_vrf`, alongside the existing Ed25519 identity key. Use ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381). Use a **separate key**, not the identity key, to avoid cross-protocol reuse.

**Derivation.** For epoch `e`:

    alpha_e        = "karst.net.v1.beacon" || u64_le(e)
    (beta_e, pi_e)  = ECVRF_prove(sk_vrf, alpha_e)
    beacon.value    = blake3("karst.net.v1.beacon-out" || beta_e)   // 64 -> 32 bytes
    beacon.epoch    = e

`beta_e` is 64 bytes and `pi_e` is 80 bytes for that ciphersuite, so a beacon record is 144 bytes plus the epoch number.

**The input must be the epoch number and nothing else.** Not the previous output, not a digest of what the publisher published, not anything the publisher can choose or selectively withhold. Chaining on a publisher-influenced value reintroduces cryptographic-self-selection grinding (Ferreira, Hahn, Weinberg, Yu, EC 2022). RFC 9381 uniqueness gives exactly one valid `beta` per `(pk_vrf, alpha)`, and that is the property that forecloses it.

**Scoring** is unchanged in shape: `H("karst.net.v1.placement" || publisher || beacon.value || provider)`, top `k`. Keep `publisher` in the preimage for domain separation even though `beta_e` already binds it.

**Timing.** The publisher emits the record for epoch `e` at the start of epoch `e-1`. The leak window is therefore exactly one epoch, which makes the existing `min_tenure() == 2` correct rather than arbitrary: an identity ground after `beta_e` appears cannot be eligible until `e+1`, by which time `beta_{e+1}` is unknown.

**Verification, which is the whole safety argument.** A reader calls `ECVRF_verify(pk_vrf, alpha_e, pi_e)` with `validate_key = TRUE`. RFC 9381 states that the validate-key path is what supplies "unpredictability under malicious key generation", so it is mandatory, not optional. **An unverified beacon is never accepted.** A design that accepts one is strictly worse than having no beacon at all, because it hands placement control to whichever provider answers first.

**Distribution.** Because the record is unforgeable and 144 bytes, it does not need placement. Any provider, any L15 index, any L8 witness, any other reader may carry it. Withholding requires blocking every source; forging requires the publisher's key.

**Failure behaviour, stated exhaustively because this is where the attack goes.**

| Reader state | Behaviour |
|---|---|
| Verified record for the current epoch | Normal placement |
| Only an older verified record | Compute on the stale value, mark the feed degraded, widen the query beyond `k`. `feed_tag(publisher, epoch) = H(publisher \|\| epoch)` stays address-derived, so the reader always knows *what* to ask for even when it does not know *whom* |
| No record at all (cold reader, new publisher, epoch 0) | `Beacon::predictable(epoch)` from the address. Identical to today's behaviour, so this is never worse than the status quo |
| Proof fails to verify | Discard the record and treat that source as having supplied nothing |

The reader takes the **highest epoch it can verify** and treats the gap as a signal. Accepting any beacon a source offers lets an adversary pin a reader to a stale value.

**Provider set liveness.** Placement remains a function of `candidates: &[Candidate]`, and readers must agree on that set and on `joined_epoch`. That agreement requirement is unchanged by this proposal and is larger than the beacon problem. See costs.

**Rotation is no longer synchronised.** Under a shared beacon every publisher's placement moves at the same instant. Under this scheme publisher `P`'s placement moves at `P`'s epoch boundary, which smooths reassignment load and is neutral for security.

**Cheaper alternative, if ECVRF is judged too much new code.** A hash chain anchored in the identity record: pick `r_N`, define `r_{i-1} = H(r_i)`, publish `r_e` at epoch `e`, verify by hashing forward to a known value. It needs only blake3. It costs a fixed chain length chosen at anchor time, `O(gap)` hashes for a cold reader, and it lets the publisher grind the seed against near-term placements. ECVRF is roughly two scalar multiplications and a hash-to-curve and is worth the extra code.
### Costs

**It is an announcement, and L6.1 currently claims it does not need one.** That claim has to be amended, not defended. The announcement is unforgeable, 144 bytes, cacheable by anyone, and has a safe fallback, but withholding it is a real attack: it pins a reader to a stale, predictable value. The mitigation is that the reader can tell.

**A silent publisher becomes a grindable publisher.** `beta_e` depends only on `(sk_vrf, e)`, so the publisher can compute any epoch's value at any time, but somebody has to emit it. A publisher who stops emitting falls back to their last released value, which an adversary then has unlimited time to grind against. Archives, which is what content addressing is for, are the worst case. There is no free fix: 144 bytes per epoch, or eventual grindability.

**A publisher can steer their own placement by grinding their VRF key at creation.** The whole sequence `beta_0, beta_1, ...` is fixed once `sk_vrf` is fixed, so a publisher can search keys for a favourable early-epoch placement. The victim is not that publisher's readers, who get integrity from signatures regardless. The victim is L16: a large provider can pay publishers to steer placement toward it, which is accumulated position bought at a known price. The cost of the grind is one search per targeted epoch against a provider set that must be predicted in advance, which is expensive for far epochs and cheap for epochs 0 and 1.

**It does not close the Sybil floor and nothing does.** With free identities and `min_tenure = 2`, an adversary pre-registers `M` provider identities, holds them two epochs, and then gets `M` independent draws against every publisher's fresh beacon every epoch. Expected capture is proportional to `M / (M + n)`. Stated precisely: an unpredictable beacon converts targeted capture into proportional capture, and converts a hashing cost into a presence cost. Presence is only expensive if being a provider is expensive, which is L14 and L16 and is not built. The quorum read in `karst-net::watch` therefore stays load-bearing.

**`joined_epoch` is self-reported and this is worse than the beacon problem.** `min_tenure` is only as strong as the evidence for when a provider arrived, and `Candidate.joined_epoch` is a field the candidate fills in. Biryukov, Pustogarov and Weinmann broke exactly this in Tor with a technique they call shadowing: phase relays in and out of the consensus while they keep flags earned on real run time. Their fix was to base the HSDir flag on "the number of past consecutive consensus documents the relay has been listed in and not on the uptime of the relay". KARST has no consensus document, so it has nothing to count. This should be its own issue.

**The provider set itself is unagreed.** `placement_among` takes a candidate list, and a publisher and a reader who disagree about that list compute different placements. Computed placement already assumes a shared view of membership, which is a larger shared-state requirement than the beacon ever was. Naming the beacon as the open problem while this sits underneath it understates the gap.

**A new primitive.** ECVRF is a real addition against "small enough to reimplement is a security property", though a modest one.

**What it does not touch at all.** Availability. A publisher whose `k` providers all refuse is unreachable regardless of how they were chosen, and this changes only who gets chosen.
### Rejected

**drand and the League of Entropy.** Works, and is the right shape for its problem. A t-of-n threshold BLS group established by distributed key generation; membership changes only by a resharing ceremony. Every consumer consults the same group. That is error 03 stated exactly: one thing, globally, that everybody's placement depends on. Rejected on architecture, not on security. (Live check of the `quicknet` chain confirms period 3s, scheme `bls-unchained-g1-rfc9380`, genesis Aug 2023.)

**NIST's beacon.** One federal agency signing pulses, with its own warning that pulse values are public and permanently recorded. One line to reject.

**Tor's shared random value, proposal 250.** The closest analogue, and the one KARST specifically cannot copy. It requires nine hardcoded directory authorities. Prop 250's own security analysis states the bias bound: "an adversary who controls b of the authorities gets to choose among 2^b outcomes for the result of the protocol", and the leak window: "an attacker can predict the final shared random value about 12 hours before it's generated". Tor accepts this because it already ships a hardcoded root of trust; L8 exists to delete that. The honest-majority-over-nine bound is not even the real bound: Luo, Bhat, Nayak and Kate (IEEE S&P 2024) show an equivocation flaw letting a **single** compromised authority produce a valid consensus for targeted clients undetectably.

**RANDAO.** Needs a blockchain, which is a global consensus, which is a singleton, before any bias question arises. And it is biasable by construction: `k` consecutive end-of-epoch proposals give `2^k` choices of next seed. Alpturer and Weinberg (AFT 2024) compute optimal manipulation: 5% of stake proposes 5.048% of rounds, 10% gets 10.19%, 20% gets 20.68%. The self-enrichment is small. The `2^k` choice against a chosen victim is the part that matters here, and it is not small.

**Verifiable delay functions.** A VDF does let a beacon be *derived* rather than published, and it does kill last-revealer bias when the delay exceeds the manipulation window. It does not solve the singleton, because the VDF needs an input everyone agrees on, so the aggregation problem is untouched. Beyond that it carries: a `Setup` producing a group of unknown order, where RSA needs a party trusted not to reveal the factorisation and using public randomness instead makes `N` "so large as to be impractical", while class groups avoid the setup but their low-order assumption "has not been studied much" (Boneh, Bünz, Fisch survey, 2018); both are broken outright by a quantum adversary; and sequentiality is a claim about hardware margins. The concrete candidate Ethereum chose, MinRoot, did not survive review: the Ethereum-Foundation-commissioned analysis reports "a speedup factor of 20 (ignoring communication latency) using 2^29 processors and a memory of size 2^40" and concludes that the assumption of no faster parallel algorithm "is wrong". A design whose stated corollary is "small enough to reimplement is a security property" should not adopt a primitive whose safety margin is an open cryptanalytic question.

**Any commit-and-reveal or threshold protocol with open membership.** This is the decisive one and deserves to be stated as an impossibility rather than a difficulty. Cleve (STOC 1986): once half the processors are faulty, no protocol agrees on a bit with negligible bias. Douceur (IPTPS 2002): "Without a logically centralized authority, Sybil attacks are always possible except under extreme and unrealistic assumptions of resource parity and coordination among entities." Together: with free identities the adversary is a majority whenever it chooses to be, so the honest-majority premise every such protocol rests on cannot be established without the authority error 03 forbids. RandHound and RandHerd are explicit: `n = 3f + 1`, and "we assume that all nodes know the list of public keys X". Raikwar and Gligoroski's SoK names the same gap as an open problem: "permissionless systems have a highly dynamic set of nodes ... setting the assumption on a number of adversarial nodes is hard."

**Derive the beacon from the network's own history** (issue option 1). Requires everyone to agree what the history was, which is a consensus, which is a singleton, and it is grindable by whoever publishes most, as the issue already says. The only version with a priced analysis is Bitcoin: Bonneau, Clark and Goldfeder find "at least 68 bits of min-entropy are produced every 10 minutes" and a single-bit lottery "manipulation-resistant against an attacker with a stake of less than 50 bitcoins in the output, or about US$12,000". That is a genuine bound, denominated in trusting one chain.

**Plural beacon quorums, readers choose** (issue option 2). Does not typecheck. Witness sets at L8 and trust weights at L15 can belong to the reader because they are judgements about what that reader accepts. Placement must be *agreed* between a publisher and every reader who has never met them, so the choice is necessarily publisher-scoped. Once that is accepted, "several quorums, publisher picks one" has the same blast-radius shape as "the publisher's own key is the beacon", plus a set of operators to capture, plus a discovery problem for which quorum a given publisher uses. Strictly worse.

**Proof of work bound to identity.** Raises the price of a grind, does not change its shape. S/Kademlia is honest about this: it notes that Castro et al. reject crypto puzzles "because they cannot be used to entirely prevent an attack" and argues only that they are the best available absent an authority. Worse here specifically: proof of work has increasing returns to scale, so this is error 04 committed at the identity layer in order to patch error 03. Rejected on the design's own terms.

**Per-reader placement.** Destroys the property that makes computed placement work at all. A publisher and a reader who never spoke must derive the same set; if each reader picks its own, the publisher must deposit to every provider, which is broadcast, not replication.

**Accept capture and detect it** (issue option 3, and what the code does today). Stays necessary, is not sufficient. Necessary because nothing above closes the Sybil floor. Not sufficient because detection without an alternative tells a reader they are being censored and leaves them censored. It is a serious answer rather than a consolation: Sridhar et al. took this route on IPFS and report a 99.6% detection rate with 100% mitigation of detected attacks. It should be the second line, not the only line.

**Did Tor's fix work?** Yes for the attack it was aimed at, and the adversary moved. Biryukov et al. asked for two things in section VIII: an unpredictable value in the descriptor ID, and an HSDir flag based on consecutive consensus appearances rather than uptime. Tor shipped both (prop 250 and prop 224; v3 onion services first in 0.3.2.1-alpha, stable in 0.3.2.9, January 2018). The v3 ring separates the two sides: `hs_service_index = SHA3-256("store-at-idx" | blinded_public_key | replicanum | period_length | period_num)` and `hs_relay_index = SHA3-256("node-idx" | node_identity | shared_random_value | period_num | period_length)`. The shared random value appears **only on the relay side**, so a relay's ring position is unpredictable for every service at once. What came back is denial by another road: HSDirSniper (Zhang, Teng, Wang, Gao, Liu, Shi, WWW 2024) floods an HSDir's descriptor cache until it evicts everything, blocking an arbitrary service up to 90% of the time, requiring no ring position at all. Mitigated in Tor 0.4.8.14. The lesson is not that beacons fail. It is that closing the placement grind pushes the adversary into the storage layer, which in KARST is the floodability already documented in `feed.rs`.
### Citations as given

Every item below was checked this session for author list, title, venue and year, and for the specific claim it is cited for. Quotes are verbatim from the source named.

**VERIFIED — Richard Cleve. *Limits on the Security of Coin Flips when Half the Processors Are Faulty (Extended Abstract).* STOC 1986, 364-369.** Cited for: no protocol agrees on an unbiased bit once half the parties are faulty. Verified via dblp record `conf/stoc/Cleve86` and the ACM DL entry (DOI 10.1145/12130.12168), which state that with less than half faulty the honest parties agree with negligible bias, and that with half faulty the output "may be heavily biased".

**VERIFIED — John R. Douceur. *The Sybil Attack.* IPTPS 2002.** Cited for the quoted impossibility: "Without a logically centralized authority, Sybil attacks are always possible except under extreme and unrealistic assumptions of resource parity and coordination among entities." Quote confirmed across the Microsoft Research publication page and multiple independent secondary sources. Already cited in KARST.

**VERIFIED — Dan Boneh, Joseph Bonneau, Benedikt Bünz, Ben Fisch. *Verifiable Delay Functions.* CRYPTO 2018, 757-788. ePrint 2018/601.** Verified via dblp `conf/crypto/BonehBBF18` and the ACM DL entry. Cited for the VDF definition and its application to randomness beacons. I could not fetch the full text of this paper (403), so all VDF *cost* claims are cited to the companion survey instead, not to this paper.

**VERIFIED — Dan Boneh, Benedikt Bünz, Ben Fisch. *A Survey of Two Verifiable Delay Functions.* 22 August 2018.** Read in full. Cited verbatim for: the RSA group needs a party "trusted to not reveal the factorization of N"; using public randomness instead means "the resulting N must be so large as to be impractical"; class groups solve the trusted setup but their low order assumption "has not been studied much, and is a fascinating avenue for future work"; and both constructions "are insecure against an adversary who has access to a quantum computer".

**VERIFIED — Benjamin Wesolowski. *Efficient Verifiable Delay Functions.* EUROCRYPT 2019.** and **Krzysztof Pietrzak. *Simple Verifiable Delay Functions.* ITCS 2019, 60:1-60:15.** Verified via IACR CryptoDB and dblp `conf/innovations/Pietrzak19a`. Cited only as the two standard constructions.

**VERIFIED — Gaëtan Leurent, Bart Mennink, Krzysztof Pietrzak, Vincent Rijmen. *Analysis of MinRoot: Public report (requested by Ethereum Foundation).* 18 September 2023.** Read in full. Cited verbatim for: "achieves a speedup factor of 20 (ignoring communication latency) using 2^29 processors and a memory of size 2^40"; "Some of our results clearly break the security claims of MinRoot, but it is unclear whether they can be implemented in practice"; and "Several previous work [...] assume that there is no parallel algorithm with lower latency than the square and multiply algorithm with latency lg(p), but our results show that this assumption is wrong."

**VERIFIED — Alex Biryukov, Ben Fisch, Gottfried Herold, Dmitry Khovratovich, Gaëtan Leurent, María Naya-Plasencia, Benjamin Wesolowski. *Cryptanalysis of Algebraic Verifiable Delay Functions.* CRYPTO 2024. ePrint 2024/873.** Author list, title, venue and year verified from the ePrint record. Cited for the peer-reviewed form of the MinRoot result: "we show that the latency of exponentiation can be reduced using parallel computation, against the preliminary assumptions." Concrete figures come from the EF report above, not from this paper.

**VERIFIED — Tor proposal 250, *Random Number Generation During Tor Voting* (commit-and-reveal consensus).** Raw specification text read in full from `torproject/torspec`. Cited verbatim for: "an adversary who controls b of the authorities gets to choose among 2^b outcomes for the result of the protocol"; "The reveal phase lasts 12 hours, and most authorities will send their reveal value on the first round of the reveal phase. This means that an attacker can predict the final shared random value about 12 hours before it's generated."; and "This does not pose a problem for the HSDir hash ring, since we impose an higher uptime restriction on HSDir nodes". Phases are 12 hours each, 00:00-12:00 UTC commit and 12:00-00:00 UTC reveal. **This confirms the 12-hour figure KARST already cites.**

**VERIFIED — Tor rend-spec v3 hash ring formulas.** `hs_service_index(replicanum) = SHA3_256("store-at-idx" | blinded_public_key | INT_8(replicanum) | INT_8(period_length) | INT_8(period_num))` and `hs_relay_index(node) = SHA3_256("node-idx" | node_identity | shared_random_value | INT_8(period_num) | INT_8(period_length))`. Cited for the structural point that the shared random value enters only the relay side.

**VERIFIED — Alex Biryukov, Ivan Pustogarov, Ralf-Philipp Weinmann. *Trawling for Tor Hidden Services: Detection, Measurement, Deanonymization.* IEEE S&P 2013.** Read section VIII and the conclusion in full. **This confirms the claim already in KARST that these authors proposed the shared-random fix in the same paper**, verbatim: "For each hour, an unpredictable value is derived by the directory authorities from a shared secret. Three of these values are included in the consensus [...] This makes it impossible for an attacker to precompute identity keys for time periods further ahead than 3 hours in the future." Also cited for the tenure fix, verbatim: "directory authorities base the decision on whether a relay is assigned an HSDir flag on the number of past consecutive consensus documents the relay has been listed in and not on the uptime of the relay. This prevents the shadowing attack we have described." And for shadowing itself: a relay re-entering the consensus "will have all the flags corresponding to its real run time and not to the time for which it was in the consensus". Full-network harvest cost, verbatim from the conclusion: "approximately 2 days by spending less than USD 100 in Amazon EC2 resources". **Note: I did not find the "a few minutes on a modern multi-core computer" quote that KARST currently attributes to this paper in the sections I read; see unverified.**

**VERIFIED — Zhongtang Luo, Adithya Bhat, Kartik Nayak, Aniket Kate. *Attacking and Improving the Tor Directory Protocol.* IEEE S&P 2024, 3221-3237. DOI 10.1109/SP54263.2024.00083.** Verified via dblp; arXiv:2503.18345 is a later posting of the same work. Cited for an equivocation attack in which "only a single compromised authority" can create a valid consensus with malicious relays, and for the count of nine hardcoded directory authorities.

**VERIFIED — Qingfeng Zhang, Zhiyang Teng, Xuebin Wang, Yue Gao, Qingyun Liu, Jinqiao Shi. *HSDirSniper: A New Attack Exploiting Vulnerabilities in Tor's Hidden Service Directories.* The Web Conference (WWW) 2024. DOI 10.1145/3589334.3645591.** Author list verified via the Semantic Scholar API by DOI. Cited for flooding an HSDir descriptor cache to block arbitrary hidden services "up to 90% of the time", and for the fact that this needs no ring position.

**VERIFIED — Kaya Alpturer, S. Matthew Weinberg. *Optimal RANDAO Manipulation in Ethereum.* AFT 2024, 10:1-10:21. DOI 10.4230/LIPIcs.AFT.2024.10.** Read in full. Cited verbatim: "an optimal strategic participant with 5% of the stake can propose a 5.048% fraction of rounds, 10% of the stake can propose a 10.19% fraction of rounds, and 20% of the stake can propose a 20.68% fraction of rounds."

**VERIFIED — Ben Edgington, *Upgrading Ethereum*, section on randomness.** Cited verbatim for the `2^k` result: "Having k consecutive proposals at the end of an epoch gives the attacker 2^k choices for the ultimate value of the RANDAO that will be used to compute future validator duties."

**VERIFIED — Matheus V. X. Ferreira, Ye Lin Sally Hahn, S. Matthew Weinberg, Catherine Yu. *Optimal Strategic Mining Against Cryptographic Self-Selection in Proof-of-Stake.* EC 2022, 89-114.** Cited for the reason the beacon input must not be a chained or publisher-influenced value: a participant "can selectively broadcast credentials they produce in round r in order to influence the seed for round r+1".

**VERIFIED — Ewa Syta, Philipp Jovanovic, Eleftherios Kokoris Kogias, Nicolas Gailly, Linus Gasser, Ismail Khoffi, Michael J. Fischer, Bryan Ford. *Scalable Bias-Resistant Distributed Randomness.* IEEE S&P 2017.** Read in full. Cited for the fixed-membership requirement, verbatim: "RandHound assumes the same threat model as RandShare, i.e., that at most f out of at least 3f + 1 participants are dishonest"; "We assume that all nodes know the list of public keys X"; and "we assume that n = 3f + 1". Also for their own assessment of NIST, verbatim: "it requires trust in their centralized beacon".

**VERIFIED — Mayank Raikwar, Danilo Gligoroski. *SoK: Decentralized Randomness Beacon Protocols.* arXiv:2205.13333, 2022.** Read in full. Cited verbatim: "most of the DRB protocols perform well in permissioned systems. However, permissionless systems have a highly dynamic set of nodes that maintain the system state. [...] Moreover, setting the assumption on a number of adversarial nodes is hard."

**VERIFIED — Kevin Choi, Aathira Manoj, Joseph Bonneau. *SoK: Distributed Randomness Beacons.* IEEE S&P 2023. ePrint 2023/728.** Authors, venue and abstract verified. Cited only as the current systematisation of the field; no specific claim is drawn from it.

**VERIFIED — Joseph Bonneau, Jeremy Clark, Steven Goldfeder. *On Bitcoin as a public randomness source.* IACR ePrint 2015/1015.** Abstract read directly. Cited verbatim: "currently, at least 68 bits of min-entropy are produced every 10 minutes"; "one can derive over 32 near-uniform bits using standard extractor techniques"; and "a lottery producing a single unbiased bit is manipulation-resistant against an attacker with a stake of less than 50 bitcoins in the output, or about US$12,000 today". The USD figure is as of 2015 and must be stated as such.

**VERIFIED — Cécile Pierrot, Benjamin Wesolowski. *Malleability of the blockchain's entropy.* ArcticCrypt 2016; *Cryptography and Communications*, 2018.** Authors, title, venue and year verified. Cited only for the existence of the manipulation result. **I could not retrieve the full text, so no quantitative claim from it is used.**

**VERIFIED — drand and the League of Entropy.** Founded 2019 by Cloudflare, Protocol Labs, University of Chile, EPFL and Kudelski Security. Uses t-of-n threshold BLS with a distributed key generation, and membership changes by a resharing ceremony. Verified from the drand README and the League of Entropy Wikipedia article. Live confirmation of the `quicknet` chain from `api.drand.sh`: period 3 seconds, `schemeID` `bls-unchained-g1-rfc9380`, genesis 1692803367 (August 2023).

**VERIFIED — NIST Interoperable Randomness Beacon.** Cited for its own verbatim warning: "WARNING: DO NOT USE BEACON GENERATED VALUES AS SECRET CRYPTOGRAPHIC KEYS." Retrieved from the NIST CSRC beacon 2.0 page. Reference document is NISTIR 8213, *A Reference for Randomness Beacons: Format and Protocol Version 2* (draft, 2019).

**VERIFIED — RFC 9381, *Verifiable Random Functions (VRFs)*, IRTF CFRG.** Read directly. Cited for: the ECVRF-EDWARDS25519-SHA512-TAI ciphersuite; proof length 80 bytes (32 + 16 + 32) and output length 64 bytes; uniqueness ("for any fixed VRF public key and for any input alpha, it is infeasible to find proofs for more than one VRF output beta"); pseudorandomness ("beta is indistinguishable from a random value" to anyone without the secret key); the requirement to pass `validate_key = TRUE` to obtain "unpredictability under malicious key generation"; and the warning that "The VRF output beta is always distinguishable from random by the Prover".

**VERIFIED — Silvio Micali, Michael O. Rabin, Salil P. Vadhan. *Verifiable Random Functions.* FOCS 1999, 120-130.** Authors, title, venue, year and pages verified via ACM DL. Cited as the origin of the primitive.

**VERIFIED — Yossi Gilad, Rotem Hemo, Silvio Micali, Georgios Vlachos, Nickolai Zeldovich. *Algorand: Scaling Byzantine Agreements for Cryptocurrencies.* SOSP 2017, 51-68.** Verified via dblp `conf/sosp/GiladHMVZ17`. Cited as the deployed precedent for VRF-based self-selection. Note Algorand seeds its VRF from a chain value, which is precisely the coupling this recommendation avoids.

**VERIFIED — Ingmar Baumgart, Sebastian Mies. *S/Kademlia: A practicable approach towards secure key-based routing.* ICPADS 2007.** Read in full. Cited for the two puzzles ("A static puzzle that impedes that the nodeId can be chosen freely and a dynamic puzzle that ensures that it is complex to generate a huge amount of nodeIds") and for their own honesty about the limit, verbatim: "In [3] the use of crypto puzzles for nodeId generation is rejected because they cannot be used to entirely prevent an attack. But in our opinion they are the most effective approach [...] to make an attack as hard as possible in such networks." Reference [3] is Castro et al.

**VERIFIED — Srivatsan Sridhar, Onur Ascigil, Navin Keizer, François Genon, Sébastien Pierre, Yiannis Psaras, Etienne Rivière, Michał Król. *Content Censorship in the InterPlanetary File System.* NDSS 2024.** Cited for "$0.0005 per identity", "$4 using AWS", and for the detection route: "99.6% detection rate and mitigate 100% of the detected attacks". **This confirms the figures KARST already cites.**

**VERIFIED — Edward Eaton, Sajin Sasy, Ian Goldberg. *Improving the Privacy of Tor Onion Services.* ACNS 2022. ePrint 2022/407.** Cited only for the residual v3 leak: malicious HSDirs can perform "attacks that target the unlinkability of onion services, allowing some services to be tracked over time". Not cited for anything about placement grinding.

**VERIFIED — Davide Cerri, Alessandro Ghioni, Stefano Paraboschi, Simone Tiraboschi. *ID mapping attacks in P2P networks.* IEEE GLOBECOM 2005, vol. 3.** Venue, year and author list confirmed. Already cited in KARST; no new claim rests on it here.
### What the author could not verify

Listed in full, because the point of this exercise is that this list is as valuable as the recommendation.

1. **The "a few minutes on a modern multi-core computer" quote currently in `placement.rs`, `docs/25-replication.md` and WHITEPAPER §3 L6.1.** I read section VIII and the conclusion of Biryukov, Pustogarov and Weinmann in full and did not find that sentence. It may appear in section V, which I did not read line by line, or in a related paper by the same group. **Somebody should locate this sentence and its section number before the next revision ships.** Given that this project has twice shipped a misattributed quote, an unlocated quote in a load-bearing sentence is exactly the failure mode to check. The rest of that paragraph, including the six precomputed relays and the Silk Road demonstration, I also did not independently confirm in the text I read.

2. **drand's actual threshold and current node count.** The `/group` endpoint is not publicly readable and the drand README does not state the numbers. The League of Entropy Wikipedia article lists roughly 24 member organisations and gives no threshold. One secondary source says 16 nodes as of September 2022, which I did not corroborate. **Do not quote a threshold or a node count for drand.** The shape is verified (t-of-n threshold BLS over a DKG'd group, resharing to change membership) and the shape is all the argument needs.

3. **Whether Ethereum has abandoned, deferred, or retained its VDF plan.** I searched and found conflicting signals: an active MinRoot VDF item on a 2026 roadmap document, and no announcement of cancellation. **Do not claim Ethereum dropped VDFs.** The verified claim is narrower and sufficient: the concrete candidate they commissioned analysis on was shown to fall short of its sequentiality claim.

4. **Whether the v3 hash ring has ever been ground against in published work.** I found no paper demonstrating v3 descriptor-ID grinding after proposal 250 shipped. That is an absence of evidence in a literature I searched for well under an hour, not evidence of absence, and it should be written as "I found no published attack" rather than "no attack exists".

5. **The Pierrot and Wesolowski numbers.** Authors, title and venue are confirmed; the full text was behind a bot wall on every mirror I tried. **No quantitative claim from that paper is used anywhere above**, and none should be added without reading it.

6. **The exact grinding cost under the proposed scheme.** I assert that pre-registering `M` identities gives roughly `M/(M+n)` proportional capture. That is a back-of-envelope statement of the obvious, not a result I found in the literature, and no paper I read models the crossover between per-epoch grinding cost and the value of one epoch of capture. **The gap `docs/25-replication.md` already names is still open and this recommendation does not close it.**

7. **Whether reusing an Ed25519 identity key as an ECVRF key is unsafe in practice.** I recommend a separate key on general cross-protocol-reuse grounds. I did not find a specific published attack on that particular reuse, and RFC 9381 does not forbid it. The recommendation is conservative rather than evidenced.

8. **Whether the per-publisher VRF beacon has prior art.** I searched for VRF-derived placement in DHTs and content-addressed storage and found VRFs used for leader election and sortition (Algorand and successors) but nothing proposing a publisher-scoped VRF as the rotation value for replica placement. **That absence is more likely to mean I searched badly than that this is novel**, and the whitepaper should not claim novelty for it. The nearest relative is Tor's v3 blinded key, which is per-service and deterministic and therefore predictable, which is precisely why Tor still needs the shared random value on the relay side.

9. **`min_tenure() == 2` as a numeric choice.** I argue it is correct given a one-epoch release lead. I did not verify that two epochs is long enough against any measured provider-churn distribution, because no such distribution exists for this network. Tor's analogous parameter is grounded in measured relay behaviour; this one is grounded in arithmetic about the release schedule alone.

10. **The current status of the Tor equivocation result.** Luo et al. propose TorEq and DirCast and state they were communicating them to the Tor security team. I did not verify whether either has shipped.
### Independent citation check

**Wrong:**

- FALSE FLAG IN THE INPUT, not an error in KARST: the prior session marked the quote 'a few minutes on a modern multi-core computer' as unverified against Biryukov, Pustogarov, Weinmann (IEEE S&P 2013). It IS in that paper, verbatim, in Section V.A: 'This takes just a few minutes on a modern multi-core computer.' KARST's existing attribution at /Users/vdmkenny/karst/docs/25-replication.md:44 is correct. Do NOT remove or re-attribute it. The same passage also independently confirms the 'six precomputed relays' claim on that same line: 'the attacker can gain control over all the responsible HS directories for a particular service by injecting 6 Tor relays with precomputed public keys.'

- Ferreira, Hahn, Weinberg, Yu (EC 2022) — the text inside the quotation marks is a paraphrase, not the source's wording. The write-up has: a participant 'can selectively broadcast credentials they produce in round r in order to influence the seed for round r+1'. The abstract actually reads: 'a user who owns multiple accounts that each produce low-scoring credentials in round r can selectively choose which ones to broadcast in order to influence the seed for round r+1'. The substance is right; the quotation marks are not. Fix: either quote it exactly, or drop the quotation marks and cite it as a paraphrase. This is exactly the failure mode that shipped a misattribution before — a claim that is true but whose quoted wording was never in the source.

- Bonneau, Clark, Goldfeder (ePrint 2015/1015) — the quoted span includes a word the source does not have. The write-up quotes '...or about US$12,000 today'. The abstract says '...or about US$12,000' with no 'today'. Move 'today' outside the quotation marks, or better, replace it with 'as of 2015' outside the quote, which is what the write-up's own caveat already requires.

- Syta et al. (IEEE S&P 2017) — minor sourcing slip. The write-up presents 'we assume that n = 3f + 1' as part of the RandHound fixed-membership argument, but that sentence appears in the RandHerd description, not the RandHound section. The RandHound-specific statement is the one already quoted: 'at most f out of at least 3f + 1 participants are dishonest'. The conclusion is unaffected; just attribute the n = 3f + 1 line to RandHerd.

**Unconfirmed:**

- drand membership 'changes by a resharing ceremony' — I confirmed the League of Entropy founding (2019, five named organisations) and live-verified the quicknet chain parameters against api.drand.sh (period 3, genesis 1692803367, scheme bls-unchained-g1-rfc9380), but I did not this session open the drand README/docs to confirm the resharing mechanism specifically. The claim is consistent with how threshold-BLS DKG groups work and I have no reason to doubt it, but per the instruction not to mark something verified on recall, it is unconfirmed. Cheap to close by fetching the drand docs page on resharing.

- Boneh, Bonneau, Bünz, Fisch (CRYPTO 2018) full text — like the prior session, I confirmed metadata only (dblp, DOI, pages 757-788) and could not retrieve the body. This is not a problem as written, because the write-up deliberately routes all VDF cost claims to the companion survey, which I did read in full. Flagging only so the routing decision stays deliberate if the text is later edited.

- Pierrot & Wesolowski full text — metadata verified, full text not retrieved. Again not a problem as written, since the write-up draws no quantitative claim from it. Keep it that way.

**Claims with no citation:**

- 'ECVRF is roughly two scalar multiplications and a hash-to-curve' — no citation, and the number is too low on both sides of the protocol. Per RFC 9381 Section 5.1, ECVRF_prove computes encode_to_curve plus Gamma = x*H, k*B and k*H, i.e. three scalar multiplications. Per Section 5.3, ECVRF_verify computes U = s*B - c*Y and V = s*H - c*Gamma, i.e. four scalar multiplications, or two double-scalar multiplications if implemented with a multiscalar routine. Since this figure is the entire justification for choosing ECVRF over the blake3 hash chain, it should be stated correctly and cited to RFC 9381 Sections 5.1 and 5.3. Suggested wording: 'roughly three scalar multiplications to prove and two double-scalar multiplications to verify, plus a hash-to-curve'.

- 'Douceur (IPTPS 2002) proves that without a logically centralised authority an adversary can be half the parties whenever it wants to be' — the 'half the parties' threshold is the write-up's own inference, not Douceur's theorem. Douceur proves that Sybil attacks are always possible absent a central authority and that a faulty entity 'can control a substantial fraction of the system'; he states no half-the-parties bound. The composite argument with Cleve still works, but it should be phrased as the write-up's inference ('an adversary can therefore reach any fraction, including half') rather than as something Douceur proves. This is the one place in the piece where a cited source is made to say more than it says.

- 'blake3(...) // 64 -> 32 bytes' — the 32-byte default output length of BLAKE3 is asserted without reference. Trivial and correct, but since the 144-byte record arithmetic elsewhere is carefully sourced to RFC 9381, a one-line reference to the BLAKE3 specification would make the wire-format section uniformly checkable.

- 'It is unpredictable to everyone but the publisher, unique so the publisher cannot regrind it, verifiable by anyone holding the address' — the three properties are asserted in the summary paragraph before RFC 9381 is introduced. They are properly sourced later in the Verification and Derivation sections, so this is a forward-reference nit rather than a gap; worth a pointer on first use.

- 'A hash chain anchored in the identity record... lets the publisher grind the seed against near-term placements' and its O(gap) cold-reader cost — presented as established properties of the cheaper alternative with no citation. These are straightforward consequences of the construction rather than literature claims, so a citation may not be warranted, but the grinding weakness is the deciding argument against the alternative and currently rests on assertion alone.

---

## L5-admission
**Question.** Is there any sound admission bound for L5, or should the layer stop claiming one?
### Answer

There is no sound admission bound available to L5, and the layer should stop claiming one, including the aspirational form. `karst-member`'s module doc is already close to right, but the surrounding documents are not: `docs/13-observation-defence.md` §2 and §4.2 still say "L5 adopts SybilLimit's structure and owes a measurement", `docs/09-references.md` still says SybilLimit "is the right shape for L5", and `docs/19` lists #47 and #40 as work in dependency order. All three should go. The measurement #47 asks for cannot rescue the bound even if it comes back favourable, because five independent failures compose and only one of them is about mixing time.

What the layer should claim instead is precise and smaller: no roll, a local whitelist with an unverified precondition and an unbounded false-accept rate, and a per-introduction cost rather than a total. The design can honestly state the price of one attack edge and refuse to state how many an adversary holds, which is the same shape as the KAX17 residual `docs/13` §3 already writes down. Two of the three things the whitepaper's L5 "Mechanism" paragraph currently claims, bounded rate and attributable introduction, are not implemented anywhere in the crate; that gap is the one piece of buildable work this question turns up.
### Mechanism

FIVE INDEPENDENT REASONS THE BOUND IS UNAVAILABLE, in decreasing order of decisiveness. Each stands alone.

1. Douceur settles it before any graph is measured. *The Sybil Attack* (IPTPS 2002) splits identity validation into direct (an entity validates presented identities itself) and indirect (it accepts identities vouched for by identities it already accepted). Introduction is indirect validation. Douceur's stated results for the indirect case: "A sufficiently large set of faulty entities can counterfeit an unbounded number of identities", and "All entities in the system must perform their identity validations concurrently; otherwise, a faulty entity can counterfeit a constant number of multiple identities." KARST has no coordination point and validates nothing concurrently, both by design. The impossibility applies directly, not by analogy. This is why no measurement can produce a bound.

2. SybilLimit's bound is conditional on a quantity no party in KARST can count, and its failure at the threshold is a cliff. The guarantee holds for g = o(n / log n) attack edges. Alvisi et al. measured the far side on a preprocessed Facebook graph: "Once the bound is exceeded, however, the performance of SybilLimit falls rather quickly: the algorithm can no longer ensure that at most log(n) sybil nodes per attack edge are admitted." A verifier who cannot count g cannot tell which side of the cliff it is on. Counting g requires knowing the graph, and no party here knows the graph.

3. Both conditions that break the whole family are KARST's default case. Viswanath, Post, Gummadi and Mislove (SIGCOMM 2010) established that every scheme in the family is performing local community detection, then showed two breaks. Rising community structure (modularity) in the honest region drives detection accuracy down. Attack edges placed near the trusted node rather than uniformly at random drive accuracy well below 0.5; their own slide reads "Attack becomes much more effective / Sybils ranked higher than non-Sybils (accuracy << 0.5)". An introduction graph built by people introducing people they already trust is high-modularity by construction. An adversary choosing whom to court is doing targeted placement by definition. Yang et al. confirm targeted placement is the observed strategy, not the theoretical worst case: on Renren, "attackers use biased random sampling to identify and send friend requests to popular users, since these users are more likely to accept requests from strangers."

4. The measured shape of a real attack is not the shape the family assumes, and every protocol scores below chance against it. Yang, Wilson, Wang, Gao, Zhao and Dai studied 650,000 sybils on Renren with the operator's ground truth. Over 70% of sybils had no edge to any other sybil. Of the 30% that did, 69% (about 65,000) formed one connected component whose edge timestamps show it formed by accident; within that component 34.5% of sybils touched exactly one other sybil and 93.7% touched ten or fewer. There is no tight-knit sybil region to detect. Alvisi et al. simulated that attack on a real Facebook graph and scored each protocol by the probability that a random honest node outranks a random sybil, 0.5 being a coin flip: SybilLimit 0.45, SybilGuard 0.44, Mislove 0.34, Gatekeeper 0.49, ACL 0.37. All five below chance.

5. Fast mixing would not rescue the bound at KARST's scale even if the graph had it. SybilLimit's own experiment accepts around ten sybils per attack edge at n = 1,000,000, and the paper states the adversary needs "nearly 100,000 real-world social trust relations with honest users in order for the sybil nodes to out-number honest nodes". Calibrating the hidden constant against ln(10^6) = 13.8 gives roughly 0.72 ln n accepted per attack edge; at n = 1,000 that is about 5 per edge and a crossover near 200 attack edges, and the asymptotic side condition g = o(n / log n) lands in the same neighbourhood. (This extrapolation is mine, see the unverified list.) The bound becomes useful at a scale this network reaches years after the point where it needs a defence.

SIXTH, SEPARATE REASON: adopting the mechanism costs the one property L5 has. SybilLimit names a tail by the two endpoint public keys of a directed edge ("KA→KB"), and the verification protocol requires the verifier and suspect to compare tail sets of size r ≈ r0·sqrt(m), with the suspect knowing the endpoints' public keys and IPs. Every verification therefore hands the counterparty a keyed sample of the introduction graph. Each node additionally needs an out-of-band symmetric edge key with every neighbour and must be online to relay w-hop walks, w = 10 to 15 in the paper's own datasets. That reconstitutes exactly the enumerable roll L5 exists in order not to have, and it does so in a design where nodes are intermittently online by construction.

WHAT L5 SHOULD CLAIM, PRECISELY. Three claims, each scoped.

(a) There is no roll. Unchanged, already correct.

(b) A local whitelist with an unverified precondition and an unbounded false-accept rate. This is the only surviving positive goal in the literature and both critical papers converge on it. Alvisi et al.'s second stated contribution is "the more limited, but practically useful, goal of securely white-listing a local region of the graph"; Viswanath et al.'s SIGCOMM talk closes on "Could be still useful for white-listing small number of nodes". But be exact about what KARST does not get. Alvisi's Problem 1 is still conditional: a set S containing the honest user u, with mixing time τ, and at most o(|S|/τ) edges between S and the rest of the graph. KARST cannot check the third condition without enumerating the cut, which is the thing it refuses to do. So KARST has the shape of a local whitelist with no verified precondition. The claim is "each node maintains its own accept list from its own contacts, and the false-accept rate of that list is unknown and unbounded". Write "unbounded", not "small".

(c) A verified relationship and a per-edge cost, not a total. The verifiable OPRF proves a shared contact exists, unforgeable by a responder holding nothing, refused rather than believed under a second key. That is a fact about a relationship, and it is precisely what an admission bound is not. Its security content is a floor on effort per introduction: an adversary must obtain a genuine shared contact for each one. That is the same input SybilLimit calls an attack edge, and neither system bounds how many are purchased. Converting the floor into a real cost requires attribution: an introduction record naming the introducer, and a consequence for introducers whose introductions turn out badly. That is Lobsters' mechanism and it works there, at human scale, with a public tree and human adjudication, and it provides no bound either. `karst-member` implements none of it. The crate has the PSI and nothing else: no introduction record, no inviter field, no rate counter. WHITEPAPER.md §L5 "Mechanism" currently claims "bounded rate" and "each introduction is attributable, so a peer who leaks their known set can be identified and cut off". Both are unbuilt. Either build them or move the sentence into the honest-assessment paragraph.

SENTENCE TO USE IN PLACE OF A BOUND: "L5 makes no admission decision and provides no bound on the number of identities an adversary can obtain. It provides a locally verifiable fact about a relationship. The cost of acquiring that fact is the cost of acquiring a real contact. No party can say how many such contacts an adversary holds, and no mechanism here caps it."

ISSUE DISPOSITION. #40: close as will-not-do; delete the SybilLimit adoption plan from `docs/13` §2 and §4.2 and the "right shape for L5" line from `docs/09`. #47: close, or restate. The mixing-time measurement it asks for cannot rescue the bound because g is unmeasurable and edge placement is adversary-chosen, and a favourable result still leaves reasons 1, 2, 3, 4 and 6 standing. If it is kept at all it should read "characterise the introduction graph" and not "measure it before quoting the bound", because the bound is not going to be quoted. #8: widen the out-of-scope declaration. It currently declares bridge distribution out of scope; it should declare admission out of scope too, and should acknowledge that the bounded rate and attribution it names are unbuilt. #50: unaffected. Membership concealment is a different problem, hiding participation rather than bounding it, and #50 is already honestly scoped as inheriting a research problem.
### Costs

What this costs, plainly.

An observer defence. `docs/13` §2 identified admission as the lever that bites against an adversary who wants presence rather than standing, and concluded L16 cannot help because it operates on standing. That conclusion stands and the replacement lever does not exist. So KARST has no defence against a KAX17-shaped fleet, and the whitepaper should say so in those words rather than as a scheduled item. The line in `docs/18` that reads "L16 confirmed insufficient; L5 admission unbuilt" becomes "L16 confirmed insufficient; no admission defence exists or is planned".

Quantitative reasoning about fleet size. Refusing the bound means the design cannot state how many identities an adversary of a given size obtains. What it can state is the unit price of one attack edge, and that price is genuinely raised: from renting a server to acquiring a relationship with a person who will vouch. It is a large multiplier and it is not a wall, and the design already has the right sentence for this in `docs/13` §3.

The ability to reject anyone. With no admission decision, a node's only lever is who it introduces and who it accepts introductions from, which is a human judgement made without support. There is no mechanism to detect that an introducer has been compromised, no revocation of past introductions, no propagation of a bad judgement outward. Lobsters gets this from a public tree and paid moderator attention; KARST cannot have the tree and has no moderators.

The PSI membership oracle remains. An intersection with a singleton is a membership query, the module already records this as a test, and the two defences named are rate limiting and not running the protocol with strangers. Neither is implemented, and the first is the same unbuilt "bounded rate" the whitepaper claims as mechanism.

What this does not solve, and what nothing solves. An adversary willing to spend years acquiring real relationships gets identities in proportion to what it spends, and Douceur's indirect-validation result says no decentralised protocol changes that. The honest cost line is that KARST's join boundary is priced, not bounded, and the price is set by the adversary's patience rather than by the protocol.
### Rejected

SybilLimit (Yu, Gibbons, Kaminsky, Xiao, IEEE S&P 2008). Loses on all five grounds in the mechanism section. The specific killer is not the mixing time, it is that the guarantee is conditional on g = o(n/log n) with a cliff at the threshold and no party in KARST can count g. Adopting it would also require exchanging keyed edge samples on every verification, which undoes the no-roll property.

Gatekeeper (Tran, Li, Subramanian, Chow, INFOCOM 2011). Better asymptotics, O(1) sybils for O(1) attack edges, O(log k) per edge for O(k) edges. Loses harder, because its assumption is stronger: it holds "in a random expander social network". A graph built by deliberate introductions along existing trust is the opposite of a random expander. Alvisi et al. scored it 0.49, the worst of the five, essentially indistinguishable from a coin flip.

SybilGuard (Yu, Kaminsky, Gibbons, Flaxman, SIGCOMM 2006). Superseded by SybilLimit on the authors' own numbers, Theta(sqrt(n)) worse, roughly 2000 sybils per attack edge at a million nodes against SybilLimit's 10, and its guarantee voids entirely once g = Omega(sqrt(n)/log n). Scored 0.44.

Personalized-PageRank community detection (ACL, Andersen, Chung and Lang, as applied by Alvisi et al.). The strongest candidate on paper: the SoK introduces it as the first community detection algorithm with provable guarantees for sybil defence, and its running time depends on the size of the region found rather than the whole graph, which suits a local decision. It scored 0.37 against the Renren attack shape, worse than SybilLimit. The paper's own recommendation is to pair it with behavioural checks (friendship-acceptance rate below 50%, clustering coefficient below 1/100, which Yang et al. report catches over 98% of sybils at under 0.5% false positives), and those checks require a platform operator computing statistics over the whole graph. KARST has no such party.

Modern supervised graph learning (SybilRank, SybilBelief, SybilSCAR, Integro, and the GNN and contrastive-learning generation surveyed by Dehkordi and Zehmakan, 2025). This is where the field actually went and it works better than anything above. It loses because every method in the family requires a party holding the whole graph plus labelled ground truth and per-account features. That is error 03 with a model attached. The two deployments with published results, SybilRank and Integro, both at Tuenti, produce a ranking that prioritises human review rather than an admission decision, which is a different output from the one L5 needs.

Proof of work at the identity layer. Does not bound identities; it prices influence per unit of spend. Douceur's Lemma 1 gives the exact shape: an adversary with rho times a minimally capable entity's resources presents rho identities. Real deployments confirm the price is low relative to what an identity is worth: Sridhar et al. (NDSS 2024) censor an arbitrary IPFS CID with 45 sybil identities, generating the whole batch of EdDSA keys for $0.0005 and running the attack for about $4 on AWS. Tor's deployed PoW (proposal 327, EquiX, stable in tor 0.4.8.4, August 2023) is an anti-DoS rate limiter on onion service introduction requests, and the Tor Project describes it as a DoS deterrent, not a sybil defence.

Proof of stake. Does not bound identities either; it makes identity count irrelevant by weighting influence by stake. In Viswanath et al.'s (COMSNETS 2012) terminology this is sybil tolerance rather than sybil detection, and it only applies where influence is the quantity at risk. An observer needs presence, not influence. This is the identical reason L16 does not help, already established in `docs/13`.

Rate limiting and per-identity quotas. SybilLimit's own authors note it subsumes Ostra-style communication quotas once identities are bounded, which is the wrong order for KARST: quotas bound throughput per identity, not identities. Worth building anyway as the PSI oracle defence, but it is not an admission bound and should not be described as one.

Proof of personhood (Borge, Kokoris-Kogias, Jovanovic, Gasser, Gailly, Ford, EuroS&PW 2017; personhood credentials, Adler et al., arXiv 2408.07892). The only family that genuinely bounds identities per human. Every construction imports an issuer, a physical event, or a federation of attestors. That is the logically centralised authority Douceur says is required and KARST refuses. It is the honest answer to "what would actually work", and it is out of scope by the design's own premises rather than by oversight.

Rejected framing: keeping a weakened bound claim. The strongest argument for keeping something is that the negative results are all measured against platforms that accept friend requests from strangers, and KARST does not, so a much sparser cut is plausible and refusing any bound throws away quantitative reasoning. It loses for three reasons. The bound is not "a sparse cut exists", it is "g is below a threshold and the graph mixes in w hops", and neither is checkable by any party here while the failure at the threshold is a cliff rather than a slope. It confuses the acceptance rule with the adversary's target: requiring a genuine relationship raises the unit price of an attack edge and bounds nothing, and Douceur's indirect-validation result says nothing does. And the quantitative reasoning it wants to keep is available without the bound and is more honest, as a price per edge with no stated total.
### Citations as given

All verified by fetching and reading the source text. PDFs were extracted locally with pypdf where WebFetch returned binary.

1. John R. Douceur. *The Sybil Attack.* IPTPS 2002. VERIFIED: full text extracted from the Microsoft Research PDF. Abstract states the paper "shows that, without a logically centralized authority, Sybil attacks are always possible except under extreme and unrealistic assumptions of resource parity and coordination among entities." Section 1 enumerates, for direct validation: "Even when severely resource constrained, a faulty entity can counterfeit a constant number of multiple identities" and "Each correct entity must simultaneously validate all the identities it is presented; otherwise, a faulty entity can counterfeit an unbounded number of identities." For indirect validation: "A sufficiently large set of faulty entities can counterfeit an unbounded number of identities" and "All entities in the system must perform their identity validations concurrently; otherwise, a faulty entity can counterfeit a constant number of [identities]." Lemma 1 verbatim: "If rho is the ratio of the resources of a faulty entity f to the resources of a minimally capable entity, then f can present g = rho distinct identities to local entity l."

2. Haifeng Yu, Phillip B. Gibbons, Michael Kaminsky, Feng Xiao. *SybilLimit: A Near-Optimal Social Network Defense against Sybil Attacks.* IEEE Symposium on Security and Privacy 2008. VERIFIED: full text extracted. Abstract verbatim: "The number of sybil nodes accepted is reduced by a factor of Theta(sqrt(n)), or around 200 times in our experiments for a million-node system. We further prove that SybilLimit's guarantee is at most a log n factor away from optimal... Finally, based on three large-scale real-world social networks, we provide the first evidence that real-world social networks are indeed fast mixing." Table 1 verified: SybilGuard accepts O(sqrt(n) log n) per attack edge for g = o(sqrt(n)/log n) and is unbounded above that; SybilLimit accepts O(log n) for g up to o(n/log n); experimentally about 2000 versus about 10 per attack edge at a million nodes. Section 1 verbatim: "the adversary needs to establish nearly 100,000 real-world social trust relations with honest users in order for the sybil nodes to out-number honest nodes, as compared to 500 trust relations in SybilGuard." Section 8 (Lower bound): "all protocols based on mixing time will end up accepting Omega(1) sybil nodes per attack edge." Section 9 verified: datasets are Friendster, LiveJournal, DBLP and Kleinberg's synthetic network; preprocessing includes "removing low (< 5) degree nodes, taking the largest connected component"; w = 10 for Friendster and LiveJournal, 15 for DBLP; the paper explicitly says "It is not possible to directly show that our data sets have O(log n) mixing time". The 200x experiment is on the synthetic Kleinberg network, not a real one. Section 5.1 verified for mechanism: tails are recorded "under the edge name KA→KB where KA and KB are A's and B's public key"; verification requires the suspect to know A's and B's public keys and IPs; every pair of neighbours shares an out-of-band edge key; the verifier holds r ≈ r0·sqrt(m) tails and the intersection condition is on tails.

3. Haifeng Yu, Michael Kaminsky, Phillip B. Gibbons, Abraham Flaxman. *SybilGuard: Defending Against Sybil Attacks via Social Networks.* SIGCOMM 2006. VERIFIED indirectly via SybilLimit's Section 1 and Table 1, which state SybilGuard's guarantee and its void condition, and via Viswanath et al.'s and Yang et al.'s reference lists. I did not fetch the SybilGuard PDF itself.

4. Abedelaziz Mohaisen, Aaram Yun, Yongdae Kim. *Measuring the Mixing Time of Social Graphs.* IMC 2010. VERIFIED: full text extracted from the SIGCOMM IMC 2010 proceedings PDF. Authors and affiliations confirmed (all University of Minnesota). Abstract verbatim: "Our findings show that the mixing time of social graphs is much larger than anticipated, and being used in literature, and this implies that either the current security systems based on fast mixing have weaker utility guarantees or have to be less efficient, with less security guarantees, in order to compensate for the slower mixing." Section 3.4 verifies the trust-semantics claim: networks "that exhibit knowledge between nodes and are good for the trust assumptions of the Sybil defenses; e.g., physics co-authorships and DBLP. These are slow mixing", against Facebook and wiki-vote "where the social links between nodes are less meaningful to the context of the Sybil defenses... which are shown to be fast mixing." Section 5 also verifies the mitigating explanation the module omits: "the trimming of lower-degree nodes would shorten the mixing time", the average mixing time is better than the worst case, and the epsilon = Theta(1/n) definition "is a very strong burden to achieve".

5. Zhi Yang, Christo Wilson, Xiao Wang, Tingting Gao, Ben Y. Zhao, Yafei Dai. *Uncovering Social Network Sybils in the Wild.* IMC 2011, extended in ACM Transactions on Knowledge Discovery from Data 8(1), February 2014. VERIFIED: TKDD version full text extracted. Abstract: detector deployed on Renren detected "more than 100,000 Sybil accounts", full dataset "650,000 Sybils" (100,000 from their detector plus 560,000 identified by Renren). Verbatim: "contrary to prior conjecture, Sybils in OSNs do not form tight-knit communities"; ">70% of Sybils do not have any edges to other Sybils at all"; of the remaining 30%, "69% (65,000 accounts) form a single connected component" that "formed accidentally"; "34.5% of Sybils only connect to one other Sybil, and 93.7% connect to 10 or fewer"; "attackers use biased random sampling to identify and send friend requests to popular users, since these users are more likely to accept requests from strangers." The module's "most sybil-to-sybil links are accidental rather than intended" is verified verbatim: "these connections are often formed randomly by accident rather than intentionally by attacker."

6. Lorenzo Alvisi, Allen Clement, Alessandro Epasto, Silvio Lattanzi, Alessandro Panconesi. *SoK: The Evolution of Sybil Defense via Social Networks.* IEEE Symposium on Security and Privacy 2013, pp. 382-396. VERIFIED: full text extracted from oaklandsok.github.io. Section VII verbatim: "We simulated the attack on our Facebook graph and measured the probability that a randomly-chosen honest node be considered more trustworthy than a randomly-chosen sybil one by SybilLimit, SybilGuard, Mislove, Gatekeeper, and ACL. A probability of 1 corresponds to the ideal case... a random ranking correspond to 0.5 probability. In our results, every protocol performs poorly: the probability is 0.45 for SybilLimit, 0.44 for SybilGuard, 0.34 for Mislove, 0.49 for Gatekeeper, and 0.37 for ACL." Abstract verifies both contributions, including "a community detection algorithm that, for the first time, offers provable guarantees in the context of sybil defense" (ACL, from Andersen, Chung and Lang) and "the more limited, but practically useful, goal of securely white-listing a local region of the graph". Problem 1 verified as stated in the mechanism section. Yang et al.'s clustering-coefficient and acceptance-rate heuristic, "more than 98% of the sybils, with a false positive rate of less than 0.5%", is Alvisi et al. reporting Yang et al.

7. Lorenzo Alvisi, Allen Clement, Alessandro Epasto, Silvio Lattanzi, Alessandro Panconesi. *Communities, Random Walks, and Social Sybil Defense.* Internet Mathematics 10(3-4):360-420, 2014. Extended version of the SoK. VERIFIED: full text extracted from epasto.org; venue and pagination confirmed by the Internet Mathematics journal listing. Verbatim: "The goal of universal decentralized sybil defense with strong theoretical guarantees, which has driven early research on sybil defense via social networks, rests on assumptions (short mixing time and cut sparseness) whose validity is at best dubious." And on SybilLimit's cliff: "Once the bound is exceeded, however, the performance of SybilLimit falls rather quickly: the algorithm can no longer ensure that at most log(n) sybil nodes per attack edge are admitted, leading to a sudden drop in the precision observed in our experiments." The same passage attributes to Yu's 2011 survey the two ways forward, serving only "the nodes in the core of the social graph" or relying on "weaker but less clean assumptions".

8. Bimal Viswanath, Ansley Post, Krishna P. Gummadi, Alan Mislove. *An Analysis of Social Network-Based Sybil Defenses.* SIGCOMM 2010. VERIFIED via the authors' own conference slide deck (Mislove's site, 40 slides, titled and attributed to SIGCOMM 2010). Slides verify: "All schemes are effectively detecting communities"; the experiment used eight real networks with 5% attack links and 25% sybil nodes, scored by "Probability Sybils ranked lower than non-Sybils"; "More community structure makes Sybils indistinguishable"; and on targeted placement, "Attack becomes much more effective / Sybils ranked higher than non-Sybils (accuracy << 0.5)". Closing slide: "Could be still useful for white-listing small number of nodes." I read the slides rather than the paper text; the paper PDF at ccr.sigcomm.org failed TLS negotiation.

9. Bimal Viswanath, Mainack Mondal, Allen Clement, Peter Druschel, Krishna P. Gummadi, Alan Mislove, Ansley Post. *Exploring the design space of social network-based Sybil defenses.* COMSNETS 2012. VERIFIED: full text extracted from mislove.org. Source of the sybil detection versus sybil tolerance distinction. Conclusion verbatim: "A detailed understanding of the effectiveness of Sybil detection on real social networks remains an open problem."

10. Nguyen Tran, Jinyang Li, Lakshminarayanan Subramanian, Sherman S. M. Chow. *Optimal Sybil-resilient node admission control.* INFOCOM 2011. VERIFIED: full text extracted from cs.nyu.edu. Abstract verbatim: "Gatekeeper is optimal for the case of O(1) attack edges and admits only O(1) Sybil identities (with high probability) in a random expander social networks... In the face of O(k) attack edges (for any k in O(n/log n)), Gatekeeper admits O(log k) Sybils per attack edge."

11. Ali Safarpoor Dehkordi, Ahad N. Zehmakan. *Graph-based Fake Account Detection: A Survey.* arXiv:2507.06541, dated 10 July 2025. VERIFIED: full text extracted. Confirms the post-2015 state of the field: SybilGuard, SybilLimit, SybilInfer, SybilRank, SybilDefender, SybilWalk and SybilBelief are tabled as "classical methods", and the live literature is GNN, belief-propagation and contrastive-learning based, trained on labelled accounts plus profile, content and temporal features. It cites Yang et al. as "Challenging homophily assumption". I searched the full text: it contains no rehabilitation of the fast-mixing assumption and no decentralised bound.

12. Yazan Boshmaf, Dionysios Logothetis, Georgos Siganos, Jorge Lería, José Lorenzo, Matei Ripeanu, Konstantin Beznosov. *Integro: Leveraging Victim Prediction for Robust Fake Account Detection in OSNs.* NDSS 2015. VERIFIED for title, authors and venue via the NDSS Symposium programme page. Deployed at Tuenti with "up to an order of magnitude higher precision" than SybilRank. I did not read the full paper.

13. Qiang Cao, Michael Sirivianos, Xiaowei Yang, Tiago Pregueiro. *Aiding the Detection of Fake Accounts in Large Scale Social Online Services.* NSDI 2012. Cited for SybilRank being an operator-side ranking deployed at Tuenti. PARTIALLY VERIFIED: title, authors and venue confirmed from the USENIX listing and from citations in Alvisi et al. and Dehkordi and Zehmakan. The USENIX PDF returned HTTP 403 so I did not read the full text; my characterisation of SybilRank as a ranking that prioritises manual inspection comes from Alvisi et al.'s and Dehkordi and Zehmakan's descriptions of it, both of which say so explicitly.

14. Srivatsan Sridhar, Onur Ascigil, Navin Keizer, François Genon, Sébastien Pierre, Yiannis Psaras, Etienne Rivière, Michał Król. *Content Censorship in the InterPlanetary File System.* NDSS 2024. VERIFIED: full text extracted from the NDSS proceedings PDF. Abstract: the attack runs "from a single, resource-constrained machine at very little cost ($4 using AWS)". Section VIII: "e = 45 Sybil identities can censor content with a aeff = 99% probability of success"; EdDSA key generation "remains below 12s translating into 0.0005$"; AWS instance cost 0.16$/hour; total catt = 7.68 + teff × 0.16$ assuming a 48h warmup. NOTE for the caller: `docs/25-replication.md` line 45 currently reads "$0.0005 per identity". That is wrong. $0.0005 is cgen, the cost of generating the whole batch of 45 identities, not the per-identity cost. The per-identity figure is about $0.00001. Fix that line.

15. Tor Project. *Introducing Proof-of-Work Defense for Onion Services.* Tor Project blog, August 2023; proposal 327; specification at spec.torproject.org/hspow-spec; EquiX by tevador; stable in tor 0.4.8.4. VERIFIED for what it is: the blog describes it as a defence that prioritises verified traffic "as a deterrent against denial of service (DoS) attacks", requiring a client puzzle before accessing an onion service, with effort scaling up to roughly a minute of work.

16. Lobsters. *About* page, lobste.rs/about. VERIFIED by fetching. Verbatim: "The full user tree is public and each user's profile shows who invited them." And: "When accounts are banned for spam, sockpuppeting, or other abuse, moderators will consider disabling their inviter's ability to send invitations or, rarely, also ban them." Also: "There's no limit on how many invitations a user can send."

17. Maria Borge, Eleftherios Kokoris-Kogias, Philipp Jovanovic, Linus Gasser, Nicolas Gailly, Bryan Ford. *Proof-of-Personhood: Redemocratizing Permissionless Cryptocurrencies.* IEEE European Symposium on Security and Privacy Workshops (EuroS&PW) 2017. VERIFIED for title, full author list and venue via IEEE Computer Society and Bryan Ford's publication page.

18. Steven Adler, Zoë Hitzig, Shrey Jain et al. *Personhood credentials: Artificial intelligence and the value of privacy-preserving tools to distinguish who is real online.* arXiv:2408.07892, August 2024. VERIFIED for title, arXiv identifier and date. I did not verify the full author list beyond the first authors, and I did not read the paper in full; I cite it only as evidence of where the identity-bounding problem is currently being worked.

19. Haifeng Yu. *Sybil defenses via social networks: a tutorial and survey.* ACM SIGACT News 42(3):80-101, 2011. VERIFIED for title, author, venue and pagination via the ACM DL listing and via the reference list in Viswanath et al. (COMSNETS 2012). The two ways forward attributed to it are quoted from Alvisi et al.'s Internet Mathematics paper, which cites it directly. I did not read Yu's survey itself.

20. Divya Siddarth, Sergey Ivliev, Santiago Siri, Paula Berman. *Who Watches the Watchmen? A Review of Subjective Approaches for Sybil-resistance in Proof of Personhood Protocols.* arXiv:2008.05300, 2020. VERIFIED: full text extracted; title and authors confirmed from the document. Used only as evidence of where the practitioner community went after the graph-based approach stalled. It is advocacy-adjacent and I have not relied on any technical claim in it. I could not confirm a peer-reviewed venue.

CORRECTIONS TO THE MODULE'S EXISTING CITATIONS. Three, one of them the understatement the review flagged.

(a) "Four of five perform at or below chance" understates the result. Alvisi et al. report five protocols and all five score strictly below 0.5. The module lists SybilLimit 0.45, SybilGuard 0.44, Gatekeeper 0.49 and "one variant at 0.34" (Mislove), and silently drops the fifth. The fifth is ACL at 0.37, and ACL is the algorithm that same paper introduces as the first community detection algorithm with provable guarantees in sybil defence. Naming it makes the finding sharper: the field's own best answer, published in the same paper as the measurement, also scores below chance. Change to "All five perform below chance, including the one the same paper introduces as the first with provable guarantees."

(b) "Alvisi and colleagues then measured those schemes under the real attack shape" is imprecise. They simulated the Renren attack shape on their own Facebook graph. They did not measure a live deployment. Change "measured" to "simulated the Renren attack shape on a real Facebook graph and scored".

(c) Gatekeeper is named without attribution or assumption. It is Tran, Li, Subramanian and Chow, INFOCOM 2011, and its guarantee is stated for random expander social networks, a stronger assumption than fast mixing. Worth one clause, because it explains why it scores worst of the five.

(d) Not an error, but an omission that cuts against the module's own case and should be stated in the interest of not overclaiming: Mohaisen et al. offer their own explanations for why SybilGuard's and SybilLimit's experiments worked despite the slow mixing they measured, namely that removing nodes of degree below five shortens mixing time, that average mixing time is better than worst case, and that the epsilon = Theta(1/n) definition may be an unnecessarily strong burden. The module should acknowledge this and then note that low-degree trimming is exactly the wrong assumption for a bootstrapping network, which is mostly low-degree nodes.
### What the author could not verify

Things I wanted to claim and could not confirm, or that are mine rather than the literature's.

1. The small-n extrapolation of SybilLimit's constant is my arithmetic, not the paper's. SybilLimit reports one data point, about ten accepted sybils per attack edge at n = 1,000,000 on a synthetic Kleinberg network, and reports the crossover as "nearly 100,000" trust relations. Calibrating a constant against ln(10^6) and extrapolating to n = 1,000 to get roughly five per edge and a crossover near 200 edges is an extrapolation from a single point on a synthetic graph, in a regime where an asymptotic bound is least trustworthy. The direction of the argument is safe (the bound is weakest when n is small) but the numbers should be labelled as an estimate or dropped. Do not put "200 attack edges at a thousand nodes" in the whitepaper as though it came from the paper.

2. The claim that running SybilLimit would reconstitute an enumerable roll is my reading of the protocol, not a cited result. I verified that tails are named by both endpoint public keys, that verification requires the suspect to know those keys and IPs, and that the tail sets compared are of size r ≈ r0·sqrt(m). I did not find any published privacy analysis of SybilLimit, SybilGuard or Gatekeeper. If one exists I did not find it, and my search for it was not exhaustive. Phrase it as "the protocol as specified exchanges keyed edge samples on every verification" and not as "it has been shown to leak the graph".

3. Whether KARST's introduction graph would be high-modularity and slow-mixing is unmeasured and unmeasurable today, which is issue #47's entire point. My claim that introductions along existing trust produce high modularity is a design inference. It cuts both ways: I cannot demonstrate the graph mixes slowly either. The argument in this answer does not depend on it, which is why #47 can be closed rather than answered, but the inference itself should not be stated as fact.

4. The claim that Tor's onion service proof-of-work is not a sybil defence is inference from what the Tor Project says it is (a DoS deterrent that prices introduction requests) plus the absence of any sybil claim in the announcement. The blog post does not say "this is not a sybil defence". State it as what the mechanism does, not as a Tor Project position.

5. I did not read the SybilGuard paper (SIGCOMM 2006) directly. Every SybilGuard number here comes from SybilLimit's Table 1 and Section 1, which is a competitor's summary, albeit by overlapping authors and uncontested in the later literature.

6. I did not read the SybilRank paper (Cao et al., NSDI 2012) directly; the USENIX PDF returned 403. My characterisation of it as an operator-side ranking for manual inspection comes from Alvisi et al. and from Dehkordi and Zehmakan, both of which describe it that way. If the whitepaper is going to state anything about the Tuenti deployment's numbers, read the paper first.

7. I did not read Integro (NDSS 2015) in full. The "up to an order of magnitude higher precision than SybilRank" figure comes from the NDSS programme abstract, not from the paper body. Do not quote it as a measured result without reading the paper.

8. I did not verify Yu's SIGACT News 2011 survey directly. The "core of the social graph" and "weaker but less clean assumptions" positions attributed to it are quoted from Alvisi et al.'s Internet Mathematics paper quoting it. That is a secondary source. If the whitepaper cites Yu 2011 for those positions, read Yu 2011.

9. The full author list of the personhood credentials paper (arXiv:2408.07892) is long and I confirmed only the first authors and the identifier. If it is cited, get the author list right or cite it as "Adler et al." with the arXiv id.

10. The venue of Siddarth, Ivliev, Siri and Berman is unconfirmed beyond the arXiv preprint. Cite it as arXiv:2008.05300 only. I would not cite it at all in the whitepaper; it is advocacy-flavoured and nothing in this answer depends on it.

11. I found no post-2015 decentralised sybil admission protocol with a proof that survives the Renren attack shape. That is a negative result from a search that covered the 2013 SoK, its 2014 journal extension, and a 2025 survey, plus targeted searches for rehabilitation. It is not a proof of absence, and I did not read every paper the 2025 survey cites.

12. I have not verified the KAX17 figures (four years, fifty-plus autonomous systems, 25.8% of paths) or the Freenet opennet quotation, both of which appear in the whitepaper and in `docs/13`. They are outside the scope of this question and I did not check them.

13. Flagged for a separate check, found in passing: `docs/25-replication.md` line 45 states "$0.0005 per identity" for the IPFS sybil attack. The NDSS 2024 paper's cgen = $0.0005 is the cost of generating the whole batch of 45 identities, not the per-identity cost. Also, the paper's own total is catt = 7.68 + teff × 0.16 dollars under its 48 hour warmup assumption, while the abstract says "$4 using AWS"; the two are reconcilable but the whitepaper should pick one and say which assumption it is under.
### Independent citation check

**Wrong:**

- CITATION 1, Douceur Lemma 1 — MISQUOTED, and it is presented as verbatim. The write-up gives: 'If rho is the ratio of the resources of a faulty entity f to the resources of a minimally capable entity, then f can present g = rho distinct identities to local entity l.' The paper reads g = FLOOR(rho), typeset with floor brackets. I confirmed this against two independent hosts of the PDF (comp.nus.edu.sg and courses.csail.mit.edu), both of which extract the raw glyph sequence 'g = rho', i.e. the floor delimiters. The paper's own proof depends on it ('Since rho >= g'). The write-up's extraction pipeline silently dropped the brackets, which is exactly the failure mode that makes a quote look verified when it is not. CORRECTION: quote it as 'g = ⌊ρ⌋ distinct identities', or paraphrase as 'the floor of the resource ratio'. This does not affect any conclusion — Lemma 1 is not load-bearing for Reason 1, which rests on the indirect-validation bullets, and those are verbatim correct.

- REASON 3, the Yang et al. sentence — MISATTRIBUTED. The write-up says: 'Yang et al. confirm targeted placement is the observed strategy, not the theoretical worst case', then quotes the biased-random-sampling passage. The quote is verbatim and the paper is real, but it does not say what it is cited for. These are two different notions of targeting. Viswanath et al.'s 'targeted placement' (SIGCOMM 2010 §5.2) is specifically defined as placing attack links 'randomly among the k nodes closest to the trusted node, where closeness is defined by the ranking given by the community detection algorithm' — targeting proximity to the VERIFIER, with accuracy collapsing as k shrinks. Yang et al. document attackers targeting POPULAR, high-degree users via Renren's friend-recommendation feature, and they explicitly find these edges land such that Sybils 'integrate seamlessly into the social graph' — a degree-biased strategy, not a verifier-proximity strategy. Yang et al. never measure placement relative to any verifier's local community and never claim to. CORRECTION: split the sentence. Keep Yang for what it does show (attack edges are real, numerous, aimed at high-acceptance-rate hubs, and produce no detectable sybil community), and state plainly that whether real adversaries target a specific verifier's neighbourhood is unmeasured — Viswanath et al. showed only that they CAN, by simulation. Reason 3 survives without the overclaim: its two independent legs (rising modularity drives accuracy down; adversary-chosen placement drives it below 0.5) are both verified directly in the Viswanath paper, and Reason 4 already carries the Renren attack shape. Fixing this costs nothing and removes the write-up's one genuine 'sounds right, isn't sourced' step.

- CITATION 11 date — TRIVIALLY WRONG. Write-up says arXiv:2507.06541 is 'dated 10 July 2025'. arXiv lists v1 submitted 9 July 2025. Everything else about the citation is correct. CORRECTION: 9 July 2025, or just '2025'.

**Unconfirmed:**

- Nothing failed verification outright. Four residual limits, all minor and none affecting a conclusion. (1) CITATION 2: I read the extended/technical-report version of SybilLimit (comp.nus.edu.sg/~yuhf/sybillimit-tr.pdf), not the IEEE S&P proceedings PDF. Every quoted string, Table 1 entry, w value and preprocessing step matched, so the risk of a conference/TR divergence on these specific facts is negligible, but I did not read the proceedings text itself.

- CITATION 7: same situation — I read epasto.org/papers/sybil-tr.pdf, not the published Internet Mathematics article. Both quotes matched verbatim. Venue, volume 10(3-4), and pages 360-420 confirmed via the Internet Mathematics journal listing surfaced in search, not by fetching the journal page (paywalled).

- CITATION 12, Integro: verified title, all seven authors, NDSS 2015 venue, and the Tuenti / 'up to an order of magnitude higher precision' claim from the NDSS programme abstract. I did not read the full paper, matching the write-up's own declared limit. The cited claim is in the abstract, so this is adequate for the use made of it.

- CITATION 15, Tor: the blog post alone does not support proposal 327, EquiX, tevador, or the 0.4.8.4 version pin. I confirmed all four from other sources (spec.torproject.org/hspow-spec names proposal 327 and lists tevador among the authors; the tor-announce 0.4.8.4 release thread and Tor forum confirm PoW shipped there; tevador/equix confirms Equi-X and HashX authorship and LGPL-3.0). The facts are right; the single-source attribution to the blog is not. Split the citation.

**Claims with no citation:**

- REASON 3's premise: 'An introduction graph built by people introducing people they already trust is high-modularity by construction.' No citation, no measurement, no argument. This is the load-bearing assumption of the entire reason — everything Viswanath et al. show about modularity only bites if KARST's graph is in fact high-modularity. It is asserted about a graph the write-up elsewhere says 'has never been measured because it does not exist' (docs/13 line ~90). This is the same species of unexamined assumption the write-up correctly criticises the fast-mixing literature for. It is plausible, but it should be marked as a conjecture, not stated 'by construction'.

- REASON 5's extrapolation: 'roughly 0.72 ln n accepted per attack edge; at n = 1,000 that is about 5 per edge and a crossover near 200 attack edges.' Self-flagged by the author, which is correct practice, and I checked the arithmetic — it is right and internally consistent with SybilLimit's own figures. But note the constant is calibrated from a single data point on one SYNTHETIC Kleinberg graph, and the write-up's own Citation 2 entry makes that provenance a central criticism. Calibrating off it and then extrapolating three orders of magnitude down is a strong move to make with a number the write-up otherwise treats as untrustworthy. Say so where the extrapolation appears, not only in the unverified list.

- REASON 5's closing clause: 'the asymptotic side condition g = o(n / log n) lands in the same neighbourhood.' At n = 1000 that expression is ~145 (natural log) or ~100 (log base 2), against the claimed crossover of 200. That is a factor of 1.4 to 2. 'Same neighbourhood' is defensible for an order-of-magnitude argument but it is an uncited numerical claim doing rhetorical work; give the number or drop the clause.

- The IPFS per-identity figure 'about $0.00001' in the NOTE to the caller. Correct arithmetic (0.0005 / 45 = 1.11e-5) but it is a derived number that appears nowhere in Sridhar et al. Present it as a derivation, not as a paper figure — which is precisely the error being corrected in docs/25 line 45.

- CLAIM (c): 'That is Lobsters' mechanism and it works there, at human scale, with a public tree and human adjudication.' The Lobsters About page documents the MECHANISM (public invite tree, moderator discretion over inviters, no invitation cap). It says nothing about whether it works, and no source is offered for the effectiveness claim. Given that the write-up's central thesis is that mechanisms get credited with guarantees nobody measured, 'it works there' is the one place the write-up does the thing it is arguing against. Either cite something, or reduce it to 'that is Lobsters' mechanism, and it provides no bound either' — which is the only part the argument actually needs.

- CLAIM (c)'s security description of the OPRF: 'unforgeable by a responder holding nothing, refused rather than believed under a second key.' These are assertions about karst-member's behaviour with no line or test reference. I confirmed the crate is a single 575-line lib.rs exposing only PSI primitives (Party, Ask, Answer, learn, exchange) and that it contains no introduction record, inviter field, or rate counter — so the 'unbuilt' half of the claim is solid. I did not verify these two specific cryptographic properties. If the sentence is going into a design document as a positive claim, point it at a test.

- REASON 1: 'KARST has no coordination point and validates nothing concurrently, both by design.' This is what makes Douceur's indirect-validation impossibility apply rather than merely rhyme, so it is the hinge of the most decisive of the five reasons. It is an internal design claim with no reference to a document or a crate. Cite the whitepaper section or the code.

---

## path-selection
**Question.** How should a KARST sender choose a path at L4, given that any diversity heuristic a relay operator can read is itself a placement target, and given that selection is currently uniform within a layer?
### Answer

Adopt Wan et al.'s security definition, not their algorithm, and take uniform-over-admitted-operators as the degenerate case of it. Their Theorem 1 says a selection rule is θ-GP-secure if and only if max over clients and relays of f(c,g)/relCost(g) is at most θ. KARST has no bandwidth measurement and no consensus, so the only cost it can price is admission at L5, which makes relCost flat at 1/N per admitted operator identity. Under a flat cost model the θ=1 rule is exactly uniform over operators. Uniform is therefore right, but not for the reason the docs currently give: it is right because it is cost-proportional under KARST's only measurable cost, not because it is neutral.

That reasoning immediately exposes the real defect, which is not the heuristic but the unit of selection. `Directory::route_to` draws uniformly over `NodeInfo` records, and `NodeInfo` carries no operator identity, so an operator publishing m records in a layer receives m/n. That is precisely LASTor's failure mode: LASTor's selection has no dependency on bandwidth, and Wan et al. measure an adversary turning a fixed 40,000 bandwidth budget into 18.22% average selection by splitting it across 20 relays. Uniform selection over unbounded identities is not a defence against placement, it is the algorithm that lost worst. Fix the unit, add tenure and a persistent sample, keep the draw uniform, and state plainly that the entire security of the rule now rests on L5's per-identity price.
### Mechanism

SELECTION RULE, six clauses.

1. Draw over operators, not records. Bind every `NodeInfo` to the `Address` of the L1 operator key that signed its segments. Group candidates in a layer by operator address, draw an operator uniformly, then draw one of that operator's records uniformly. Per-operator selection probability is 1/|operators in layer|, independent of how many records it publishes. Without this, m records buy m/n, which is the 20-relay split Wan et al. measure at 84x.

2. Structure enters only as eligibility, never as weight. A relay is eligible or it is not. No score, no ranking, no continuous preference, no function of anything an operator reports about itself. Eligible in layer L iff: segment signature verifies and the carried key hashes to the claimed operator address; segment unexpired at `now`; operator tenure at least T epochs (clause 3); operator not already on this path. If a capacity floor is wanted, it is a threshold predicate ("sustains the network per-relay rate"), never a weight.

3. Tenure is local. `placement::min_tenure` measures against a public beacon epoch because placement must be third-party computable. Selection must not be. Tenure here is "how many epochs has this sender held a valid segment from this operator", read from the sender's own store. An adversary can neither grind it nor observe it. Suggested T = 2 epochs, matching `min_tenure()`, with no evidence that value transfers.

4. Persist the sample for the first hop the sender contacts directly (`hops[0]` from `route_to`). Maintain a per-layer sampled set of size s, drawn uniformly per clause 1 from eligible operators, persisted across sessions, and refreshed only when a member becomes ineligible or after lifetime L. Draw paths from the sample, not from the full eligible set. Tor's guard-spec gives the rationale verbatim: the sampled set "is meant to limit the total number of guards that a client will connect to in a given period." Elahi et al. give the reason not to re-draw. Parameters transplanted from Tor proposal 271: s = 20 (MIN_FILTERED_SAMPLE), L = 120 days (GUARD_LIFETIME).

5. Selection entropy is local and never derived from public inputs. Never seed a path draw from H(sender address || epoch || operator) or any other function of public values. Placement is grindable because it must be recomputable by a third party; selection has no such requirement, and importing the pattern would import the attack that `grinding_into_a_chosen_publishers_set_is_cheap` measures at a few hundred hashes per slot.

6. Fix `Segments::compose`'s ordering. It sorts by `(hops, [operator addresses])`. Both keys are operator-influenceable: an address is the hash of a freely generated key, so an operator grinds a low-sorting address and takes first position for every sender; and an operator offering many long-reach segments shortens paths and rises. Any caller taking `compose(...)[0]` is following a readable preference of exactly the kind the module's doc comment disclaims. Either shuffle inside `compose` with local entropy, or return an explicitly unordered type so callers cannot take the first element by accident.

FAILURE BEHAVIOUR. An empty layer after eligibility filtering is `RouteError::EmptyLayer`, not a shorter route, which `directory.rs` already gets right. A sample that falls below a floor of eligible members refills from the eligible set rather than falling back to the full set, so a churn event cannot silently widen exposure.

VALIDATION. Three tests are needed beyond the existing `selection_within_a_layer_is_uniform`, which currently asserts uniformity over node ids and therefore asserts nothing about the property that matters. (a) One operator publishing m records in a layer receives 1/k of selections, where k is the operator count, for m from 1 to 64. This is the LASTor test. (b) A newly admitted operator is not selectable before T epochs, mirroring `a_newly_arrived_provider_cannot_be_assigned_yet`. (c) Two senders with identical stores and identical seeds-from-the-OS produce different samples, so selection is not recomputable from public inputs.
### Costs

All capacity information is discarded. Selection probability is independent of what a relay can carry, so usable throughput is the operator count times the least capable admitted operator, not the sum of capacities. Large relays run with permanently unused headroom. There is no fix without a cost oracle, and the only credible oracle in the literature needs the thing KARST removed: PeerFlow states its bound as γ ≤ 2/τ in terms of a trusted fraction τ and voting weights held by directory authorities. KARST's partial escape is that L4 already emits at a fixed Poisson rate with cover, per Loopix, so per-sender load is constant by construction and capacity becomes an eligibility threshold rather than a weight. That converts load balancing into an admission question. It does not recover the wasted headroom.

Uniform is not unconditionally safer than weighted, and the design depends on an assumption that can fail. Murdoch and Watson simulated this and found Tor's bandwidth-weighted selection compromises fewer paths than uniform selection against a node-rich, bandwidth-poor adversary, because uniform selection's compromise rate corresponds to the number of nodes injected and not their bandwidth. Uniform is correct for KARST only if L5 makes identities the expensive resource. If admission is cheap, KARST has deliberately chosen the LASTor end of the spectrum. This is a hypothesis of the design and belongs in the text as one.

KARST cannot claim θ-GP-security in Wan et al.'s sense, and should not try. Definition 1 quantifies over all client locations precisely because a bounded average "could still leave certain client locations highly vulnerable". KARST's per-sender segment stores are that case: a sender holding four eligible operators in a layer gives each 0.25, against a relCost near 1/N for the whole network. Per-sender ρ is unbounded. What KARST bounds is the adversary's ability to choose which senders it reaches, and that bound lives entirely in L5 introduction, which is unbuilt.

A persistent sample is a long-lived fingerprint, and here it is worse than Tor's because the candidate set is the social graph. This is DPSelect's leak with a heavier payload: DPSelect bounds leakage of a client's AS through location-biased guard choice, whereas a KARST sender's held set leaks its social neighbourhood to every operator in it. No selection rule fixes this, because the leak is in the candidate set and not in the draw. The whitepaper already concedes it at L5 and section 6.3.

Tenure and a persistent sample stop an adversary who arrives after reading the rule. They do nothing against one who arrived years earlier, which is the KAX17 case and the residual docs/13 already documents.

What this does not cost: load balance. Wan et al. measured it. Applying the θ cap to LASTor reduced the median client's guard load factor from 7.91 to 2.19 and the worst from 70.1 to 8.70; DeNASA went 1.25 to 1.07 median and 3.00 to 1.70 worst; Counter-RAPTOR was essentially unchanged at θ = 1.25. Capping probability-to-cost ratio is a load-balancing constraint. The genuine tension is between placement resistance and the diversity goal itself, which they also measured: LASTor's median expected guard distance ranges 1,348 km to 4,375 km across θ, and DeNASA's suspect-free guarantee falls from 366 of 368 client locations to 80% of locations at θ = 2.
### Rejected

Diversity-aware or standing-disjoint selection, which L16 proposes. This is the exact class Wan et al. break, and `karst-symmetry::placement` reproduces the effect at >20x per hop against KARST's own rule. Already the issue's conclusion; nothing found changes it.

Wan et al.'s Algorithm 1 applied directly. Not wrong, unimplementable here. It requires relCost(g) for every relay in the network and a base distribution f_A over the global relay set, iterating until excess probability is exhausted. KARST has neither a global relay set nor a cost oracle. Under KARST's only available cost model, flat per admitted identity, Algorithm 1 collapses to "cap each operator at θ/N", and at θ = 1 that is uniform over operators. The recommendation is the degenerate case of the paper's own theorem, which is why it can be stated as following from a proof rather than from taste.

DPSelect. Solves a different problem and must not be cited as a placement defence. It bounds Max-Divergence, the leakage of client location through guard choice, using the exponential mechanism, reporting an 83% decrease in worst-case Max-Divergence and a 245% increase in worst-case Shannon entropy after five selections at η = 1.25, against slightly less BGP hijack resilience than Counter-RAPTOR. Its text contains no guard-placement analysis and makes no GP-security claim. It also presupposes a client AS and a resilience metric computed over a global AS topology, neither of which exists in KARST. This is the confusion the issue warns about, and it is easy to make: the two papers are both PoPETs 2019 and share two authors.

CLAPS, the actual state of the art, which does solve both problems at once and is rejected on structural grounds. It bounds location leakage and bounds relay placement advantage together, via a linear program over the whole relay set and the client-location distribution. That program is solved centrally and its output shipped to clients, which is a consensus document under another name. Worth naming in the docs so the rejection is visible rather than an omission.

Bandwidth-weighted selection, the Tor default. Rejected because nothing in KARST measures bandwidth, and weighting by a number the operator influences is a placement attack with one extra step. PeerFlow's Shadow experiment measured a single exit relay inflating its consensus weight from 7% to 11% while its consumed bandwidth fell from 22.5 to 0.2 MiB/s, a bandwidth inflation factor of 177 against TorFlow, and 28.1 against EigenSpeed.

Deterministic per-sender selection derived from a public beacon, by analogy with `placement::placement_among`. Rejected: grindable. `placement.rs` already documents and measures this, and the distinction between a value that must be third-party computable and one that must not be is the point.
### Citations as given

VERIFIED, primary source read in full unless noted.

Gerry Wan, Aaron Johnson, Ryan Wails, Sameer Wagh, Prateek Mittal. "Guard Placement Attacks on Path Selection Algorithms for Tor." PoPETs 2019(4), pages 272-291, DOI 10.2478/popets-2019-0069. Verified: authors, title, venue, volume, issue, pages and DOI from the PoPETs proceedings page; full text extracted from https://www.rwails.org/research/wan_gpa_popets2019.pdf and read.
  - Abstract, verbatim: "an adversary contributing only 0.216% of Tor's total bandwidth can attain an average selection probability of 18.22%, 84x higher than what it would be under Tor currently." VERIFIED verbatim in the extracted PDF text and independently on the PoPETs abstract page.
  - PRECISION POINT the KARST docs currently miss: that figure is LASTor specifically, with 20 relays, Table 3. Intro, verbatim: "we show that in LASTor an adversary with a bandwidth of just 0.216% of the Tor network can increase its average guard selection probability to almost 18.22%, 84x the current Tor selection probability." The same budget against Counter-RAPTOR gives 0.909% average (Table 1, 4.2x); against DeNASA 0.555% average but 54.16% maximum over client locations (Table 2). Writing the figure as though it applies to all three algorithms is imprecise.
  - SECOND PRECISION POINT: the paper's own cost-adjusted number for that configuration is 27x, not 84x, because 20 relays cost relCost 0.665% while one costs 0.134%. Verbatim: "he increases the average success probability 84x over Vanilla Tor and 27x over the relative cost." Both numbers are the paper's; the 84x is the headline and is correctly quoted by KARST, but the 27x is the one under the paper's own security definition.
  - THIRD PRECISION POINT: the abstract says "Tor's total bandwidth"; the table captions say "total guard bandwidth". The tables are the more precise phrasing.
  - Theorem 1, verbatim: "Path selection algorithm A is θ-GP-secure if and only if ρ(A) ≤ θ", where ρ(A) = max over client locations c and guards g of f_A(c,g)/relCost(g). Equation 3. VERIFIED.
  - Definition 1, verbatim: "Path selection algorithm A is secure against guard placement attacks with parameter θ, i.e. is θ-GP-secure, if σ(A) ≤ θ." VERIFIED. The paper's own justification for a worst-case rather than average metric, verbatim: "a bounded average could still leave certain client locations highly vulnerable to attack". VERIFIED.
  - Theorem 2, verbatim: "Let A be any guard selection algorithm and θ ≥ 1 be the security parameter. Then using the guard selection distribution f'_A = D(A,θ) is θ-GP-secure." Algorithm 1 is the defence. VERIFIED, including the full pseudocode.
  - LASTor's bandwidth independence, verbatim: "LASTor selection probabilities have no dependency on bandwidth". A single guard at the minimum consensus weight 2,000 obtains 1.13% average success, "103x greater than what the same adversary would obtain under Vanilla Tor, and 34x greater than the relative cost", and 2.94% against any specifically targeted client location, against 0.74% for the highest-bandwidth honest guard. VERIFIED. This is the load-bearing fact for KARST: bandwidth-independent selection is what KARST calls uniform.
  - Load balancing under the defence, section 7.2.3: LASTor median load factor 7.91 to 2.19, worst 70.1 to 8.70; DeNASA median 1.25 to 1.07, worst 3.00 to 1.70; Counter-RAPTOR "nearly identical". Recommended thresholds θ = 1.25 for Counter-RAPTOR, θ = 2 for DeNASA, θ = 5 for LASTor. VERIFIED.
  - Diversity cost of the defence: LASTor median expected guard distance ranges "between 1,348 km to 4,375 km" over θ; DeNASA falls from 366 of 368 client locations guaranteed suspect-free to "80% of client locations" at θ = 2. VERIFIED.
  - Cost model: empirical, from seven commercial hosts, cheapest Online SAS at $11.40/month for 1,000 Mbps dedicated, $4.55 for 200 Mbps cloud, $2.28 for 100 Mbps cloud, one month chosen to cover the time to earn the GUARD flag; consensus weights converted to bandwidth by linear regression with r^2 = 0.86. VERIFIED.

Hans Hanley, Yixin Sun, Sameer Wagh, Prateek Mittal. "DPSelect: A Differential Privacy Based Guard Relay Selection Algorithm for Tor." PoPETs 2019(2), pages 166-186, DOI 10.2478/popets-2019-0025. Verified: authors, title, venue, volume, issue, pages, DOI from the PoPETs page; full text extracted from https://petsymposium.org/popets/2019/popets-2019-0025.pdf and read.
  - What it actually claims, verbatim from the abstract: "compared to Counter-RAPTOR, our approach achieves an 83% decrease in Max-Divergence after one guard selection and a 245% increase in worst-case Shannon entropy after 5 guard selections". Conclusion specifies η = 1.25 and "worst-case Max-Divergence". VERIFIED.
  - What it costs, verbatim from its own summary: "Provides comparable but slightly less resilience to BGP hijack attacks compared to Counter-RAPTOR", and comparable bandwidth, load balancing and Shadow-simulated performance. VERIFIED.
  - What it does NOT claim: the string "guard placement" does not appear anywhere in the extracted full text. VERIFIED by grep over the complete extraction. DPSelect is not a guard placement defence.

Steven J. Murdoch, Robert N. M. Watson. "Metrics for Security and Performance in Low-Latency Anonymity Systems." PETS 2008, LNCS 5134, pages 115-132. Full text extracted from https://murdoch.is/papers/pets08metrics.pdf and read.
  - Directly answers "is uniform actually right". Verbatim: "The Tor uniform path selection algorithm exhibits the expected behaviour that rate of compromise corresponds simply to the number of nodes injected, and not their bandwidth." VERIFIED.
  - Verbatim conclusion: "not only does Tor's default bandwidth-weighted path selection algorithm offer improved performance over the supposedly more secure Tor uniform path selection algorithm, but also offers improved anonymity in the presence of node-rich but bandwidth-poor attackers." VERIFIED.
  - Verbatim on the assumption that inverts: "The vulnerability of supposedly secure path selection algorithms reflects a historical assumption that bandwidth is a low-cost commodity to acquire, but that large numbers of nodes in different equivalence classes are expensive. We believe that this assumption no longer holds due to the proliferation of botnets". VERIFIED.
  - Method: four algorithms compared (Tor bandwidth-weighted, Tor uniform, Snader-Borisov s=1, Snader-Borisov s=15), 1,000 simulated paths, two adversary cost models (fixed bandwidth per added node, versus a fixed 100 MB/s budget split over a varying node count). VERIFIED.

Aaron Johnson, Rob Jansen, Nicholas Hopper, Aaron Segal, Paul Syverson. "PeerFlow: Secure Load Balancing in Tor." PoPETs 2017(2). Full text extracted from https://www.ohmygodel.com/publications/peerflow-popets2017.pdf and read.
  - Verbatim: "our attack enabled the test relay to obtain more units of consensus weight fraction per bandwidth unit cost with a bandwidth inflation factor of 177." Median consumed bandwidth fell 22.5 to 0.2 MiB/s while median consensus weight rose 7% to 11%, one exit relay, Shadow. VERIFIED.
  - Verbatim: "the measured TorFlow and EigenSpeed inflation factors of up to 177 and 28.1, respectively." PeerFlow's own bound: "the inflation factor is γ < 4.6 when τ = 0 and the adversary is at most 4% of the network", and generally "a bounded inflation factor of γ ≤ 2/τ" where τ is the trusted fraction. VERIFIED.

Tariq Elahi, Kevin Bauer, Mashael AlSabah, Roger Dingledine, Ian Goldberg. "Changing of the Guards: A Framework for Understanding and Improving Entry Guard Selection in Tor." WPES 2012. Full text extracted from https://www.freehaven.net/anonbib/cache/wpes12-cogs.pdf and read. The two quotes already used in `placement.rs` are correct: verbatim "It is obvious that guard rotation increases the chances of active guard list compromise substantially" and verbatim "thus ensuring that after enough time all clients will have been compromised at some point". VERIFIED. Also verified: over an eight-month slice, rotation gives a client 12 to 24 potentially unique guards, average 17, against three without rotation.

Tor Project. Proposal 271, "Another algorithm for guard selection." Fetched from https://spec.torproject.org/proposals/271-another-guard-selection.html. Verbatim: "To add a new guard to {SAMPLED_GUARDS}, pick an entry at random from ({GUARDS} - {SAMPLED_GUARDS}), weighted by bandwidth." Parameters GUARD_LIFETIME 120 days, N_PRIMARY_GUARDS 3, MAX_SAMPLE_SIZE 60, MAX_SAMPLE_THRESHOLD 20%, MIN_FILTERED_SAMPLE 20. VERIFIED.

Tor Project. Guard specification, current, https://spec.torproject.org/guard-spec/algorithm.html. The rationale sentence, verbatim: "The {SAMPLED_GUARDS} set is meant to limit the total number of guards that a client will connect to in a given period. The upper limit on its size prevents us from considering too many guards." Current text says the pick is made "according to the path selection rules" rather than repeating "weighted by bandwidth". VERIFIED by extracting the rendered chapter.

Tor Project. Proposal 291, "The move to two guard nodes." Status Finished. Verbatim: "Back in 2014, Tor moved from three guard nodes to one guard node." VERIFIED via fetch.

Ania M. Piotrowska, Jamie Hayes, Tariq Elahi, Sebastian Meiser, George Danezis. "The Loopix Anonymity System." USENIX Security 2017. Full text extracted from the USENIX PDF. Relevant to the load-balancing escape: verbatim "the traffic sent by the client follows Pois(λP + λL + λD)", so a client's emitted rate is constant regardless of payload. Stratified topology and Poisson mixing confirmed. VERIFIED. The existing `directory.rs` citation is accurate.

Florentin Rochet, Ryan Wails, Aaron Johnson, Prateek Mittal, Olivier Pereira. "CLAPS: Client-Location-Aware Path Selection in Tor." ACM CCS 2020, pages 17-34, DOI 10.1145/3372297.3417279. Full text extracted from https://www.rwails.org/research/rochet_claps_ccs20.pdf. Verbatim: it introduces "(1) a method for location-aware load balancing; (2) a generic technique to prevent location-aware schemes from leaking user locations to a long-term adversary; and (3) a new method to bound the risk of relay-placement attacks", via "a powerful linear-programming framework". Also verbatim: Counter-RAPTOR "when guard bandwidth isn't abundant could increase median download times by 28.7%". VERIFIED.

Zhifan Lu, Siyang Sun, Yixin Sun. "RPKI-Based Location-Unaware Tor Guard Relay Selection Algorithms." arXiv:2501.06010, 10 January 2025, formatted for PoPETs, volume and issue not yet assigned. Read for currency. It confirms the θ constraint is now standard practice, verbatim: "the guard placement constraint that no single relay should have more than θ times the probability of being chosen compared to vanilla Tor", and confirms that biasing toward a scarce property recreates the attack, verbatim: "forcing all traffic through ROV-enforcing relays may introduce additional vulnerabilities such as guard placement attacks because the ROV-enforcing relays will have significantly higher probability of being chosen". VERIFIED. Flagged as not yet formally published.

CITED BUT NOT RE-VERIFIED HERE, because they were used only as background and their existing KARST citations were not the subject of this question: Thaler and Ravishankar 1998, Biryukov et al. 2013, Sridhar et al. 2024, Yu et al. SybilLimit 2008, Mohaisen et al. 2010, Danezis PET 2004, Cheng and Friedman 2005. Snader and Borisov, "A Tune-up for Tor", NDSS 2008 is verified as to authors, title and venue only; I did not read its full text, and I use it only as the source of the s-parameter family that Murdoch and Watson evaluate.
### What the author could not verify

Things I wanted to claim and could not confirm.

KARST's own >20x and >400x figures. These come from `karst-symmetry::placement` and are not from any paper. I read the code rather than re-deriving them. One honest observation follows: `PlacementResult::resource_share` is the adversary's share of relay *count*, and `Selection::Uniform` returns weight 1.0 for every relay, so `uniform_selection_pays_no_premium` asserts an identity, not a result. Uniform amplification is exactly 1.0 by construction under a resource measure of relay count. The non-tautological result is the >20x for the diversity rule. docs/13 presents both rows of that table as if they were symmetric findings, and they are not.

No paper quantifies the placement-resistance versus load-balancing tradeoff for a network without a consensus document. Every quantification I found (Wan et al. section 7.2.3, Murdoch and Watson, CLAPS) presumes a global directory listing relays with measured bandwidths. I could not confirm that any of those results transfer to per-sender candidate sets.

No source gives the crossover at which per-identity admission cost makes uniform selection preferable to weighted selection. Murdoch and Watson establish that the crossover exists and that it moved with botnet availability. They do not give a threshold, and I found nobody who does. `placement.rs` already records the same gap for a different question ("No paper appears to model that crossover"), and this is a second instance of it.

I found no measurement of per-sender candidate set sizes in any deployed sender-composed-path system. The claim that small stores dominate KARST's risk is analysis from Definition 1's quantifier structure, not measurement, and should be labelled as such.

The parameters s = 20 and L = 120 days are Tor's, verified as Tor's, and transplanted with no evidence they transfer to a mixnet with per-sender candidate sets and a socially-introduced peer set. T = 2 epochs is copied from `min_tenure()`, which itself carries no derivation.

I did not confirm from Tor source that a client builds circuits through exactly one guard today. Proposal 291 (status Finished) states the 2014 move to one guard, and the current spec keeps N_PRIMARY_GUARDS = 3 primaries. Those are consistent under "three maintained, one used", but I verified only the documents, not the runtime behaviour.

I could not verify that binding a `NodeInfo` to an operator `Address` is currently possible. `NodeInfo` carries `id: u16`, `addr`, `mix_public` and `layer`, with no operator field, and I did not trace whether the L1 segment that authorises a node is reachable from the directory at all. The clause 1 fix may require a wire or directory change I have not scoped.

The whole recommendation rests on L5's admission bound, and that bound is the thing docs/13 already says is owed a measurement. SybilLimit's log n bound is contingent on fast mixing, which Mohaisen et al. measured and found weaker than assumed, and KARST's introduction graph does not exist to be measured. Nothing found in this pass improves that position. If admission is cheap, the recommended rule is the wrong rule and Murdoch and Watson say so explicitly.

Finally, I did not attempt to verify whether any published system uses per-sender candidate sets as a placement defence. If one exists, it would be the closest prior art to KARST's L1 design and I did not find it.
### Independent citation check

**Wrong:**

- Lu, Sun, Sun, RPKI-Based Location-Unaware Tor Guard Relay Selection Algorithms — publication status is WRONG. The write-up says 'formatted for PoPETs, volume and issue not yet assigned' and 'Flagged as not yet formally published.' It IS formally published. Correction: Proceedings on Privacy Enhancing Technologies 2025(2), pages 564-581, DOI 10.56553/popets-2025-0077, published April 2025 (confirmed via Crossref). Cite it as PoPETs 2025(2):564-581 rather than as an arXiv preprint. The arXiv id 2501.06010 and the 10 January 2025 date are correct, and both quoted sentences are verbatim correct.

- Wan et al., DeNASA figures — row misattribution. The write-up reads: 'that figure is LASTor specifically, with 20 relays, Table 3 ... The same budget against Counter-RAPTOR gives 0.909% average (Table 1, 4.2x); against DeNASA 0.555% average but 54.16% maximum over client locations (Table 2).' The Counter-RAPTOR pair (0.909%, 4.2x) is indeed the K=20 row of Table 1. The DeNASA pair (0.555%, 54.16%) is the K=2 row of Table 2, not the 20-relay row. In the K=20 configuration DeNASA gives 0.531% average and 62.32% maximum. Both quoted numbers do appear in Table 2, so this is not a fabricated figure, but placed after 'the same budget' and immediately after a sentence establishing 20 relays it reads as the 20-relay result and is not. Correction: either say 'against DeNASA, two relays on the same 40,000 budget give 0.555% average and 54.16% maximum (Table 2); twenty give 0.531% and 62.32%', or drop the relay-count framing. Note also that the paper's prose rounds the K=2 maximum to 54.2% while Table 2 prints 54.16%.

**Unconfirmed:**

- Snader and Borisov, 'A Tune-up for Tor', NDSS 2008 — authors, title and venue confirmed via dblp, but I did not read the full text, so the s-parameter family is confirmed only as Murdoch and Watson describe it, not against the original. The write-up already scopes its use this way, so this is a scope note rather than a defect.

- Thaler and Ravishankar 1998, Biryukov et al. 2013, Sridhar et al. 2024, Yu et al. SybilLimit 2008, Mohaisen et al. 2010, Danezis PET 2004, Cheng and Friedman 2005 — explicitly excluded from this pass by the write-up and NOT re-verified here. They carry live numeric claims in crates/karst-net/src/placement.rs (Biryukov 'takes just a few minutes on a modern multi-core computer' and six precomputed relays for Silk Road; Sridhar $0.0005 per identity and about $4 total on AWS). Given that this project has already shipped one fabricated and one misattributed citation, those two numeric quotes deserve their own verification pass before the placement module is considered clean.

- Wan et al. Theorem 2 — the quote is verbatim as numbered in the body (section 7.1), but Appendix C numbers the same statement Theorem 3 and uses Theorem 2 for 'D halts'. Not a defect in the write-up; flagged so a reviewer checking the appendix does not read it as a misattribution.

**Claims with no citation:**

- 'Under a flat cost model the θ=1 rule is exactly uniform over operators.' This derivation appears nowhere in Wan et al. It follows from their Theorem 1 (with relCost(g) = 1/N for all g, ρ(A) ≤ 1 forces f(c,g) ≤ 1/N, and since f sums to 1 over N operators, f = 1/N exactly), and their Theorem 2 admits θ ≥ 1 so θ=1 is in range. The reasoning is sound but it is KARST's inference, not a cited result, and it is currently presented in the same breath as the citation. Mark it as derived.

- 'KARST has no bandwidth measurement and no consensus, so the only cost it can price is admission at L5, which makes relCost flat at 1/N per admitted operator identity.' This is a modelling assumption about KARST with no external support and no internal reference. It is the single load-bearing premise of the whole argument — if L5 admission is not a real per-identity cost, θ=1 uniform-over-operators is not cost-proportional and the security claim collapses. The write-up says as much in its last sentence, but the premise itself carries no citation or measurement.

- Clause 4, 's = 20 (MIN_FILTERED_SAMPLE)'. The value 20 is correct for MIN_FILTERED_SAMPLE, but the parameter's role is misdescribed. In proposal 271 and the guard spec, MIN_FILTERED_SAMPLE is a floor on the number of usable guards remaining after filtering, which triggers expansion of the sample; it is not the size of the sampled set. The size cap is MAX_SAMPLE_SIZE = 60, bounded also by MAX_SAMPLE_THRESHOLD = 20% of the guards. Transplanting 20 as 'sampled set size s' silently changes what the parameter means. Either take s = 20 as an independent choice and say so, or use MAX_SAMPLE_SIZE.

- Clause 3, 'Suggested T = 2 epochs, matching min_tenure(), with no evidence that value transfers.' Self-flagged, correctly. min_tenure() = 2 is confirmed at crates/karst-net/src/placement.rs:143. No citation supports 2 as a selection-tenure threshold, and Tor's analogue (the time to earn the GUARD flag, which Wan et al. price at one month) is a very different quantity.

- Clause 5, 'the attack that grinding_into_a_chosen_publishers_set_is_cheap measures at a few hundred hashes per slot.' Verified against the repo (crates/karst-net/src/placement.rs:310-338, assertion tries <= 128 * 8 with the comment 'a few hundred hashes'), so the number is real, but its source is KARST's own unit test over a 128-provider set, not literature. Presenting it beside the cited material invites reading it as an external result. It is also parameter-dependent: it scales with n, so 'a few hundred' is a property of n = 128, not a constant.

- Clause 6, 'an operator grinds a low-sorting address and takes first position for every sender; and an operator offering many long-reach segments shortens paths and rises.' The sort keys are confirmed in code (crates/karst-path/src/lib.rs:393-398, sort_by_key on (hops, operator addresses)) and the grindability of an address as a hash of a freely generated key is consistent with the placement module's own measurement, but no cost figure or test is offered for this specific grind. Unlike the placement grind, it is asserted rather than measured.

- Validation test (a), 'This is the LASTor test.' The analogy to LASTor is the write-up's framing, not a result in Wan et al. Wan et al. measure LASTor's bandwidth independence against a fixed bandwidth budget split across relays; the proposed test measures record-count independence against an operator count. Structurally parallel, but the equivalence is asserted, not sourced.

- 'Elahi et al. give the reason not to re-draw' (clause 4). The Elahi quotes are verified and do support the harm of rotation, but Elahi et al. study Tor guard rotation over an eight-month window with real consensus data; nothing there speaks to a per-layer sample in a network with no consensus and no measured bandwidth. The transfer is an inference.
