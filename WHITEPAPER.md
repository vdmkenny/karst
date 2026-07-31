# KARST

**A network stack with no seizable chokepoint, no accumulable position, and no markup.**

Draft 03. No working group, no reference implementation, deliberately.

> *karst*: a limestone landscape with no surface rivers. Water moves through thousands
> of dissolved channels underground, so there is nothing to dam, and when one channel
> silts up the water is already taking four others.

---

## Abstract

The internet made four design errors in the early nineteen eighties. The web, built on
top of it twenty years later, made the identical four again at the document layer.
Surveillance, takedowns, link rot, advertising, national shutdowns, credential theft,
the search monopoly, app store gatekeeping, and agents reduced to scraping pages written
for human eyes are all symptoms of one of those eight instances.

KARST is a seventeen layer stack, from the physical bearer to the discussion board, that
commits none of them. It is mostly an assembly of published work: Loopix for anonymity,
Sphinx for packet format, macaroons for authority, BitTorrent for delivery, Xanadu for
citation, content addressing for naming. The contributions are the four error framing,
the flattening of returns to scale as an explicit layer, making publication and indexing
a single operation, and putting the machine-actionable surface inside the signed
document rather than beside it.

This document specifies all seventeen layers, three device profiles, the applications
that fall out of them, and an itemised list of everything the design makes worse.

---

## 1. The four errors

Each was committed once at the packet layer and once at the page layer. Every layer in
§3 corrects one of them and is tagged with which.

### Error 01: location used as identity

| | |
|---|---|
| **Internet, 1981** | An IP address states who you are and where you are in one field. Move, and you become someone else. |
| **Web, 1990** | A URL names a server and a path, not a document. Move the file and every reference to it is now false. |

**Consequences.** NAT, carrier grade NAT, mobile IP, the difficulty of multihoming,
losing your identity on every network change. At the page layer: link rot. A quarter of
all pages that existed between 2013 and 2023 were gone by October 2023, and 54% of
Wikipedia pages contain at least one dead reference link. The most carefully maintained
citation graph humans have built is more than half broken, because a link names a place
rather than a thing.

**Fix.** Name things by their keys and their contents. Location demotes to an ephemeral
hint that anybody may supply and nobody may revoke.

### Error 02: authority granted ambiently

| | |
|---|---|
| **Internet** | Anyone may send anything to anyone, unsolicited and free. Spam, scanning and reflection floods are not abuses of this, they are uses of it. |
| **Web** | The cookie attaches itself to requests automatically. |

**Consequences.** Cross site request forgery, session theft, third party tracking, and
one injected script owning an entire page. Every site inventing its own login, and
therefore reinventing password reuse, and therefore credential stuffing.

**Fix.** Nothing is granted by default anywhere in the stack. Every right is an explicit
capability naming one permission, narrowable before it is passed on, and never handed to
a party it was not addressed to.

### Error 03: exactly one of something, globally

| | |
|---|---|
| **Internet** | One root zone, one address allocator, one routing consensus, one trust store per client. |
| **Web** | One search index that matters, two rendering engines, two app stores, a handful of certificate authorities anyone actually trusts. |

**Consequences.** Every chokepoint any state has ever used. Domain seizure, compelled
certificates, national routing withdrawal, delisting orders, client removal from app
stores.

**Fix.** Zero or *n*, never one. A corollary that does real work: a specification only
two organisations on earth can afford to implement has a de facto owner regardless of who
wrote it, so **small enough to reimplement is a security property**.

### Error 04: increasing returns to scale, left unpriced

| | |
|---|---|
| **Internet** | Transit and peering pay off superlinearly with size, so a tier emerged that everyone else must buy from. |
| **Web** | Crawling, indexing and audience aggregation pay off superlinearly, so search and social became monopolies on schedule. |

**Consequences.** This is the error nobody designing decentralised systems defends
against, which is why they decentralise the protocol and recentralise the deployment
within a decade, and then blame the architecture for what the economics did.

**Fix.** Flatten the returns rather than policing the winners. Specified at L16, and the
least proven part of this document.

---

## 2. Threat model

Four adversaries, named separately because they need different answers.

**A. The local censor.** Controls the network path in one jurisdiction. Can block by
address, fingerprint protocols, actively probe suspected endpoints, and withdraw routes
entirely. Defended at L0, L1, L3, L5.

**B. The global passive adversary.** Observes every link in the network simultaneously
but does not modify traffic. Correlates by volume and timing. Tor explicitly does not
defend against this. Defended at L4, and this is the single largest architectural
difference between KARST and onion routing.

**C. The legal process.** Serves orders on any party able to comply: registries,
certificate authorities, hosts, platform operators, payment processors, app stores.
Defended by removing the compliant party at L2, L5, L6, L8, L9, L14, L15.

**D. The market incumbent.** Acquires, subsidises below cost, extends the protocol
privately, and locks in the graph. Defended at L16, weakly.

**Explicitly out of scope.** Endpoint compromise, compelled unlock, rubber hose
cryptanalysis, and operating system vendors. If the adversary owns the device, no layer
here helps, and a design that makes people feel safer than their hardware actually is has
made them less safe.

---

## 3. The stack

```
  COMMONS     L16  Symmetry      no operator can accumulate position
              L15  Discovery     publishing and indexing are one act
              L14  Value         settlement as a protocol primitive

  SURFACE     L13  Provenance    signed lineage, structural quotes, backlinks
              L12  Agency        the client decides how things render
              L11  Affordance    typed machine operations inside the object
              L10  Document      typed node graph, no markup

  TRUST       L9   Authority     capabilities, attenuable and revocable
              L8   Witness       plural transparency logs, no root store

  CARRIAGE    L7   Streams       append-only media, swarm delivery
              L6   Objects       signed, immutable, content-addressed
              L5   Membership    social introduction, no enumerable roll
              L4   Mixing        constant-rate cover, Poisson delay
              L3   Wire          no stable fingerprint

  SUBSTRATE   L2   Identity      address is the hash of a local key
              L1   Path          sender-composed signed segments
              L0   Bearer        plural media, delay tolerant
```

Status key: **built** means implemented and tested in `crates/`. **specified** means
described here in enough detail to implement. **sketched** means the mechanism is named
and the details are open.

---

### L0 Bearer

*Fixes error 03. Status: sketched.*

**Lever removed.** Licensed fibre and licensed spectrum. Honestly: still theirs. See §6.2.

**Bug fixed.** The stack assumes one always-on medium at low latency, so removing that
medium removes the network. Egypt withdrew essentially the whole country's routes within
hours in 2011; Iran ran a near-total shutdown for roughly a week in 2019.

**Mechanism.** Several bearers concurrently with identical semantics across all of them:
fibre where it exists, unlicensed mesh radio where it does not, low orbit satellite where
it reaches, and physically carried storage as a first class link rather than a joke.
Delay tolerance is the base case rather than the failure case, so a hop with an eight hour
round trip is slow rather than broken.

A stack that only works at twenty millisecond round trip is a stack that dies in the first
shutdown. Designing for the degraded case first is what makes graceful degradation
possible: full connectivity, then regional mesh, then sneakernet, with the same names and
the same keys working at every tier.

**Open.** Bearer switching without leaking which bearer you are on. Battery cost of mesh
participation. Whether physically carried storage can be made routine rather than heroic.

---

### L1 Path

*Fixes error 03. Status: sketched.*

**Lever removed.** BGP convergence, and the registry that allocated your prefix.

**Bug fixed.** One global routing consensus means one operator's error or one operator's
compliance becomes everybody's outage.

**Mechanism.** Each relay signs the path segments it is willing to carry. Senders compose
the end to end path themselves and carry it in the packet. There is no global convergence,
so there is no route leak, no hijack, and no national withdrawal. There is no allocation
authority to revoke from, because nothing was ever allocated.

This is SCION's design. It is not a thought experiment and it carries production traffic.

**Interaction with L4.** Path selection also determines anonymity, so segments must be
drawn from standing-disjoint neighbourhoods per L16. See §3.5 and §6.3.

**Open.** Sender-chosen paths mean the sender decides who gets paid, which inverts transit
economics in a direction whose equilibrium we cannot predict.

---

### L2 Identity

*Fixes error 01. Status: **built** (`karst-id`).*

**Lever removed.** The address your ISP lent you, and the prefix a registry lent them.

**Bug fixed.** Error 01 in its original form, and the direct cause of NAT, of mobility
being hard, and of losing your identity every time you change network.

**Mechanism.** An address is the BLAKE3 hash of a locally generated Ed25519 public key.
There is no registration step and nobody to register with, so there is no roll of
participants for anyone to seize, publish, or be compelled to produce.

The address does not change when you move, multihome, or migrate. The long term key never
touches the wire; sessions carry ephemeral keys only, so an observer learns that something
is being said and not by whom. A device gets its identity the same way, at manufacture or
first boot, from nobody.

Everything is self certifying: given a public key you derive its address and check it
matches, with no directory and no lookup. That property is what lets capability chains at
L9 verify entirely offline.

**Open.** Key rotation and recovery without reintroducing an authority. Hash-of-key
addresses are unreadable by humans, so a petname layer is mandatory, and every petname
layer in recorded history has recentralised into a registry.

---

### L3 Wire

*Fixes error 03. Status: sketched.*

**Lever removed.** Anything with a recognisable handshake, which today means everything.

**Bug fixed.** The wire ossified so hard that new transports must disguise themselves as
old ones simply to be forwarded. QUIC encrypts its own headers substantially to hide from
middleboxes that would otherwise refuse to pass it.

**Mechanism.** No fixed header bytes, no fixed length distribution, no stable handshake
shape. The wire image adapts per region: indistinguishable from uniform random where
random traffic is unremarkable, and steganographically embedded in whatever protocol
dominates locally where it is not.

**Honest assessment.** This is the weakest layer here and the only one in a permanently
contested arms race. Uniform random is itself a fingerprint if all normal traffic is
structured. A censor who is willing to block everything they cannot classify wins, and
some are.

---

### L4 Mixing

*Fixes error 02. Status: **packet format and adversary simulator built** (`karst-mix`);
production format and active-adversary modelling open.*

**Adversary.** B, the global passive adversary. This layer exists to defeat the attack
onion routing declines to attempt.

**Bug fixed.** Encryption solves content and does nothing about volume or timing, both of
which survive any number of encryption layers. Onion routing hides the path from any
single relay while preserving both signals end to end, which is why an adversary at both
ends wins.

**Mechanism.** This is Loopix (Piotrowska et al., USENIX Security 2017), with Sphinx
(Danezis and Goldberg, IEEE S&P 2009) as the packet format.

1. **Constant rate emission.** Every node emits fixed size packets at a fixed rate,
   always. Real payloads displace cover packets; when there is nothing to send, cover is
   sent. Volume therefore carries zero information: an idle node and a node streaming a
   film are indistinguishable, session boundaries are invisible, and website
   fingerprinting has no profile to match. Every partial version of this ever deployed has
   been broken, because a padding scheme with gaps leaks at the gaps.
2. **Continuous time mixing.** Each hop holds each packet for an independently drawn
   exponential delay. A packet leaving a mix carries no timing relationship to the packet
   that entered, and unlike a batch mix there is no batch boundary for an n-1 attack to
   exploit.
3. **Loop cover traffic.** Nodes and mixes send packets addressed back to themselves. An
   adversary who drops or delays traffic to observe the effect reveals themselves, because
   loops that fail to return are evidence. This converts classic active attacks from cheap
   and invisible into detectable.
4. **No consensus document.** Paths are composed from L1 segments learned through L5
   introductions. There is nothing to publish and no authority publishing it.

**Traffic classes.**

| | `Deferred` (default) | `Prompt` |
|---|---|---|
| Latency | seconds to minutes | tens of milliseconds |
| Mixing | full Poisson delay per hop | forwarded promptly |
| Cover traffic | constant rate | constant rate |
| Global passive adversary | resisted | **not resisted** |
| For | publishing, fetching, messaging, agent tasks, media prefetch, device sync | interactive calls, live control |

`Prompt` is approximately Tor's guarantee. It exists because refusing to provide it means
people tunnel latency sensitive work over something worse, which is a real outcome rather
than a hypothetical. **Selecting it is observable**, and clients must say so at the point
of choice rather than in documentation.

**Anonymity is the default, not a mode.** Tor is slow, so few people use it, so the
anonymity set is small, so using it is itself a signal. If the anonymous path is a special
slow mode, only those who badly need it turn it on, and turning it on marks them. Here
everyone routes the same way and the anonymity set is every user.

**Simulated results.** `karst-mix` includes a global passive adversary simulator. 200 clients,
3 mix layers, 0.5% duty cycle, adversary observing every link and knowing the delay
distribution:

| Configuration | Anonymity set | Adversary gain | Bandwidth |
|---|---|---|---|
| Onion routing (no cover, no delay) | 2.0 / 200 | **126.6x** | 1x |
| Mixing only (no cover) | 64.9 / 200 | **3.2x** | 1x |
| Cover only (no delay) | 200 / 200 | 1.0x | 199x |
| KARST (cover + mixing) | 200 / 200 | 1.0x | 193x |

**Against a passive adversary, cover traffic does all the work.** Poisson delay alone leaves a
3.2x advantage, and cover alone scores identically to cover plus delay, because uniform
emission every tick is effectively a synchronous batch mix and a batch mix is strong against
an observer who only watches. Passive evidence alone does not justify the delay layer.

**The active adversary does.** An attacker who can suppress traffic mounts the n-1 attack:
block every other honest packet entering a mix, inject packets it recognises, and anything
else departing is the target.

| Discipline | Anonymity set | Target isolated | Packets suppressed | Detected by loops |
|---|---|---|---|---|
| Batch mix | 1.7 | **51.7%** | 10 | 65.1% |
| Poisson mix | 38.5 | 0.7% | 81 | **100.0%** |

A batch mix has a moment when it is empty but for the target: the flush. Ten suppressed
packets isolate the target half the time. A Poisson mix has no such moment, because
exponential residuals are memoryless, so the backlog never ages out and only drains. Draining
it costs 351 suppressed packets, which loop cover traffic detects with certainty. Separately,
batching needs a synchronised clock: at one tick of skew a third of batches hold fewer than
three packets and the worst holds none, while continuous time has no round boundary to
disagree about.

**Both mechanisms are load bearing, against different adversaries.** Cover defeats the passive
observer, delay defeats the active one. Neither is redundant, and a passive measurement alone
argues for dropping the wrong one.

**The cost is roughly 200x bandwidth at that duty cycle**, charged continuously to everyone
including everyone who never needed it. That cost is **not a defect to be optimised away**. Das,
Meiser, Mohammadi and Kate prove an anonymity trilemma (IEEE S&P 2018): strong anonymity, low
bandwidth overhead and low latency, choose two. Any roadmap item promising to cut this without
weakening anonymity is promising to refute a theorem.

The two costs buy different things from different adversaries. Cover traffic buys the passive
result and delay does not, as the table above shows. Delay buys the *active* result, where a
batch mix is isolated 51.7% of the time and a Poisson mix 0.7%. The trilemma governs the
bandwidth; the n-1 attack governs the latency. Neither is redundant.

**The patient adversary.** Both results above concern a single message. The long-run attack is
statistical disclosure (Danezis 2003): difference the recipient population across rounds where
a target is sending against rounds where it is not. `karst-mix::intersection` measures it over
4,000 rounds, scoring **attribution**, meaning how much better the adversary does on its target
than on a stranger given identical data:

| Target behaviour | Attribution | Full recall at |
|---|---|---|
| Sends only when it has traffic | **+1.00** | round 500 |
| Constant-rate emission | 0.00 | never |
| Constant rate, joins at round 2,000 | **+1.00** | round 3,000 |

Constant-rate emission removes the attack's input, because the differencing needs absent rounds
and there are none. **Joining is the exception, and everyone joins exactly once.** Arriving
creates precisely the before-and-after boundary the attack needs, and the longer the adversary
watched beforehand the sharper it is. The only complete defence is to have always been there.

**Open.** The device profile is exempt from constant rate cover, because a battery powered
sensor cannot emit continuously, and **exempt devices are therefore not anonymous**. That is a
hole, and it segments the anonymity set, which is exactly the mistake this layer otherwise
avoids. See §6.11.

---

### L5 Membership

*Fixes error 03. Status: sketched.*

**Lever removed.** The list of everyone reachable, and the national block list built from
it.

**Bug fixed.** Tor publishes a signed consensus listing every relay, so a censor downloads
it and blocks all of them. Bridges are the patch, and bridge distribution is unsolved:
enumeration through repeated requests, and active probing where the censor connects to a
suspected bridge to confirm it before blocking. Any global membership list is a block list
waiting to be downloaded.

**Mechanism.** Peers are learned by social introduction at a bounded rate. Each
introduction is attributable, so a peer who leaks their known set can be identified and
cut off. No party holds a roll, so no party can be compelled to produce one.

**Secondary benefit.** Entry is not adversary selectable. In Tor an attacker can volunteer
to be your entry by running relays and waiting; here they must be introduced to you by
someone you already trust.

**Honest assessment.** This does not solve bridge distribution, it moves it into the social
graph and declares the harder case out of scope. It also makes your entry set highly
identifying, mapping directly onto your real social graph, which is worse than a random
guard set if it leaks. See §6.3.

---

### L6 Objects

*Fixes errors 01 and 03. Status: **built** (`karst-object`, `karst-blob`).*

**Lever removed.** The origin server, at its legal address, reachable by process server.

**Bug fixed.** You can ask for a host, never for a thing, so ten million people wanting one
file made ten million separate fetches, and an entire industry grew to paper over it.

**Mechanism.** Content is a signed immutable object named by the hash of its own canonical
encoding. The author's public key travels with the object, so verification needs no
directory, no certificate, and no lookup. Anyone holding it can serve it, so every reader
is a replica and a takedown order has no unique target to name. Identical content has one
address, so replication deduplicates automatically.

**File serving.** What IPFS does, natively. Files split into content addressed chunks under
a merkle manifest, which buys four things at once:

- **Global automatic deduplication.** Identical chunks have identical names, so storing the
  same bytes twice costs nothing, anywhere.
- **Verified random access.** Any chunk verifies against the manifest root with a merkle
  proof logarithmic in file size. A 4 GiB file needs 16 sibling hashes, 512 bytes, to prove
  any 64 KiB chunk. You can seek into the middle of a film and trust what you got without
  trusting whoever served it and without fetching the rest.
- **Every reader is a server**, because the bytes prove themselves.
- **The origin uploads once.** Measured in `karst-blob`: origin egress is flat at 600 KB
  whether the audience is one or ten thousand. That column is the delivery network bill.

**Canonical encoding.** Everything hashed or signed goes through one deterministic, length
prefixed encoding with exactly one valid representation of any value. There is no error
recovery: malformed input is rejected, never heroically repaired. Parser differentials, where
two implementations disagree about what a signed document says, are among the largest
vulnerability classes on today's web and they exist because HTML was specified to recover.
**Rejecting is a security property.**

Enforced rather than asserted. `karst-fuzz` checks four properties against every decoder in the
stack: no input panics, no attacker-supplied length prefix allocates, `decode(encode(v)) == v`,
and **`encode(decode(b)) == b`**. The last is the one that forecloses the differential, because
it means exactly one byte string names each value. Concretely that requires rejecting unknown
tags rather than skipping them, refusing trailing bytes, and requiring record keys to be
strictly increasing, since a permissive decoder would let reordered or duplicated keys build one
map and a node would then have more than one content address. Across 280,000 mutated and random
inputs, 13,006 decode and every one re-encodes to itself.

---

### L7 Streams

*Fixes errors 01 and 04. Status: **built** in structure (`karst-blob`), live append unbuilt.*

**Lever removed.** The delivery network, and the interconnect deals only large publishers
can strike.

**Bug fixed.** HTTP moves documents, so live and large media were rebuilt on top of it
twice as playlists of chunks, fetched across a network engineered to hide the fact that
every fetch is unicast.

**Mechanism.** A stream is a signed append only sequence of content addressed chunks under
one manifest. Subscribers serve each other the instant they hold a chunk, so an origin
emits once regardless of audience size: eighty thousand people watching one match pull it
across the origin's uplink one time.

Renditions are sibling objects under the same manifest, so adaptive bitrate is a client
decision rather than a playlist protocol. The manifest is a merkle structure, so seeking
fetches and independently verifies a byte range. Live and archived are the same object; the
stream simply stops appending.

BitTorrent solved this in 2001 and was ignored because the economics suited nobody selling
bandwidth.

**Open.** Latency for live streams under L4 mixing. `Deferred` is unusable for real time
video, so live either accepts `Prompt` and its weaker guarantee, or accepts tens of seconds
of delay. There is no third option and we should stop looking for one.

---

### L8 Witness

*Fixes error 03. Status: sketched.*

**Lever removed.** A root store of a few hundred certificate authorities across a few dozen
jurisdictions, any one of which can sign anything.

**Bug fixed.** Trust was retrofitted onto a stack that shipped without any, and the retrofit
was a list of companies your browser vendor picked. Tor makes the same mistake in miniature:
around nine or ten directory authorities, hand operated, their keys compiled into the
client. Decentralised except for the part that bootstraps trust is centralised, and a
hardcoded key list in source is a root store by another name.

**Mechanism.** No root store and no default authority set. Keys are witnessed in append only
transparency logs the operator chooses, vouched for by parties they choose. This is
Certificate Transparency generalised past certificates. Two deployments may share no trust
roots at all and still interoperate at every layer below this one.

**Honest assessment.** There being no default means there is no safe out of the box
configuration, which means most people will use whatever their client ships with, which
becomes a de facto authority set anyway. We have moved the problem from the protocol into
the distribution, where it is at least contestable. That is an improvement and not a
solution.

---

### L9 Authority

*Fixes error 02. Status: **built** (`karst-cap`).*

**Lever removed.** Session databases, and the identity providers three companies own.

**Bug fixed.** The cookie. Ambient authority attached automatically to every request is why
cross site request forgery exists, why session theft is fatal, why tracking is the default
rather than an abuse, and why every site had to invent its own login.

**Mechanism.** This is macaroons (Birgisson et al., NDSS 2014) with one deliberate change.
Macaroons chain nested HMACs, which is fast and compact and requires the verifier to share a
secret with the issuer, reintroducing a party who must be consulted, which is error 03. Here
the chain is Ed25519 signatures, so a capability verifies against nothing but itself and the
address of the resource owner: no directory, no authority, no network. We pay in bytes and
verification cost and get a credential that works offline.

A capability is a resource identifier plus a chain of grants. Each grant carries the
issuer's public key, an audience address, a caveat set, and a signature binding it to the
previous link. Verification checks that the first grant came from the resource owner, that
each issuer is the previous audience, that **each link's caveats are at least as strict as
its parent's**, and that every signature holds. The effective authority is the tightest
caveat of each kind across the whole chain.

**The property that matters for agents: a delegation can only ever narrow.** A chain link
that tries to widen is rejected even when every signature in it is individually valid. This
is verified in `karst-cap` and demonstrated in the PoC: an agent signs itself a broader
grant, correctly, and verification refuses it. An API key cannot do this, which is why there
is no API key here.

Nothing to steal in bulk, because there is no central table of sessions. Nothing to correlate
across sites, because nothing reaches a party it was not addressed to.

**Open.** §6.8: capability security is a fifty year old sound theory with unsolved
interaction design, and it is where this most plausibly dies.

---

### L10 Document

*Fixes errors 01, 02 and 03. Status: **built** (`karst-doc`).*

**Lever removed.** The origin, and the DNS name the entire browser security model hangs from.

**Bug fixed.** HTML was a document format hammered into an application runtime, so two
kilobytes of text costs megabytes of script, and the same origin policy makes a domain name
the unit of trust, so one injected script owns everything.

**There is no markup language here.** A document is not text with tags in it. It is a merkle
DAG of typed nodes, each content addressed and independently referenceable. Markup was a
1990s answer to a 1980s problem, getting structure through a byte oriented pipe that only
understood text. The constraint is gone; everything it forced on us is still here.

| HTML's problem | What it causes | KARST |
|---|---|---|
| Text format, recovery based parsing | Parser differentials, enormous spec, markup confusion attacks | One canonical binary encoding, malformed input rejected |
| Stringly typed | Agents scrape and guess | Typed values: a price is `Money`, an instant is `Instant`, a link is a `Cid` |
| Structure entangled with presentation | You write `<div class>` for styling, not meaning | Zero presentation in the document. No classes, no styles, no hooks |
| Only the document is addressable | Hand placed anchors that rot | Every node has a `Cid`. Any paragraph is quotable forever |
| Links point at a location | Link rot | Links are content identifiers and cannot rot |
| Behaviour inline | One injected script owns the page | No behaviour in documents at all |

**Node vocabulary**, closed on purpose: `Prose` (runs of text with emphasis and optional
content references), `Heading`, `List`, `Record` (named typed fields), `Media`, `Quote`
(a reference to an exact version, never a copy), `Section`.

**Three separated things.** Content is a signed structured tree, addressed by hash and
versioned. Presentation is a detached, optional, user overridable sheet keyed by node type
and role rather than by markup hooks. Behaviour is a module in a deny by default sandbox
holding exactly the capabilities it was handed, with no ambient authority to inherit.

**Size is a security property.** The format stays small enough that one competent person can
build a complete client in a season. That is what keeps error 03 from returning as a
rendering engine duopoly, and it is also most of the fingerprint resistance: Tor Browser
exists because a general browser leaks identity through DNS, WebRTC, canvas and font
fingerprinting, plugins, and a long tail nobody catalogued. The fingerprinting surface is
proportional to the size of the platform specification.

**Cost.** §6.6: this is permanently and by design far less capable than a modern browser.

---

### L11 Affordance

*Fixes errors 02 and 03. Status: **built** (`karst-afford`).*

**Lever removed.** API keys, developer terms of service, and the rate limits that decide who
is allowed to build.

**Bug fixed.** Machines were never in the design, so an agent either scrapes pages written
for eyes or you wrap an API in a server in a side protocol. Every wrapper carries its own
authentication, its own documentation, and its own drift away from what the service does.

**Mechanism.** An object declares typed operations alongside its content, in the same signed
structure: inputs, outputs, preconditions, declared cost, and the capability required to
invoke. One representation serves every reader at the resolution it needs. A person sees a
document. An agent sees the operations available and what each will cost **before** committing
to one. A thermostat sees the two it implements.

There is no parallel API surface to drift, no separate key to issue, no wrapper protocol, and
no gate to close, because the capability you already hold is the credential. Closing the API
is not an available move: there is no API, only an object.

**Delegation is attenuation.** You hand an agent *may book one appointment under fifty euros
this week* rather than your account. Every invocation carries its delegation chain, so which
person authorised which machine to do what, within what bound, is answerable from the receipt
rather than inferred from logs. That accountability is something nothing in production today
provides.

**Relation to current agent protocols.** Every one of them, this year's included, is a wrapper
around a web that was never designed for machines. Wrappers are the correct move when you
cannot change the substrate. This is what you would build if you could.

**Cost.** §6.9: a uniform, discoverable, priced action surface is as useful to automated fraud
as to legitimate agents.

---

### L12 Agency

*Fixes error 02. Status: specified.*

**Lever removed.** None directly. This layer is aimed at companies rather than states.

**Bug fixed.** The user agent stopped being an agent for the user. A page commands layout,
autoplay, modal interruption, consent theatre and infinite scroll, and the client obeys.

**Mechanism.** A document *requests* a rendering and the client decides. Presentation, reading
order, motion, execution budget and the right to interrupt belong to whoever holds the device.
A publisher's stylesheet is a suggestion with no privileged standing. Anything that wants to
move, play sound, or take the viewport must hold a capability for it, and the default grant is
none of them.

This also carries fingerprint resistance: a page cannot probe what rendering it received,
because it never had the authority to ask.

---

### L13 Provenance

*Fixes error 01. Status: **built** (`karst-doc` backlinks, `karst-object` lineage).*

**Lever removed.** Making something unattributable by taking the original offline.

**Bug fixed.** Links point one way at a place, so references break when the place moves and you
can never learn who pointed at you.

**Mechanism.** Every object carries a signed authorship chain and an explicit edit lineage. A
quotation is a structural reference to one exact version rather than a copy, so it verifies
against its source and cannot silently drift. References register in the object graph, so
**backlinks exist**: the feature Xanadu had, the web dropped in 1990 for deployability, and
never got back.

Machine generated output carries the same chain as everything else, so what produced a thing is
a field rather than a guess.

**Why this matters more than it sounds.** Backlinks are what make discussion boards possible
without a host. See §5.2.

#### 3.13.1 Human and machine authorship

The requirement is to separate human-created from machine-created content. The honest answer
is that **you cannot verify what produced content, and you should stop trying.** Detection is
an arms race the detector loses, its false positives land on non-native and unusual writers,
and it is a centralised opinion wearing the costume of a fact. Watermarking needs universal
provider cooperation and dies to paraphrase. A proof-of-personhood registry is error 03 in its
purest form and would undo the rest of this document.

What *is* verifiable is who is accountable and what their relationship to production was, and
the stack already has every piece: an agent has its own key (L2) and already acts on
capabilities attenuated from a person (L9). So an object declares its agency class:

| Class | Meaning | Verifiable |
|---|---|---|
| `Direct` | The signing key composed it. | **No, permanently.** |
| `Assisted` | A person composed it with a named tool and signs personally. | No, but their key is on it. |
| `Delegated` | An agent acted under a principal's authority. | **Yes.** The chain must verify to the principal. |
| `Autonomous` | An agent on its own standing. | **Yes**, as to operator. |

You therefore cannot falsely claim to be *authorised by* someone, and you can always falsely
claim to be a person. What the design buys is threefold. A false claim is signed, permanent
under L13's append-only lineage, and retroactively attributable to everything else that key
ever said, so one label operation at L15 handles the cleanup rather than a manual purge.
Standing at L16 does not transfer, so a burned key cannot buy a fresh reputation. And most
usefully, **the incentives point the right way**: only a declared agent can present a
delegation chain, therefore only a declared agent can hold authority and invoke L11
affordances, so a bot pretending to be a person is confined to speech and cannot act. That
property fell out of L9 and was not designed for this.

Where a community needs confidence about people rather than accountability, the answer is
L5's social graph used as attestation: peers vouch, with their own keys, that they know a key
as a person. Plural, local, no registry, and an unattested key is unattested rather than
banned.

Policy belongs at L15, never in the protocol. Boards choose to index only `Direct` from
attested keys, or everything with labels, or only `Delegated` for an agent marketplace. A rule
about who may speak is an opinion, and opinions belong in subscribable views.

Full treatment in [`docs/07-authorship.md`](docs/07-authorship.md), implemented in
`karst-attest`.

#### 3.13.2 Versioning, and whether this replaces the Internet Archive

Objects are immutable, so editing publishes a *new* object carrying `supersedes` pointing at
its predecessor. Every version keeps its own name and signature forever. `Lineage` walks this
both ways: back to the original, forward to the current head.

Two properties today's web cannot offer. **A citation cannot rot**, because a reference is a
hash that resolves from anyone holding that version. **A citation cannot silently change
meaning**, which is the underrated one: today a page is edited under a stable URL and every
citation to it now points at different text with no signal to the reader. Here a quote names an
exact version, so what you cited is what is returned, and `resolve()` separately tells you what
it has since become.

If an author signs two different successors to one version, showing different histories to
different audiences, resolution returns `Forked` rather than picking silently. Silently
choosing is how an author gets away with it.

**Does this remove the need for an Internet Archive? Partly, and the remainder matters.**

It removes the authenticity problem, since an archived version verifies against the author's
key, so a copy from a stranger or a hostile party is exactly as checkable as one from the
archive. It removes the singularity problem, since every reader is already an equal replica and
no single organisation's loss is categorically worse than any other node's.

It does not remove the cost. **Content addressing provides integrity and addressability, never
availability.** If nobody holds a version it is gone, and it is gone whether or not everyone
could have proved what it said. Replication follows attention, so popular content is held by
thousands and the obscure municipal document that matters in one lawsuit eight years later is
held by nobody, which is precisely what an archive exists for. The archival function survives
and changes shape: a deliberate custodian of unpopular things, one among many rather than *the*
one. That is a much better position than the Internet Archive occupies today and it is not the
same as not needing one.

Timestamp attestation, the Wayback Machine's other function, comes from L8 logs witnessing that
a version existed by a given point, plurally, rather than trusting one organisation's clock.

Full treatment in [`docs/10-versioning-and-permanence.md`](docs/10-versioning-and-permanence.md).

---

### L14 Value

*Fixes errors 02 and 03. Status: **built** (`karst-value`); threshold issuance and the earn/spend loop implemented, blind signature not.*

**Lever removed.** Payment processors, and the de-banking that runs through them.

**Bug fixed.** HTTP reserved `402 Payment Required` and never shipped it. With no way to charge
for anything, advertising became the default business model, and surveillance became the default
business model one step after that. This is the most expensive omission in the history of
computing.

**Mechanism.** Settlement is a protocol primitive rather than a bank integration: value is a
signed object that moves the way every other object moves, so there is no processor to lean on.
Reading something can cost a fraction of a cent with no checkout, no account, and no
relationship. An operation declares its price before anyone invokes it (L11).

Advertising is not regulated here, it is made unnecessary, which is the only approach that has
ever worked on anything.

**Secondary benefit.** Relays can be paid by the traffic they carry rather than by a patron.
Tor's development has been heavily funded by US government sources, which is a permanent
adoption cost even where the reality is fine, and a genuine structural dependency.

**Resolution of the L4 conflict.** Acquisition and spending are two acts with opposite
requirements, joined only by habit. Credentials are acquired in the open, rarely, and spent
unlinkably, constantly. The spender's anonymity set is not everyone spending right now, which
would be small and time-correlated; it is **everyone who ever acquired**, which is large and
grows monotonically. This is Coconut (Sonnino et al., NDSS 2019), whose listed applications
include distributing proxies for censorship resistance. Issuance is threshold, so no issuer is
a correlation point or a subpoena target.

**And there is no money.** Capacity is earned by providing capacity: a relay that carries
traffic earns credentials, a client that consumes capacity spends them. The loop closes with
no bank and nothing to de-bank, which is what this layer required. A financial on-ramp is
optional rather than structural.

Denominations are fixed at one unit, because a variable amount is a fingerprint.

**What remains open** is double spending across verifiers that cannot see each other. A
credential is worth one unit *per verifier*, not one in the universe, and closing that needs
either a shared ledger with its consensus cost or an always-online authority. See §6.10 and
[`docs/14-value-and-anonymity.md`](docs/14-value-and-anonymity.md).

---

### L15 Discovery

*Fixes errors 03 and 04. Status: specified.*

**Lever removed.** One search index, and the national delisting and erasure orders served on it.

**Bug fixed.** Publishing does not include announcing, so finding anything required crawling;
crawling costs billions a year; and that cost is the entire moat under the search monopoly.

**Mechanism.** **Publishing an object and indexing it are one operation.** Authoring content
obliges you to emit a signed structured index entry for it, so the expensive half of search,
discovering that a thing exists at all, is done once by the author instead of guessed at
repeatedly by crawlers.

Third parties may publish indexes over anyone. Clients merge whichever indexes they trust and
rank locally against their own criteria, so ranking becomes a personal setting rather than a
company's product. Labels and filters ride the same mechanism, which is how moderation works
(§5.2).

Nobody needs a search engine, because everybody already holds the index. What stays competitive
is ranking quality, which is a small forkable piece of software rather than a decade of crawl
infrastructure and a datacentre.

**Announcement is an obligation of authorship, not of holding.** An author publishes an index
entry for what they wrote. A node that caches or replicates announces nothing. So discovery
covers authored content while replication stays private, and holding something is not
observable.

That distinction comes directly from Tor: in v2 onion services, hidden service directories could
be positioned to harvest descriptors, so the full set of onion addresses was enumerable by anyone
willing to run enough relays. v3 fixed it with blinded keys, so a directory stores a descriptor
it cannot identify. Any lookup infrastructure learns the set of things being looked up unless you
design specifically against it.

**Cost.** §6.7: mandatory announcement still tells everyone what you authored.

---

### L16 Symmetry

*Fixes error 04. Status: **simulated** (`karst-symmetry`); mechanism holds under contention, observation gap confirmed.*

**Lever removed.** Acquisition. Buy the largest operator and inherit its position.

**Bug fixed.** Every protocol so far rewards scale, so decentralised networks recentralise on
schedule and the architecture takes the blame for what the economics did.

**Mechanism.** The layer governing how the other sixteen may be operated. Four mechanics, none of
which require anyone to detect who owns what:

1. **Flat returns.** A node's standing saturates, so a thousand nodes under one owner earn
   exactly what a thousand independent ones do and gain no coordination advantage. Scale stops
   paying rather than being policed.
2. **Standing does not transfer.** It is earned per relationship and decays without use, so it
   cannot be bought, merged, or inherited. Acquiring an operator buys hardware and staff, never
   position.
3. **No privileged client.** The protocol admits no capability available only to large operators:
   no bulk endpoint, no rate limit exemption, no preferential peering. Today one company may crawl
   you while you may not crawl it, and that asymmetry is the moat. Here it is specification level
   illegal.
4. **Zero switching cost by construction.** Identity is your key, content is its own name, your
   graph is an object you hold. There is no surface to be locked into, which is the only thing that
   has ever actually stopped a network effect hardening into a monopoly.

**Sybil defence.** This is also the structural answer to a problem Tor handles manually. The KAX17
operator ran over 900 relays against a network of roughly 9,000 to 10,000, from 2017 until removal
in late 2021, across more than fifty autonomous systems, giving users up to a 16% chance of a
hostile guard and 35% of a hostile middle relay. It was caught by a small number of people looking
carefully at metadata over a period of years. Vigilance does not scale and does not survive the
departure of the people providing it.

Under L16 a fresh Sybil fleet starts at zero standing and cannot buy its way up. That constrains an
adversary who wants to be *trusted* and does nothing about one who only wants to be *present*, which
is what KAX17 was. The defence against presence is L5 admission, not L16 standing.

**Simulated results.** `karst-symmetry` puts a 200-node operator against forty five-node operators
under contention, for 800 rounds.

| | Standing per node | Traffic share | Compounding |
|---|---|---|---|
| Linear returns | 1.06 and rising | 50.8% | grows |
| **Flat returns** | **1.00** | 50.1% | flat |

Claims 1 and 2 hold. Standing per node stays between 1.00 and 1.01 across a 90% to 99.9% uptime
range, because a ceiling is a ceiling however often you reach it, so buying reliability does not
route around it. Reliability buys a few points of traffic share, proportional to being available to
be chosen, and does not compound. Acquisition transfers machines and not position.

**The hole is observation, and it is not small.** An adversary who wants to watch rather than be
trusted is untouched by every rule above, because path coverage tracks node count and there is no
reputation involved to saturate:

| Fleet | Paths touched | Both endpoints held |
|---|---|---|
| 900 of 9,500 (KAX17 scale) | 25.8% | 0.90% |
| 1,800 of 9,500 | 46.8% | 3.59% |
| 3,000 of 9,500 | 68.0% | 9.97% |

KAX17 ran that first line against Tor for four years and would have been exactly as effective under
every rule tested here.

**L16 raises the cost of buying position and does nothing about buying presence.** That is a real
defence against acquisition and no defence at all against surveillance, which is L4's job. L16 does
not prevent capture in general. See §6.6.

---

## 4. Profiles

One stack, three readers, no translation layer between them. They differ only in how far up they
bother to go. Nothing is wrapped, adapted, or bridged, because there is no second protocol to
bridge to.

| | Person | Agent | Device |
|---|---|---|---|
| Layers | all 17 | all except L12 | L0, L2, L3, L6, L8, L9, L11 |
| Role | reads, publishes, decides, pays | invokes, pays, stays accountable | senses, actuates, outlives its vendor |
| Anonymity | full, `Deferred` by default | full | **exempt from cover traffic, therefore not anonymous** |

**Person.** The full stack. L12 is theirs alone: only a human needs the right to refuse a
rendering. Holds the root capabilities everything else is attenuated from, and ranks their own feed
at L15 rather than receiving somebody's product.

**Agent.** Reads the same object a person does and sees L11's typed operations, preconditions and
prices before committing. Runs on attenuated capabilities with a spend cap, so its blast radius is
bounded by construction rather than by prompt. Every action carries the delegation chain back to
the human who authorised it. Never scrapes, because the machine surface is the surface.

**Device.** Seven layers, small enough for a microcontroller. Its identity is its key, so there is
no vendor account and no phone home: it works on a dark LAN with no internet and keeps working
after the vendor is acquired, pivots, or dies. Actuation requires a capability rather than merely a
packet from the right subnet, which is the entire reason consumer IoT is a security disaster.
Firmware is a content addressed object with signed lineage, so owning the distribution path buys an
attacker nothing without the author's key.

---

## 5. Applications

Neither of the following is a layer. Both fall out of layers that exist for other reasons, and
between them they need exactly two new primitives. That they need so little is the strongest
available argument that the lower stack is shaped correctly. Had native messaging required a
messaging layer, the object and mixing layers would be wrong.

### 5.1 Messaging

| Need | Provided by |
|---|---|
| Addressing | L2. A recipient is a public key. No account, no server, no handle to lose. |
| Confidentiality | L2 and L9. Ephemeral session keys, long term identity never on the wire. |
| **Metadata privacy** | L4. The hard part. Who talks to whom, when, and how often carry no signal. |
| Offline delivery | L0 and L6. A message to an offline recipient is an object the network holds. |
| Attachments, voice | L6 and L7. An attachment is an object; a voice note is a short stream. |
| Groups | L6 and L13. A group is an object listing member keys, with signed membership changes forming an auditable lineage. |

Metadata is what every messenger gets wrong. Signal has excellent message confidentiality and still
knows who connects and when, because it is a server. Removing that observation is the reason to
build messaging here rather than on Signal.

**New primitive: blinded drops.** Storing a message at "the recipient's address" fails immediately,
because the holder learns who it is for and the fetcher identifies themselves. Instead, sender and
recipient derive a shared secret from their keys and a counter, and the message is stored at an
address derived from that secret. The holder sees an opaque address and an encrypted blob and learns
nothing about either party. The recipient computes the same addresses and polls them, invisibly,
because L4 already has them emitting at a constant rate.

*Cost:* the candidate address set grows with how long the recipient has been offline, and the drop
set is a correlation surface if the shared secret leaks.

### 5.2 Discussion boards

Forums are centralised today for one missing feature: a link points one way. Given a post there is no
way to find what replied to it, so somebody keeps the list, and whoever keeps the list owns the
community. L13 already fixed this for unrelated reasons.

**New primitive: conversation objects.** A post is an ordinary signed object with a body and an
optional structural reference to a parent. That is the entire data model. Everything else is derived:

- **A thread** is the transitive closure of backlinks from a root post, computed by the reader rather
  than stored by anyone. Nobody hosts it, so nobody can delete it.
- **A board** is an index (L15) over posts matching whatever its curator likes. Anyone may publish a
  competing board over identical posts.
- **Moderation** is a label set you subscribe to. Two people reading the same board with different
  subscriptions see different boards, and both are correct.
- **Ranking** is local, computed by your client from signals you chose.

**A board is a view, not a place.** There is no server to seize, no company to acquire, no admin who
owns the archive. If a curator becomes hostile, someone republishes the index without them and the
community moves by changing a subscription. The posts never moved, because they were never anywhere.
This is verified in `karst-thread`.

*Costs:* nothing can be deleted, only unlisted, and the tombstone is shown rather than hidden. Thread
assembly moves work to the reader. Posting is cheap and identities are free, so an uncurated board
drowns, and boards will recentralise around good curators, which is §6.6 arriving early.

---

## 6. What it costs

A design that lists only its properties is a manifesto. These are the eleven things genuinely worse
under this architecture. None has a clever fix hiding behind it.

**6.1 Nothing can ever be taken down. Not one thing.** Content addressing plus universal re-serving
means child sexual abuse material, intimate images published without consent, doxxes, and live
streamed atrocity are exactly as permanent as everything else. L15 filters reduce how far something
travels and do nothing about whether it exists. No host has a plug to pull and no key destroys it.
Any version of this design claiming otherwise is lying about how content addressing works. This is
the largest cost, it is unavoidable given the constraints, and the constraints are the requirements.

**6.2 The ground it runs on is still theirs.** No protocol defeats a backhoe or a raid on a
transmitter. L0 buys graceful degradation, not immunity. That is genuinely valuable and a great deal
less than ungovernable.

**6.3 Not enumerable also means not open.** L5 costs the single best property v1 ever had: a stranger
can just connect. Growth becomes bounded by social introduction, so the network inherits the shape of
existing social access including everybody already outside it. Your entry set also maps onto your real
social graph, so compromise of a socially close peer hurts more here than in Tor.

**6.4 The endpoint and the app store beat every layer above them.** Compelled unlock, implants, or
taking the phone. Two companies decide what software runs on most of the world's pocket computers, and
pulling a client from both stores is a routine order.

**6.5 Ungovernable is symmetric and cannot be aimed.** The properties defeating a censor equally defeat
a fraud investigation, a sanctions regime, a court order for a stalker's logs, and a product recall. No
chokepoint opens only for good reasons, because a chokepoint that opens selectively is a chokepoint with
better marketing. This is an engineering fact rather than an ethical objection, and it is not small.

**6.6 Flat returns costs real efficiency, and defends against only half the threat.** L16 deliberately
prevents an operator who is genuinely better at running infrastructure from serving proportionally more,
so the network will be slower, less reliable and more expensive per byte than a well run centralised one.
That is the trade: pluralism bought with efficiency, paid every day forever.

On the mechanism itself, simulation (§3, L16) is good: a per-node ceiling holds under contention, stops
an initial advantage compounding, and is not routed around by buying uptime. What it does **not** touch
is observation. An adversary who wants to watch rather than be trusted buys path coverage with node
count alone, with no ceiling, because no reputation is involved to saturate. A KAX17-sized fleet touches
a quarter of all paths under every rule tested.

So L16 raises the cost of buying position and does nothing about buying presence. Surveillance is
L4's problem. What remains unproven is whether the ceiling survives the channels the simulation does
not model: convenience, defaults, bundling, and simply being the operator everybody has heard of.

**6.7 Mandatory indexes tell everyone what you authored.** L15 kills the search monopoly by making
publication and announcement one act, and the direct consequence is that authorship is observable. The
authorship-not-holding split protects replication and does nothing for the author. Publishing under
rotating pseudonymous keys is the mitigation, and it costs you all accumulated reputation.

**6.8 Capability security is a usability problem nobody has solved at scale.** L9 and L12 are correct
and are where this most plausibly dies. Every consumer facing attempt at explicit authority has drowned
people in grant prompts until they clicked through reflexively, which is strictly worse than ambient
authority because it launders the same outcome through consent. The theory is fifty years old and sound;
the interaction design is unsolved and is not a small job left as an exercise.

**6.9 A machine actionable priced surface is a machine actionable target.** L11 makes every capability
legible and invocable, which is as useful to automated fraud as to legitimate agents, and L14 puts money
behind it. Attenuation and spend caps bound each individual compromise, which is real, but the volume of
attempted abuse against a uniform discoverable priced action surface will exceed anything the scraping
era produced.

**6.10 A credential is worth one unit per verifier, not one in the universe.** The L14 and L4
conflict resolves by separating acquisition from spending, so this is no longer the stack's largest
open problem. What it leaves is double spending: a serial spent twice at one verifier is caught, and
two verifiers that cannot see each other both accept the same credential. Closing that requires a
shared ledger with its consensus cost, or short epochs that bound the damage, or accepting that each
relay honours a credential once. The same limit applies to L9's use counts, for the same reason, and
in both cases the design has to pick an option rather than imply the problem is solved.

**6.11a Joining the network is observable, and everyone does it once.** Constant-rate cover
protects a participant and not the act of becoming one. An adversary who was already watching
gets the absent-population baseline that statistical disclosure needs, and half an observation
window of it is enough for full attribution. Joining before you need the network helps and
costs the full bandwidth rate from that moment; joining in cohorts helps and needs coordination
the design deliberately lacks.

There is a known research direction and no deployed solution. Membership-concealing overlay
networks (Vasserman et al., CCS 2009) hide who is participating at all, so the differencing
boundary does not exist rather than being padded over. L5 already conceals membership from a
*directory*; what remains is concealing it from a *network observer*, which is an unfinished
research problem rather than an engineering task. See
[`docs/15-fundamental-limits.md`](docs/15-fundamental-limits.md).

**6.11 Constrained devices are exempt from cover traffic and are therefore not anonymous.** A battery
powered sensor cannot emit continuously. The exemption is honest and it segments the anonymity set,
which is precisely the failure mode L4 exists to avoid. We do not have a good answer.

**6.12 A claim of human authorship is unfalsifiable, and the field invites exclusion.** §3.13.1 makes
delegation checkable and leaves `Direct` a bare assertion, permanently. If your threat model is a
well-resourced actor flooding a board with content claiming to be human, this design does not stop
them; it makes cleanup one label operation after exposure. Separately, a machine-readable authorship
field makes it trivial to build venues excluding assistive tools, which will land on disabled users and
non-native speakers first, and the protocol cannot prevent that because the policy layer is the point.
The categories are also dissolving: a person editing model output, a model drafting and a person
signing, an agent under standing instructions written months ago. `Assisted` is one word over a
growing range and any taxonomy here has a shelf life.

### Unsolved

**Send cost.** Spam, credential stuffing and reflection floods are businesses built on sending being
free, so unsolicited contact must cost something. It cannot cost money, because a payment rail is a
chokepoint. That leaves memory hard proof of work, which taxes old hardware and subsidises botnets with
processor time to spare, or socially issued allowances, which put L5's access problem in charge of who
may speak. Neither is good enough.

**Names people can use.** Hash of key addresses are unreadable, so a petname layer is mandatory, and
every petname layer in recorded history has recentralised into a registry. Expect one within five years
wearing a false moustache, and expect it to become singleton number seven.

---

## 7. Prior art

Almost none of this is new, which is the interesting part. Full citations in
[`docs/09-references.md`](docs/09-references.md).

| Layer | Prior art |
|---|---|
| L1 Path | SCION (ETH Zurich), carrying production traffic |
| L2 Identity | HIP (RFC 7401), ILNP (RFC 6740) |
| L3 Wire | obfs4 and twenty years of pluggable transports |
| L4 Mixing | Loopix (USENIX Security 2017), Sphinx (IEEE S&P 2009) |
| L6 Objects | IPFS, Named Data Networking |
| L7 Streams | BitTorrent, Hypercore |
| L8 Witness | Certificate Transparency, generalised |
| L9 Authority | Macaroons (NDSS 2014); KeyKOS, E, Capsicum |
| L13 Provenance | Xanadu |
| L15 Discovery | Tor v3 blinded descriptors; Bluesky labels |
| L0 Bearer | Bundle Protocol (RFC 9171) |

**Genuinely new, and therefore genuinely unproven:** L16's flat returns, L15 making publication and
indexing one operation, L11 putting the machine surface inside the document, L13.1 deriving authorship
agency from the capability chain rather than from detection, and the four error framing itself. The framing is a way of organising known problems rather than a result. It is useful if it
predicts where the next chokepoint appears, and so far it has only been used to explain ones that
already exist.

**Why the assembly does not exist, and it is not technical.** Each flaw is load bearing for somebody's
revenue: delivery networks sell the absence of caching, certificate authorities sell the absence of
trust, clouds sell the absence of mobility, scrubbing centres sell the absence of a send cost, app
stores sell the absence of user agency, and the entire advertising economy sells the absence of 402.

---

## 8. Status

See [`docs/08-roadmap.md`](docs/08-roadmap.md) for phases and open issues.

| Layer | Status | Crate |
|---|---|---|
| L2 Identity | built, tested | `karst-id` |
| L6 Objects | built, tested | `karst-object`, `karst-blob` |
| L7 Streams | structure built, live append open | `karst-blob` |
| L9 Authority | built, tested | `karst-cap` |
| L10 Document | built, tested | `karst-doc` |
| L11 Affordance | built, tested | `karst-afford` |
| L13 Provenance | built, tested | `karst-doc`, `karst-object` |
| L13.1 Authorship agency | built, tested | `karst-attest` |
| L13.2 Version lineage | built, tested | `karst-object` |
| Boards, threads | built, tested | `karst-thread` |
| L4 Mixing | specified, unbuilt | none |
| L12 Agency, L15 Discovery | specified, unbuilt | none |
| L0, L1, L3, L5, L8, L14, L16 | sketched | none |

**Nothing above L4 is private until L4 exists.** Everything currently built assumes a network that
does not yet protect who is talking to whom. That is the single most important thing to understand
about the current state of this repository.

---

## 9. Deployment

**Devices first**, not because it is exciting: it is seven layers, fits a microcontroller, has no
entrenched incumbent, and sells itself in one sentence, which is that the thing keeps working after
the company that made it goes away. Every other profile is easier to argue for once that one is boring
and deployed.

**Media second**, because L6 and L7 delete the delivery bill outright and that is a number a finance
department understands without believing a word of §1.

**Documents and agents last**, because that is where the incumbents live.

Throughout, everything above L2 runs over UDP on whatever port is open, with a wire image resembling
whatever is locally ordinary. L1 native paths exist only between consenting relays and tunnel
everywhere else. L0 plurality arrives last and only where needed, because mesh hardware follows
shutdowns rather than anticipating them.

The upper half cannot be a browser extension, because the whole point of L9 through L12 is that the
browser's security model is the bug. It is a separate client, which is a far higher adoption barrier
and the honest price of not inheriting the cookie.

### What actually kills it

Not a ban. A ban is the design input. What kills it is one client implementation everybody runs, one
label set everybody subscribes to, one index everybody merges, one agent runtime everybody builds
against, and one relay operator carrying sixty percent of traffic from a building with a street address.

L16 exists specifically to make that harder and it is the least proven thing in this document. If L16
does not hold, nothing else here matters, because the failure will not be a seizure. It will be an
acquisition.
