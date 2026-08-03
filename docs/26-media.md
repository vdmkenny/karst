# 26 — Media

Everything before this layer is small. A document is kilobytes, an index entry is bytes, a
message fits in one packet. Media is not small, and the difference is not a matter of degree.

---

## The measurement that decides the design

`cargo run --release -p karst-net --bin karst-bulkcost`

A client emits fixed-size packets at a constant rate whether or not it has anything to say.
That is what makes its traffic unreadable and it is equally a hard ceiling on how much it can
say. Each 1024-byte datagram carries 709 bytes of message.

| | 20/s | 60/s | 250/s | 1000/s |
|---|---|---|---|---|
| goodput | 13.8 KB/s | 41.5 KB/s | 173 KB/s | 692 KB/s |
| a photograph | 4.9min | 1.6min | 24s | 6s |
| a podcast episode | 73.9min | 24.6min | 5.9min | 89s |
| **an hour of video** | 31.6h | **10.5h** | 2.5h | 37.9min |
| a film | 7.0d | 2.3d | 13.5h | 3.4h |

The last two rows are the whole story. Raising the rate until video fits multiplies the constant
cost for **every** client, including the ones who only send text, because constant-rate emission
does not become cheaper when a client is idle. There is no rate at which bulk media is
comfortable and cover traffic is affordable.

This is not an implementation problem, and no amount of engineering removes it. Das, Meiser,
Mohammadi and Kate (*Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead, Low Latency —
Choose Two*, IEEE S&P 2018) prove the shape of it. Constant-rate emission is this design
choosing strong anonymity and low latency, and paying in bandwidth.

For calibration against a real system: Loopix's measurement section says bandwidth "increases
linearly until it reaches around **225 messages per second**", after which "the performance of
the mix node stabilizes and we observe a much smaller growth". The abstract separately says a
relay handles "upwards of 300 messages per second".

A previous version of this document called 300 "the saturated ceiling" and 225 the end of
linear scaling. **The first half of that is wrong.** The paper states no saturated ceiling; 300
appears only in the abstract, and "upwards of" makes it a lower bound rather than a cap.
Quoting it as a ceiling reverses its direction. 225 is right, and the paper describes it as
where linear growth ends rather than as a hard limit.

The measured topology matters too, and is easy to take from the wrong experiment: the
throughput and latency numbers come from **six mix nodes in three layers of two**, not the
three-by-three topology used in the security simulation.

That is a **node's** aggregate across all its clients, not one client's goodput, which is the
number in the table above.

---

## So the split, and the asymmetry that makes it safe

Bulk moves another way, and the exposure is written down rather than hoped away.

A manifest is signed and names every chunk by content address, so a chunk fetched over **any**
path is checked against the manifest's merkle tree.

> **Integrity survives the exposed path. Privacy does not.**

A hostile bulk carrier can refuse to serve, serve slowly, or serve garbage that is detected
immediately. It cannot substitute. That is why carriage is a **privacy** decision rather than a
trust one, and why the reader makes it per fetch instead of the publisher fixing it.

`Exposure` states what each carriage reveals as four separate facts rather than one word:
reader address, content requested, volume and timing, and ability to substitute. The last is
false for both, and saying so explicitly is the point.

### "Volume and timing" is far too mild a phrase

It means **which film**. Reed and Kranch (*Identifying HTTPS-Protected Netflix Videos in
Real-Time*, CODASPY 2017) built a fingerprint database of 42,027 Netflix titles and report
differentiating between videos with "greater than 99.99% accuracy", identifying **199 of 200**
test streams, most within two and a half minutes, using **only TCP/IP header information** and
no payload at all. Variable-bitrate encoding makes each DASH segment's size content-dependent,
so the sequence of segment sizes is the fingerprint and encryption does not touch it.

Schuster, Shmatikov and Tromer (*Beauty and the Burst*, USENIX Security 2017) show the same
attack does not even need an on-path observer: a JavaScript advertisement running on a nearby
machine suffices.

So a reader choosing `Direct` for a film is not revealing "some bytes moved". They are
revealing the title, to anyone on the path, at better than 99% accuracy. `Exposure` says
`content_requested` and `volume_and_timing` are both true for direct carriage, and this is what
those two words are worth together.

---

## Two things made structural rather than advisory

**The manifest never crosses the exposed path**, whatever it costs, because it names everything
else. A reader who fetches it directly has told the carrier which work they are about to read,
and being careful with the chunks afterwards does not undo that. The test holds even when the
threshold is set to zero.

**A plan reports what the private path would have cost**, measured against total bytes rather
than exposed ones. Measuring the exposed part reported zero to exactly the reader who chose
privacy — the one reader who most needs to know the price of that choice. A design that makes
exposure convenient while hiding the cost of avoiding it has decided for the reader while
appearing to offer them a choice.

---

## The publisher was choosing the reader's exposure

A per-chunk size threshold looks like a reader's policy and is not one, because **chunk size is
the publisher's choice**. Chunk a film one byte over a reader's limit and every reader must use
the exposed path to read it at all; chunk it one byte under and every reader spends ten hours
pulling it through the mix network. Either way the reader's stated preference has been
overridden by someone else's encoding decision.

A policy has to be expressed in quantities the publisher does not control:

| | Publisher-influenced | Binds |
|---|---|---|
| `mixed_limit` | yes, chunk size is theirs | advisory only |
| `exposure_budget` | no | total bytes exposed |
| `never_expose` | no | absolutely |

Chunks beyond the budget go **back onto the mix network** rather than being refused, so a
publisher cannot make content unreadable by chunking it past a limit. They can make it slow,
which is a cost the reader sees in advance.

---

## Bulk must never share a path with careful traffic

Le Blond, Manils, Chaabane, Kaafar, Castelluccia, Legout and Dabbous (*One Bad Apple Spoils the
Bunch*, LEET 2011) ran six instrumented Tor exit nodes for 23 days and revealed **10,000 IP
addresses** of Tor users, which they describe as the largest attack on Tor by that measure.

The mechanism is the part that matters here, and it is not really about BitTorrent. Tor
multiplexes several TCP streams from one source onto a single circuit, so **deanonymising any
one stream links every other stream sharing that circuit**. They used BitTorrent as the
insecure application because it leaks an IP directly, and then harvested everything travelling
beside it: 193% additional streams on top of the BitTorrent baseline, including **27% of HTTP
streams possibly originating from "secure" browsers**. BitTorrent was over 40% of Tor's traffic
by volume at the time.

That is the strongest argument for the split in this document, and it is stronger than the
bandwidth argument. Bulk is not merely too big for the mix network. **Bulk sharing a path with
careful traffic destroys the careful traffic**, because the bulk is what gets deanonymised
first and everything beside it comes along.

The design keeps them apart structurally rather than by advice. Fragments already take
independent routes, so no single node sees a whole message's timing, and `Carriage::Direct` is
a different transport entirely rather than another circuit on the same one. There is no
arrangement in which a film and a private message share a path.

---

## Deduplication and unlinkability are opposed, and this takes deduplication

A chunk's content address is identical for every reader and every publisher. That is exactly
what makes storage efficient, and equally what makes a chunk identifier a **durable
fingerprint**: an adversary who once learns that a chunk belongs to some work knows it for every
reader who ever fetches it, for as long as the work exists.

The test asserts it rather than the prose merely mentioning it: two publishers of the same film,
under different names, produce identical chunk addresses.

This is a property of the design and it is not a bug that a later version fixes. Randomising
chunk content per reader would break the property, and would break deduplication with it. The
choice is real and this is the side it takes.

The adjacent published result is Harnik, Pinkas and Shulman-Peleg (*Side Channels in Cloud
Services: Deduplication in Cloud Storage*, IEEE Security & Privacy 8(6), 2010), where a client
learns whether content already exists on a server from whether their upload is skipped. It needs
**source-based deduplication across users**, and this design does not do that: a provider stores
what it is given and no upload is ever skipped on the basis of what someone else uploaded. So
that particular channel is absent here, and the fingerprint above is a different one, arising
from address stability rather than from upload behaviour.

---

## What is not built

- **Nothing carries bulk yet.** `Carriage`, `Exposure` and `Policy` decide and account; no
  direct transport exists, and the demo does not move a film.
- **Swarm delivery is not connected.** `karst-blob::Swarm` measures amplification in a
  simulation and no reader re-serves a chunk to another reader over the real network.
- **Chunks are not encrypted.** A bulk carrier reads what it carries. For content published to
  a public feed that is intended; for anything else it is not, and there is no mechanism.
- **Range requests over the network.** `Manifest::chunks_for_range` exists and nothing calls it,
  so seeking within media is arithmetic rather than a capability.

---

## What is still uncited

Two narrower claims, kept separate from the verified ones above.

- **Video identification through a VPN.** The HTTPS and remote-observer cases are verified. No
  peer-reviewed evaluation of the same attack *through a VPN tunnel* was found, so nothing here
  claims it.
- **Video identification over Tor.** A 2025 journal paper on the subject appears to exist, and
  its reported accuracy figures could not be confirmed from the paper itself. No number from it
  is used.

---

## References

- Das, Meiser, Mohammadi, Kate. *Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead,
  Low Latency — Choose Two.* IEEE S&P 2018.
- Piotrowska, Hayes, Elahi, Meiser, Danezis. *The Loopix Anonymity System.* USENIX Security
  2017, pp. 1199-1216.
- Le Blond, Manils, Chaabane, Kaafar, Castelluccia, Legout, Dabbous. *One Bad Apple Spoils the
  Bunch: Exploiting P2P Applications to Trace and Profile Tor Users.* LEET 2011.
- Reed, Kranch. *Identifying HTTPS-Protected Netflix Videos in Real-Time.* CODASPY 2017,
  pp. 361-368.
- Schuster, Shmatikov, Tromer. *Beauty and the Burst: Remote Identification of Encrypted Video
  Streams.* USENIX Security 2017.
- Harnik, Pinkas, Shulman-Peleg. *Side Channels in Cloud Services: Deduplication in Cloud
  Storage.* IEEE Security & Privacy 8(6):40-47, 2010.
- `docs/15-fundamental-limits.md`, for what the trilemma costs elsewhere in this design.
- `docs/21-a-running-network.md`, for where the constant-rate emission comes from.
