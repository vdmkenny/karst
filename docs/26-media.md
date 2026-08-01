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

For calibration against a real system: Loopix reports over 300 messages per second per **mix
node**, under 1.5 ms of node-added delay, and end-to-end latency in the order of seconds
(Piotrowska, Hayes, Elahi, Meiser, Danezis, USENIX Security 2017). That is a node's aggregate
across all its clients, not one client's goodput, which is the number in the table above.

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

## Claims I wanted to make and could not verify

Recorded because leaving them out silently would be the same as never having tried, and stating
them without a citation would be worse.

- **BitTorrent over Tor deanonymises its users.** I believe there is a LEET 2011 paper by Le
  Blond and colleagues on tracing Tor users through P2P applications. **Unverified**, so the
  swarm section above claims nothing about whether peer-to-peer delivery is safe here.
- **Deduplication is a published side channel.** A client learning whether content already
  exists from whether an upload is skipped is, I believe, in the literature. **Unverified**, so
  the section above rests on the property demonstrated in this repo's own test rather than on
  anyone else's result.
- **Encrypted video streams are fingerprintable by bitrate.** Widely believed and I could not
  confirm a specific paper or accuracy figure. **Unverified**, and no claim above depends on it.

Verification was interrupted rather than attempted and abandoned. These are open, not settled.

---

## References

- Das, Meiser, Mohammadi, Kate. *Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead,
  Low Latency — Choose Two.* IEEE S&P 2018.
- Piotrowska, Hayes, Elahi, Meiser, Danezis. *The Loopix Anonymity System.* USENIX Security 2017.
- `docs/15-fundamental-limits.md`, for what the trilemma costs elsewhere in this design.
- `docs/21-a-running-network.md`, for where the constant-rate emission comes from.
