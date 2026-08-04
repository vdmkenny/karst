# 24 — Composing the stack

Every layer worked and none of them touched. L6 objects could not leave the process that made
them, L15 announcements were structs in memory, and the running network at L3/L4 carried opaque
bytes between two clients who already knew each other.

`cargo run --release -p karst-stack --bin karst-stack-demo` closes that. Alice writes a
document, publishes it to a feed, and Bob reads it knowing nothing but her address, over seven
mixes on real sockets.

---

## Objects had no wire form

`Object` had no encoding. It could be created, signed and verified, and never sent anywhere,
which is a strange thing for the unit of content in a network to be.

The encoding is the same canonical form everything else uses: length-prefixed, deterministic,
refusing rather than repairing. Two properties are asserted rather than assumed. Encoding is
**idempotent**, so a publisher emitting the same object twice emits the same bytes and anyone
diffing what they published sees no spurious change. And decoding **does not verify**, because
verification is a separate decision a caller makes with a key in hand, and folding them together
would make it possible to hold an object nobody ever checked.

That separation is what L6 is for. **Provenance rides with the object rather than with the
connection**, so an object learned from an adversary is exactly as trustworthy as one learned
from its author, and the demo's mixes and provider could have altered nothing.

---

## Publishing is not sending, and needs a different envelope

A mailbox tag is 32 secret random bytes handed to correspondents, and its **secrecy** is what
stops a stranger flooding a box they were never told about.

A feed cannot work that way. The point of publishing is that people who have never met you can
read you, so the tag must be derivable from your address alone:

```text
feed_tag(publisher, epoch) = blake3("karst.net.v1.feed" || address || epoch)
```

That makes a feed box public, readable and floodable. Each needs an answer.

### Readable is intended

Content published for the world is content the provider holding it can read. Encrypting it to a
key everybody has would be theatre. What stays hidden is **who published it**, which is L4's
job, and **who reads it**, which is not solved and is #53.

So the envelope grew a kind byte, and the two kinds are exactly the same width:

| | Body | Provider can read | Padding authenticated |
|---|---|---|---|
| `ENV_SEALED` | HPKE-sealed fragment | no | yes, inside the seal |
| `ENV_OPEN` | plaintext fragment plus random padding | yes | **no** |

Open padding is malleable: a relay can alter it without detection. It carries no content and
changes no outcome, so what it offers is a covert channel between parties who are already
relaying for each other and have better ones. In a sealed envelope the same bits are inside the
seal, because there they would be a channel out of somebody's private mail.

### Floodable buys denial, never substitution

Anyone can compute a feed tag and deposit into it. They cannot forge content, because a
subscriber verifies every object against the publisher's key and discards the rest.

The test for this is worth stating precisely, because the first version of it did not test
anything: it had the impostor publishing to **their own** feed tag rather than the victim's, so
no flood ever reached the box under attack. The real test deposits valid objects signed by
someone else, and unparseable junk, directly into the victim's box, and asserts the reader
yields exactly one thing.

Denial is real and is not fixed. A full box refuses genuine deposits, and a publisher's
publications are lost. It is **visible**: the refusal count travels in the collection response,
so a subscriber sees that a feed lost deposits and a publisher watching their own feed sees it
too. That is weaker than prevention, and the mechanism that would prevent it is named rather
than gestured at: per-fragment authorisation, so a provider can refuse a deposit into a feed it
is not signed for, at 64 bytes per fragment.

That claim was **false when first written**, and the way it was false is the interesting part.
The count was computed and then dropped; the collection response had no field for it; and
handing back one item emptied the box and re-deposited the remainder, which recreated the entry
through `or_default()` and reset the count to zero. The entire justification for making feed
tags public rested on a number nobody could read. Reading no longer dismantles a box, and the
count is on the wire.

---

## Adding a kind byte opened the private inbox

The worst defect in this work was created by it. `Client::accept` dispatched on the envelope's
kind byte, and once `ENV_OPEN` existed that branch was reachable from a client's **own
mailbox** — so anything that could write bytes into the box could put chosen content into the
application's inbox with no key, no seal and no signature. A hostile provider is exactly such a
party, and so is anyone who can land a datagram on the collect port.

The test that claimed to cover this missed it by one bit. It flipped `0x40` in a genuine sealed
envelope, turning `ENV_SEALED` (1) into `0x41`, which falls through to the reject arm. It never
tried `1 ^ 0x03 = 2`.

There is now no dispatch on an attacker-controlled byte at all. The mailbox path takes sealed
only, feeds have their own entry point, and a test sweeps **every one of the 256 kind values**
rather than the one the author happened to think of.

The general lesson is not "check the kind byte". It is that **adding a case to a shared
dispatch changes every caller of that dispatch**, including the ones whose security argument
assumed the old set of cases.

## Reading and draining are different rights

Collection required only the tag, and the tag is what a sender needs in order to deposit. So
every correspondent could permanently delete the mail they had sent, and because a feed tag is
computable from a public address, **any stranger could delete any publication with one 32-byte
datagram**. Read access and delete access were the same capability.

They are separate now:

| | Deposit needs | Collect needs | Removes on read |
|---|---|---|---|
| Mailbox | the tag | a signature under the drain key, whose hash is the tag | yes |
| Feed | the tag | the publisher's address and epoch, which anyone can derive | **no** |

A read names a feed by preimage rather than by tag, so the provider derives the tag itself and
the readable keyspace is exactly the image of the feed derivation. A mailbox tag is not secret,
it ships in every contact, so this is what keeps a correspondent from reading the box it was
given the right to deposit into.

A mailbox tag is the hash of a collection key its owner keeps and never puts in a `Contact`, so
holding the tag lets you write and not drain. A feed has no such key, because its tag is public
by construction, so feed reads are non-destructive and served by cursor. Content published for
everyone has no confidentiality reason to vanish when one reader takes it.

## Two buffers, and an eviction order the adversary was choosing

A `Client` held one `Reassembler` fed by sealed mail, every feed, and whatever a provider chose
to hand back. Fragments are keyed only by a 16-byte message id the **sender** picks, so a flood
into a world-writable feed box could occupy and evict state belonging to private mail. The
secrecy of a mailbox tag stopped being what gated reach into a client's reassembly.

Each `FeedReader` now has its own buffer, and sealed mail keeps its own.

Eviction was worse than shared. The comment said oldest-first; the code took
`partial.keys().next()`, which on a map keyed by message id is the numerically **smallest** id,
and the id is chosen by whoever sent the fragment. Send high ids and your entries outlive
everyone else's. That is the same defect as evicting by content address at L15 — an ordering an
adversary can compute is an ordering an adversary controls — in a different module, found the
same way, one week apart. Entries now carry an arrival counter and eviction is genuinely by age.

## A defence that matches its exposure

The two tag kinds get different treatment, and the reason is not arbitrary:

> **A secret tag needs no authentication because it is unguessable. A public tag needs it
> because it is not.**

Private mail is opaque to a provider and unauthenticated at deposit, bounded by per-box caps and
protected by the tag nobody else knows. Public feeds are readable and must be authenticated by
the *reader*, because the tag protects nothing.

Getting that backwards in either direction produces a real flaw: authenticating private mail at
the provider would require the provider to read it, and leaving public feeds unauthenticated
would let anyone speak as anyone.

---

## Documents are graphs, so they publish as graphs

The demo publishes **one signed object per document node**, not one object per document.

That is not a detail. A document is a DAG of content-addressed nodes, so encoding only the root
would drop its children, and encoding the whole thing as one blob would give up what content
addressing buys: two documents quoting the same paragraph share it rather than copying it, and a
reader fetches the parts they need and verifies each independently.

Bob rebuilds the graph from the nodes he verified, and the announcement names which node to
start reading from.

---

## What the demo proves, and what it does not

Proved, in a single run over real sockets:

- An address is the hash of a locally generated key. Nobody issued it, so nobody can revoke it.
- A stranger reads a publisher knowing only that address. No introduction, no registry.
- Every object is verified against the author's key rather than against where the bytes came
  from.
- The index entry was emitted by the author at the moment of writing. No crawler ran.
- The catalogue and the ranking are the reader's. There is no index to capture.
- The document is a typed node graph. There is no markup to parse and no script to run, so a
  document cannot reach into a reader's machine, because there is nothing to reach with.

Not proved, and stated in the demo rather than left implied:

- **Who reads is not hidden.** Polling a feed tells the provider which publisher a client
  follows. That is #53 reached by a different road.
- **Denial is not prevented**, only made visible.
- **Anyone can still read any feed**, which is what publishing means, and anyone can still
  flood one. What they cannot do is forge, delete, or be counted twice.
- **Nothing replicates.** One provider holds the feed. If it stops, the feed stops, and the
  objects survive only where someone kept them. Permanence is L6's problem and is not wired to
  this.

---

## A measurement worth keeping

A test failed on a boundary and the reason generalises: **a per-hop drop rate is not the loss a
client sees.** Over a four-hop route a 2% per-hop rate compounds to 7.8% end to end, which is
*above* a 5% baseline rather than below it.

Both sides need to know this. An adversary sizing an attack to stay under a client's noise floor
has to account for route length, and a client setting a baseline has to set it against
end-to-end loss rather than link loss.

---

## References

- Piotrowska, Hayes, Elahi, Meiser, Danezis. *The Loopix Anonymity System.* USENIX Security 2017.
- Barnes, Bhargavan, Lipp, Wood. *Hybrid Public Key Encryption.* RFC 9180.
- `docs/21-a-running-network.md` for L3 and L4.
- `docs/22-links.md` for what the rendered links mean.
- `docs/23-discovery.md` for L15 and why ranking is anchored at the reader.
