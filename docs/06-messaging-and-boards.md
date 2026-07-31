# 06 — Messaging and boards, natively

Messaging and discussion are the two things people actually do, and on today's stack
both require a company. A chat needs a server to hold the messages; a forum needs a
server to hold the replies. That hosting requirement is the whole reason a platform
can own a community, ban a user, or hold an archive hostage.

Neither needs to be a layer here. Both fall out of layers that exist for other reasons,
and they need exactly **two** new primitives between them. That they need so little is
the strongest available argument that the lower stack is shaped correctly. If native
messaging had required a messaging layer, the object and mixing layers would be wrong.

---

## 1. Messaging

### What already does the work

| Need | Provided by | How |
|---|---|---|
| Addressing | L2 Identity | A recipient is a public key. There is no account, no server, no registration, no handle to lose. |
| Confidentiality | L2 + L9 | Ephemeral session keys; long-term identity never on the wire. |
| **Metadata privacy** | L4 Mixing | The hard part. Constant-rate cover means who-talks-to-whom, when, and how often carry no signal. |
| Offline delivery | L0 + L6 | Delay tolerance is the base case, so a message to an offline recipient is an object the network holds until fetched. |
| Attachments and media | L6 + L7 | An attachment is an ordinary object; a voice note is a short stream. No size limits, no separate upload service. |
| Groups | L6 + L13 | A group is an object listing member keys, with signed membership changes forming a lineage anyone can audit. |

Metadata is the part every messenger gets wrong. Signal has excellent message
confidentiality and still knows who connects and when, because it is a server.
Constant-rate mixing at L4 removes that observation entirely, which is the single
reason messaging is worth building here rather than on Signal.

### New primitive 1: blinded drops

A message must reach an offline recipient without anyone learning who the recipient is.
Storing it at "the recipient's address" fails immediately: whoever holds it learns who
it is for, and whoever fetches it identifies themselves.

**Mechanism.** Sender and recipient derive a shared secret from their keys and a
counter. The message is stored at an address derived from that secret rather than from
either identity. The holder sees an opaque address and an encrypted blob and learns
nothing about either party. The recipient computes the same addresses and polls them,
and the polling is invisible because L4 already has them emitting at a constant rate.

This is the same insight behind Tor v3 onion service descriptors, where a directory
stores a descriptor it cannot itself identify. See `04-lessons-from-tor.md` §5.

**Cost.** The recipient must poll a set of candidate addresses, which grows with how
long they have been offline, and the drop set is a correlation surface if the shared
secret leaks. Forward secrecy on the derivation limits the damage to future drops but
does not repair past ones.

---

## 2. Discussion boards

### Why forums are centralised today

Not for a good reason. It is one missing feature: **a link points one way.** Given a
post, there is no way to find what replied to it, because the reply knows about the
parent and the parent knows nothing. Somebody therefore has to keep the list, and
whoever keeps the list owns the community.

L13 Provenance already fixes this, for reasons that had nothing to do with forums:
references register in the object graph, so backlinks exist. Once backlinks exist, a
thread assembles itself and nobody needs to host it.

### New primitive 2: conversation objects

A `Post` is an ordinary signed object with a body and an optional structural reference
to a parent post.

That is the entire data model. Everything else is derived:

- **A thread** is the transitive closure of backlinks from a root post. It is computed
  by the reader, not stored by anyone. Nobody hosts it. Nobody can delete it.
- **A board** is an index (L15) over posts matching whatever its curator likes: a topic,
  a set of authors, a tag, a language. Since indexes are ordinary objects anyone may
  publish, anyone may publish a competing board over the same posts.
- **Moderation** is a label set (L15) you subscribe to. A moderator publishes labels;
  your client hides what they labelled. Two people reading the same board with different
  label subscriptions see different boards, and both are correct.
- **Voting and ranking** are local. Scores are computed by your client from signals you
  chose, so ranking is a setting rather than somebody's product.

### What this changes

**A board is a view, not a place.** There is no server to seize, no company to acquire,
and no admin who owns the archive. If a moderator becomes hostile, someone republishes
the index without them and the community moves by changing a subscription. The posts
never moved because they were never anywhere.

This is the anti-capture requirement (L16) doing real work at the application layer:
a platform cannot hold a community hostage, because the platform was only ever an
opinion about which posts are interesting.

**Anonymous, pseudonymous and named posting are the same mechanism.** Post under your
long-term key, under a persistent pseudonym, or under a fresh key per post. The last one
is genuinely unlinkable given L4, at the cost of accumulating no reputation. Boards
choose their own policy by declining to index unknown keys, which is a curation choice
rather than a protocol rule.

### What this costs

- **Nothing can be deleted.** A post is an immutable object. Retraction marks it in your
  lineage and unlists it from indexes that honour the retraction. Anyone who kept a copy
  keeps it. This is WHITEPAPER §6.1 arriving somewhere very concrete, and it will hurt
  most in exactly the ordinary case: somebody posts something regrettable and cannot take
  it back.
- **Thread assembly costs the reader.** The server used to do this. Now your client walks
  backlinks, which is more work and more round trips, mitigated by the fact that objects
  are cached everywhere and most of a thread is already local.
- **Sybil flooding.** Posting is cheap and identities are free, so a board with no
  curation drowns. The defences are the send cost (unsolved, see WHITEPAPER §6) and
  curators declining to index unknown keys, which reintroduces a gatekeeper at exactly
  the point where gatekeepers become valuable. Boards will recentralise around good
  curators, and that is WHITEPAPER §6.6 showing up early.

---

## 3. Status

The PoC in `crates/karst-thread` implements the conversation object model: posts,
structural replies, backlink-derived threads, and two competing board views with
different label subscriptions over an identical post set.

Blinded drops are specified here and not built. They need L4, which is not built either.
