# 10 — Versioning and permanence

Two questions, with different answers.

1. **Can content be updated while old versions survive?** Yes, completely, and it is
   already implemented.
2. **Does that remove the need for something like the Internet Archive?** Partly. It
   removes the Archive's two hardest problems and leaves its most expensive one exactly
   where it was.

The distinction matters enough to be worth being precise about, because "content
addressed, therefore permanent" is a claim people make constantly and it is false.

---

## 1. Updating content

An object is immutable. Editing does not modify it; editing publishes a **new** object
carrying `supersedes: Cid` pointing at its predecessor.

```
  v1 (c:9a3f…)  "the original claim"
      ^
      | supersedes
  v2 (c:41c8…)  "a revised claim"
      ^
      | supersedes
  v3 (c:7b02…)  "the final claim"       <- current
```

Every version keeps its own name forever, keeps its own signature, and keeps verifying.
`Lineage` in `karst-object` walks this in both directions: `history()` backwards to the
original, `successors()` forwards, `resolve()` from any version to the current head.

### What this buys that today's web cannot

**A citation cannot rot.** A reference is a hash. It resolves from anyone holding that
version, forever, with no server involved. The Pew finding that 54% of Wikipedia pages
contain at least one dead reference link is a symptom of naming a place instead of a
thing, and it does not occur here.

**A citation cannot silently change meaning.** This one is underrated. Today a page can
be edited under a stable URL, and every citation to it now points at different text with
no signal to the reader. Under KARST that is structurally impossible: a quote is a
reference to one exact version (L13), so the thing you cited is the thing that is
returned. If the author has since revised it, `resolve()` tells you so, and shows you
both.

**Equivocation is detectable.** If an author signs two different successors to the same
version, showing one history to one audience and another elsewhere, `resolve()` returns
`Forked` rather than silently picking a winner. Surfacing that is deliberate: silently
choosing is how an author gets away with it. Transparency logs at L8 are what make it
detectable in practice, since an equivocating author would simply never show you both
branches themselves.

### Retraction, which is not deletion

An author can publish a signed retraction as the next entry in the lineage. Indexes that
honour it stop listing the retracted version. **The bytes remain**, because anyone who
holds them holds them, and nothing in this design can reach into their storage. This is
WHITEPAPER §6.1 arriving in its most ordinary and most painful form: somebody publishes
something they regret and cannot take it back.

---

## 2. So do we still need the Internet Archive?

### What genuinely goes away

**The authenticity problem.** Today you must trust archive.org that its snapshot is a
faithful record of what the page said. There is no way to check. Under KARST an archived
version carries the author's signature, so **any copy from anyone verifies against the
original author's key**. A snapshot handed to you by a stranger, a hostile party, or a
government is exactly as trustworthy as one from the archive itself, which is to say
fully, or not at all, and you can tell which. This is a large improvement and it is the
part people underestimate.

**The singularity problem.** One organisation, in one jurisdiction, one lawsuit or one
funding crisis away from the record disappearing. Under KARST every reader is already a
replica and every replica is equal. There is no privileged archive whose word you take,
and therefore no archive whose loss is categorically worse than any other node's.

**Format decay.** A canonical binary encoding with one valid parse (L6) and a small closed
node vocabulary (L10) is drastically more likely to be readable in forty years than a
snapshot of a JavaScript application that needed a specific browser to mean anything.

### What does not go away, at all

**Somebody still has to store the bytes.**

Content addressing provides **integrity** and **addressability**. It does not provide
**availability**, and no amount of hashing will make it. If nobody holds a version, that
version is gone, and it is gone whether or not everyone can prove what it would have said.
`Lineage::resolve()` returns `Unknown` for content nobody kept, which is the honest
behaviour and also a confession.

Replication is voluntary and it follows attention. Popular content is held by thousands of
readers automatically. The obscure municipal planning document that turns out to matter in
one lawsuit eight years later is held by nobody, because nobody read it, and that document
is precisely what an archive exists for.

**So the archival function survives, and its shape changes:**

| | Today | Under KARST |
|---|---|---|
| Who can archive | Effectively one org at scale | Anyone, including one person with a disk |
| Is the copy trustworthy | You trust the archivist | It verifies against the author's key |
| What a takedown costs | One order to one org | One order per holder, and holders are unknown |
| What a funding crisis costs | The record | One node among many |
| Who pays for storage | The archivist | **Still somebody. Unchanged.** |

An archive under KARST is a well-resourced actor deliberately holding unpopular things:
one custodian among many rather than *the* custodian. That is a much better position than
the Internet Archive occupies today, and it is not the same as not needing one.

### Timestamps

The Wayback Machine's other function is attestation of time: proof that a page said this
on that date. L8 transparency logs give the same thing without the Wayback Machine. A log
witnesses that a version existed by a certain point, and you choose which logs you trust,
plurally, rather than trusting one organisation's clock.

---

## 3. Costs and open problems

1. **Storage economics are unsolved.** L14 could pay for custody, and we have not designed
   that, and it collides with L4 the same way every other use of L14 does (WHITEPAPER §6.10).
   "Anyone can archive" is not an answer to "who will".
2. **Selective preservation reproduces attention.** What survives is what someone chose to
   keep, and that choice tracks popularity and power. This is true of every archive ever
   built, and the design does nothing to fix it while making it easier to notice.
3. **Permanence has no undo.** Every argument above for why a citation cannot be erased is
   simultaneously an argument for why a mistake cannot be erased. Same mechanism, and you
   do not get to keep one and discard the other.
4. **Lineage leaks drafting.** A visible edit history shows what an author changed and when.
   That is exactly what you want for a public record and exactly what you do not want for a
   person revising something personal. Publishing under a fresh key breaks the lineage and
   costs you the continuity, and there is no option that gives both.

---

## Status

`Lineage`, `Resolution`, `history`, `successors`, `resolve` and `equivocations` are
implemented and tested in [`crates/karst-object`](../crates/karst-object). Timestamp
attestation needs L8, which is Phase 3. Storage economics need L14, which is Phase 4 and
may not be solvable as specified.
