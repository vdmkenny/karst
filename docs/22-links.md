# 22 — Links

A URL names a location and resolves to whatever is there now. That single behaviour produces
both of the web's reference failures, and they look like opposites:

- **Link rot.** The thing you cited is gone, and the reference is worthless.
- **Silent substitution.** The thing you cited is still there, has changed, and the reference is
  worse than worthless because it now vouches for something the author never saw.

They have one cause. The reference cannot say whether it meant *these bytes* or *whatever this
becomes*, so it always means the second, and a reader cannot tell which was intended.

Both meanings are legitimate. A citation means the first. A menu entry means the second. The
flaw is not that URLs chose wrongly; it is that there is only one thing to choose.

---

## Two types, and the reader is told which

```rust
pub enum Link {
    Pinned(Cid),
    Tracking { seen: Cid },
}
```

| | Resolves to | Verifies | Changes under the reader |
|---|---|---|---|
| `Pinned` | exact bytes | by construction | never |
| `Tracking` | current head of the chain | against the lineage | yes, and visibly |

`Pinned` is content addressing doing what it already does. Nothing can substitute for it,
because a substitution would not hash to the name.

`Tracking` carries **what the author saw** rather than the start of the chain. Same 66 bytes,
two things bought:

- A reader holding nothing newer gets exactly what the author saw. **Staleness degrades to the
  pinned behaviour** rather than to an error, so a tracking link is never worse for a reader
  who is merely behind.
- A reader holding something newer can diff the author's reference against what they are being
  shown. That **detects** substitution rather than merely permitting it.

Rendering says which kind it is. A link whose kind is invisible is a URL again.

---

## Resolution, and the one case it refuses

Resolution walks forward from `seen` through `supersedes` edges the lineage has verified.

| Outcome | Meaning |
|---|---|
| `Pinned(c)` | Nothing to follow. |
| `Current(c)` | Tracking, and nothing has superseded it. |
| `Superseded { head, seen, steps }` | Moved, and by how much. |
| `Unknown(c)` | Nothing newer is held, so the author's view stands. |
| `Forked { at, candidates }` | **Refused.** |

A fork means the publisher signed two conflicting continuations of the same chain. Any rule for
picking one lets that publisher **show different readers different content while both verify**,
which is precisely the attack this layer exists to prevent. So resolution returns no target and
the reader decides, because a fork is a fact about the publisher rather than a problem with the
link.

`Resolved::target()` returns `None` only in that case. There is no default, on purpose.

### What resolution inherits for free

A stranger publishing an object that claims to supersede a popular page does not capture
tracking links to it. `Lineage::is_valid_edge_with_rotations` already refuses the edge, so
resolution never sees it. That check exists because of issue #31, and this is the second
mechanism it protects.

Walking is bounded at 4096 steps. The chain is publisher-controlled, so an unbounded walk is
unbounded reader time bought by whoever publishes the chain.

---

## Quotes are pinned by construction

`Node::Quote` takes a `Cid` and not a `Link`, and it will not be widened.

A quotation asserts that somebody said a particular thing. A tracking quote could be **rewritten
under the person quoting it**, which turns an honest quotation into an accusation nobody made
and attributes it to the quoter. That is not a feature with a narrow use case; it is a way to
put words in someone's mouth with the quoter's signature on it.

Media takes a `Link`, because a logo that follows its source and a specific photograph are both
real requirements.

---

## What this does not solve

**A pinned link to content nobody serves any more** is a retrieval failure, not a resolution
failure, and reports as one. Link rot is not fixed by naming content; it is *relocated*, from
"the reference is wrong" to "the reference is right and no one has the bytes". L6 permanence
carries that weight, not this layer.

**Freshness.** A tracking link whose head is being withheld is a freeze attack, and
`karst-object::freshness` detects it. Nothing currently wires the two together.

**Discovery.** Knowing a chain exists is not the same as holding it. A reader resolves only as
far forward as what they have, which is why `Unknown` is a normal outcome rather than an error.

---

## References

- Issue [#66](https://github.com/vdmkenny/karst/issues/66).
- `karst-object::Lineage`, for the edge validity rules resolution depends on.
- `docs/10-versioning-and-permanence.md`, for why versions are objects rather than a mutable
  pointer.
