# What a capability costs, including the part the README used to skip

Issues #108 and #109. Two costs this design imposes that no document stated. Both are
consequences of choices made deliberately, and neither had been written down, which made the
choices look free.

## 1. Authority is not revocable

README commitment 2 said every right is an "explicit, attenuable, revocable capability."
`grep -rni 'revoc\|revoke' crates/` returns nothing in `karst-cap`. There is no revocation, and
there was never a design for one.

This is not an oversight to be scheduled. It follows directly from a property the layer is built
on:

> Every check is local: the capability verifies offline against this object and the owner's
> address, with no directory and no callback to an authorization server.

A verifier that never calls anyone cannot learn that a capability was withdrawn. Revocation
requires either a check against something the issuer controls, which is a callback and reinstates
the availability dependency the layer exists to remove, or a revocation list every verifier
holds, which is a global singleton and is error 03. **Offline verification and revocation are the
same tradeoff seen from two sides**, and this design took offline.

So the honest statement is: a delegation stands until it expires or runs out of uses. An agent
whose key is compromised keeps its delegated authority until then. The resource cannot be
reissued under a new name to escape, because it is content-addressed and a new name breaks every
other capability, link, and quote pointing at it.

What exists instead:

| Bound | What it actually bounds |
|---|---|
| `ExpiresAt` | Wall-clock, against the **verifier's** clock (see below) |
| `MaxUses` | At most `n` times *per verifier*, not in the universe. `UseLedger` is local, and `karst-cap` says so |
| Attenuation | Each delegation can only narrow. A compromised delegate cannot widen |

An API key can be revoked and this cannot. That is a real regression against the incumbent on one
axis, bought with the removal of the authorization server as a point of failure and of control.
Stating it is not optional.

## 2. The expiry caveat was set by the party it bounded

`Caveat::ExpiresAt(t)` was compared against `Request.at`, a public field of `Request` that the
**holder** fills in and signs. A holder of a capability that expired last year signed a request
claiming an earlier time and the caveat passed.

So the only bound that survives key compromise bounded honest holders exclusively, which is the
set that does not need bounding.

This is the same defect as issue #29, where `MaxUses` was checked against a `use_index` the
caller supplied. That one was fixed by moving usage into a `UseLedger` the caller cannot reach.
The comment written at the time reads:

> There is no field it can lie about that helps.

That comment was in the same file as a field it could lie about. The fix was applied to the
instance rather than to the class, which is why the second instance survived.

`Request` now has no time in it, and `authorize` takes `now` from the verifier. **A verifier does
not read its clock off the party it is checking**, which is the same rule `karst-mix::clock`
already enforces against the network, and the same rule that made `UseLedger` verifier-side.

### The general shape

Three instances now, in three crates:

| Where | The value trusted from the wrong party | Fixed by |
|---|---|---|
| `karst-cap` `MaxUses` | `use_index`, caller-supplied (#29) | `UseLedger`, verifier-side |
| `karst-cap` `ExpiresAt` | `Request.at`, holder-supplied (#109) | `now`, verifier-supplied |
| `karst-mix` clock | the wire's notion of time | monotonic high-water mark |

The rule is worth stating once, plainly, so the fourth instance is caught by reading rather than
by audit: **if a check compares a policy value against a number, ask who supplies the number.**
If it is the party being checked, the check is decoration.

## 3. Losing an identity key is terminal

An address is the hash of a locally generated key. The only migration path, `Rotation`, needs the
old private key to sign the forward half:

```rust
pub fn forward(old: &Identity, new_key: &[u8; 32], seq: u64)
```

That bidirectionality is deliberate: it is what stops anyone from claiming to be someone's
successor out of their public key alone. It does not stop a compromised old key, which signs
both halves. It also means a key that is gone cannot
authorise its own succession, and by design there is no registrar to petition.

What a user loses with the key:

- Every L16 standing. Standing does not transfer, and cannot be bought, merged, or inherited.
- Every L9 capability naming that address as audience.
- Every L5 introduction: each contact must re-introduce by hand.
- Every undelivered blinded drop, since those addresses derive from a shared secret over both keys.
- The ability to ever publish a successor to their own documents, so every `Tracking` link to
  their work is frozen at the last version permanently.

The web offers password reset. This offers nothing, and the reason it offers nothing is the same
reason it has no registrar: an account recovery path is an authority that can take an identity
from you, which is error 01 wearing a helpful face.

**Key custody is the user's sole responsibility and loss is terminal.** No mitigation is claimed
here, because none is built. The candidates, none of which are designed, are offline key backup
(which moves the problem to a medium, and is what hardware keys are for), a social-recovery
construction over L5 introductions (which makes your contacts a quorum that can take your
identity, so it needs a threshold argument before it is safe), and a published successor
pre-signed in advance (which needs the successor key to be as well protected as the first, so it
buys less than it looks like).

Any of the three is a design task with a real adversary. Until one is built, the cost stands as
written.
