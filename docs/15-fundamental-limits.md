# 15 — Fundamental limits, and one claim withdrawn

Two results from the literature bear directly on L4. The first says KARST's costs are
unavoidable rather than sloppy. The second says a claim made in `05-anonymity.md` §8 was
too strong.

---

## 1. The anonymity trilemma

Das, Meiser, Mohammadi and Kate, *Anonymity Trilemma: Strong Anonymity, Low Bandwidth
Overhead, Low Latency, Choose Two* (IEEE S&P 2018), prove that an anonymous communication
protocol can achieve at most two of:

- **strong anonymity**, meaning anonymity up to a negligible chance,
- **low bandwidth overhead**,
- **low latency overhead**,

against a global passive adversary. The bounds differ for synchronised and unsynchronised
user behaviour, and the unsynchronised case is the harder one.

### What this settles

KARST's roughly 200x bandwidth and seconds of latency read like implementation waste. They
are not. **Strong anonymity against a whole-network observer requires paying at least one of
those costs, provably, regardless of how well anyone writes the code.** Any design claiming
all three is either not achieving strong anonymity or not measuring honestly.

That reframes WHITEPAPER §6 considerably. The bandwidth cost is not a defect to be optimised
away later; it is the price of the property, and a roadmap item promising to reduce it without
weakening anonymity is promising to refute a theorem.

### What it raises

**KARST pays both costs, and the theorem only requires one.**

`karst-mix::frontier` maps the two corners:

| Corner | Bandwidth | Latency needed for strong anonymity |
|---|---|---|
| Cover traffic, minimal delay | ~200x | 1 tick suffices |
| No cover, delay only | ~1x | large, and never quite reaches the padded result |

Against the *passive* adversary, cover traffic alone reaches strong anonymity at one tick of
delay. The delay is not what buys that result. So the shipping configuration is paying twice
for something one payment achieves.

Two readings, and the design should say which:

1. **The overpayment is margin**, buying resistance to attacks the trilemma does not model.
   The active-adversary results support this: `karst-mix::active` shows a batch mix, which is
   what cover-plus-prompt-forwarding amounts to, is isolated 51.7% of the time by an n-1
   attack, while a Poisson mix is isolated 0.7%. **Delay is not paying for passive anonymity,
   it is paying for active resistance**, and the trilemma is a statement about passive
   adversaries only.
2. **There is slack to reclaim**, and the delay parameter could come down.

Reading 1 is the correct one and it is now stated: the two costs buy two different properties
from two different adversaries. The trilemma governs the bandwidth cost; the n-1 attack governs
the latency cost. Neither is redundant, and neither is optional.

### And the passive result is conditional, which was not visible

"Cover traffic alone reaches strong anonymity" is measured at one packet per client per tick.
That is twenty-four packets of every client in flight at all times, and no deployment emits at
that rate: constant-rate cover at one packet per tick is 1024 bytes per tick, forever.

The harness could not ask what happens below it. The tick was both the emission period and the
delay unit, so turning cover on pinned the rate at one packet per tick, and the regime where a
client has **less than one packet in flight** was not expressible. `sim::passive_frontier`
separates the two and measures it, at 200 clients, 3 layers, mean per-hop delay 8:

| emit every | packets in flight | anonymity set | adversary gain |
|---|---|---|---|
| 1 | 24.0 | 200.0 | 1.00x |
| 16 | 1.50 | 200.0 | 1.00x |
| 64 | 0.38 | 199.5 | 1.00x |
| 128 | 0.19 | 147.4 | 1.37x |
| 256 | 0.09 | 106.3 | 1.90x |
| 512 | 0.05 | 86.0 | 2.35x |

So the claim holds, and it holds **conditionally**. A deployment that widens its emission
interval to save bandwidth walks off this cliff without anything in the design noticing.

**Little's law is the wrong rule, and it is wrong in the expensive direction.** The natural
derivation says a client needs at least one packet in flight, `r * k * d >= 1`. The measurement
puts the boundary near 0.2, so that rule costs about five times more bandwidth than the
property requires. The reason is that the adversary's candidate window is not who has a packet
in flight now but who emitted anywhere in the plausible delay window, and end-to-end delay is
Erlang with a long tail.

Stated as a rule rather than a constant, because the constant depends on the delay
distribution: **the emission interval must stay inside the spread of the end-to-end delay, not
merely inside its mean.**

---

## 2. Membership concealment, and a claim withdrawn

`05-anonymity.md` §8 and WHITEPAPER §6.11a state that joining the network is observable, fully
deanonymises a user the adversary was already watching, and has **no complete defence short of
having always been there**.

That last clause is wrong, and the literature has a name for the answer.

Vasserman, Jansen, Tyra, Hopper and Kim, *Membership-Concealing Overlay Networks* (ACM CCS
2009), formalise networks that hide **the real-world identities of participants**, so an
observer cannot determine who is a member at all. The paper gives three proof-of-concept
designs, trading efficiency against robustness to churn, and notes that membership concealment
is orthogonal to anonymity while making pseudonymous communication and censorship resistance
substantially easier when you have it.

**If membership itself is concealed, there is no observable join event, because there is no
observable membership.** The differencing boundary that statistical disclosure exploits does
not exist rather than being padded over.

### KARST is already partway there

L5 was specified for censorship resistance: peers are learned by social introduction, no party
holds a roll, and there is no document listing the network. Those are membership-concealment
properties, arrived at for a different reason.

What is missing is that L5 conceals membership from a *directory*, not from a *network
observer*. Someone watching the wire still sees a host begin emitting at constant rate, and
that is the join event. Closing it needs the MCON line of work: concealing that a given host
is participating at all, not merely concealing the list of who is.

### What this costs

MCON designs are from 2009 and none deployed. The paper's own framing is proof-of-concept, and
the three designs trade against each other rather than dominating. Adopting the approach means:

- accepting an efficiency or churn-robustness penalty on top of the trilemma cost already paid,
- and inheriting an unfinished research problem rather than an engineering task.

So the honest position is: **the join boundary has a known research direction and no deployed
solution.** That is a materially different statement from "no complete defence exists", and the
docs now say the former.

---

## 3. Consequences

1. WHITEPAPER §6 gains a note that the bandwidth cost is theorem-mandated, not a defect.
2. WHITEPAPER §6.11a withdraws "no complete defence" and points at MCON.
3. `docs/05-anonymity.md` §8 does the same.
4. The two costs are attributed to two different adversaries, so neither can be dropped as
   redundant.

---

## References

- Das, Meiser, Mohammadi, Kate. *Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead,
  Low Latency, Choose Two.* IEEE S&P 2018.
  <https://www.freehaven.net/anonbib/cache/trilemma-oakland2018.pdf>
- Vasserman, Jansen, Tyra, Hopper, Kim. *Membership-Concealing Overlay Networks.* ACM CCS 2009.
  <https://www.robgjansen.com/publications/mcon-ccs2009.pdf>
