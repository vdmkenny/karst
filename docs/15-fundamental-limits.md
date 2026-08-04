# 15 — Fundamental limits, and one claim withdrawn

Two results from the literature bear directly on L4. The first says KARST's costs are
unavoidable rather than sloppy. The second says a claim made in `05-anonymity.md` §8 was
too strong.

---

## 1. The anonymity trilemma

Das, Meiser, Mohammadi and Kate, *Anonymity Trilemma: Strong Anonymity, Low Bandwidth
Overhead, Low Latency, Choose Two* (IEEE S&P 2018), derive necessary conditions relating
latency overhead and bandwidth overhead for strong anonymity against a global passive
adversary.

Four things about that sentence are load-bearing, and an earlier version of this document got
each of them slightly wrong in the direction of claiming more.

**The latency is counted in rounds, not seconds.** Latency overhead is "the number of rounds a
message can be delayed by the protocol before being delivered", and bandwidth overhead is "the
number of noise messages per user that the protocol can create in every round" (Section III-B,
p. 112). The paper carries no wall-clock quantity at all and says so: "our model abstracts from
the time the computations at the node take and also the length of the messages". So the theorem
does not price KARST's seconds. It prices a round count, and mapping rounds onto seconds is a
step this design has to make itself and defend on its own.

**The constraints are necessary and never sufficient.** The paper is explicit twice: "all the
constraints we have derived in Section V and Section VI are necessary for anonymity, but they
are not sufficient conditions for anonymity" (p. 117), and "There can exist l and p such that
2*l*p > 1 - neg(eta), but still no protocol can achieve strong anonymity" (p. 118). Satisfying
the bound is therefore not evidence of anonymity, and treating `2*l*p > 1` as a design target
is a misreading the paper anticipates by name.

**L4 sits under the unsynchronised bound, Theorem 7, and the paper places it there itself.**
Section X (p. 120) names Loopix: "Loopix naturally enforces our unsynchronised user
distribution: the rate at which Loopix clients send messages is the sum of a dummy-message rate
(beta) and a payload message rate (p'), which are system parameters." It computes
`(p' + beta) * l = 1` and concludes that "the trilemma does not exclude strong anonymity for
Loopix". Citing the synchronised result, Theorem 2, for this design is citing the wrong theorem.

**The bound does not scale with the number of users.** In the unsynchronised model
`f_p(x) = min(1/2, 1 - (1 - p)^x)` carries no population term and Theorem 7 has no side
condition on N. The synchronised model does carry one. So the trilemma constrains the product
of round count and per-round rate, and a KARST deployment cannot argue its way past the bound
by having more users, nor does a small deployment violate it by having few.

One further trap, because it looks like an anonymity-set claim and is not: "Note that eta does
not measure the size of the anonymity set, but the computational limitation of the adversary"
(p. 111).

### What this settles

**Strong anonymity against a whole-network observer requires paying at least one of the two
overheads, provably, regardless of how well anyone writes the code.** A design claiming low
latency overhead and low bandwidth overhead together is either not achieving strong anonymity
or not measuring honestly.

That reframes WHITEPAPER §6 considerably. The bandwidth cost is not a defect to be optimised
away later; it is the price of the property, and a roadmap item promising to reduce it without
weakening anonymity is promising to refute a theorem.

What it does **not** settle is that KARST has strong anonymity. The bound runs one way, and
the paper says so. Passing it means the design is not excluded, which is the same thing the
paper concludes for Loopix and no more.

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

### What sets the delay, since the trilemma does not

The trilemma prices rounds, not seconds, and the passive adversary is saturated by cover alone.
So neither can produce a delay parameter. The n-1 attack can, and `karst-mix::active` measures
it. 600 trials per row:

| arrival rate | mean delay | occupancy | isolation | packets suppressed |
|---|---|---|---|---|
| 10 | 0.5 | 5 | 0.518 | 5 |
| 10 | 1 | 10 | 0.185 | 10 |
| 10 | 2 | 20 | 0.058 | 20 |
| 10 | 8 | 80 | 0.015 | 83 |
| 10 | 16 | 160 | 0.005 | 168 |
| 40 | 0.5 | 20 | 0.157 | 19 |
| 40 | 2 | 80 | 0.022 | 82 |
| 2.5 | 8 | 20 | 0.052 | 20 |
| 2.5 | 32 | 80 | 0.022 | 83 |

**Mean pool occupancy governs isolation, and delay on its own does not.** Occupancy is
`arrival_rate * mean_delay`, and the rows at occupancy 80 agree to within 0.007 across a
sixteen-fold spread of arrival rates. That is what makes the delay derivable: a deployment
computes its arrival rate per mix as `N * r / W` for N clients emitting at rate r across W
mixes per layer, picks an isolation target, and reads off the occupancy it needs.

**With one exception, and it is the one a careless derivation would walk into.** At occupancy
20 the three samples are 0.052, 0.058 and 0.157. The outlier has a mean delay of half a tick.
Below roughly one unit of schedule granularity the exponential has no room to spread, most
packets leave in the interval they arrive, and the discipline degrades toward the batch
behaviour delay exists to avoid. Occupancy stops predicting anything.

So the rule has two parts, and using only the first produces a configuration that does not
defend:

1. **Set occupancy from the isolation target.** Roughly 20 for 5%, 80 for 2%, 160 for 0.5%.
2. **Keep the mean delay above the granularity of the emission schedule.** Occupancy bought by
   raising the arrival rate while shrinking the delay below that floor is not real.

Both are measured here rather than derived from the literature, because the literature does not
supply them: Loopix recommends no parameter values, giving only the ratio `lambda/mu >= 2` for
aggregate arrival rate at a mix, and the trilemma abstracts away from wall-clock time entirely.

### The emission rate, and the thing it collides with

The delay derivation above needs an emission rate to start from. Three independent lines of
evidence converge on roughly one packet every five seconds, and a fourth says that number
cannot be run on a phone.

**What it costs in data.** At 1024 bytes both directions, one packet per second is 5.31 GB per
month, and IP and UDP headers add 3% to 8% on top. That exceeds the ITU's 5 GB reference basket
for mobile broadband, the FCC Lifeline minimum of 4.5 GB per month (frozen at that figure
through 1 December 2027), and the 4.51 GB per month an average Kenyan mobile broadband
subscriber actually consumes. At one packet per second, cover traffic is not a share of a
low-end plan, it is more than the whole plan.

One packet every five seconds is 1.06 GB per month. That is about 5% of what a typical
subscriber in the EU, US or India uses, and 106% of the ITU's low-consumption basket. Thirty
seconds is 177 MB, under 1% of typical usage, which is a rounding error anywhere.

**What comparable systems chose.** Tor's deployed connection padding samples its interval from
1.5 to 9.5 seconds, mean 5.5. Talek picked exactly 5 seconds as its shipped default after
evaluating 1 second and rejecting it on bandwidth grounds. Tor's reduced mode for mobile
clients samples 9 to 14 seconds. Loopix's lowest experimental configuration is one message
every 12 seconds. The deployed precedent band is one packet every 5 to 12 seconds, and nothing
above one per second ships anywhere except Nym.

**What it costs in battery, which is where the agreement ends.** The binding constraint is not
the data plan, it is the RRC inactivity timer, and every network with a published measurement
puts it between 10.7 and 21.4 seconds. **An emission interval below about ten seconds means the
radio never returns to idle, at all, ever.** A pinned LTE radio draws about 1060 mW against an
idle floor of about 31 mW, a factor of 34, and radio-only battery life on a 15.5 Wh phone falls
from roughly 21 days to roughly 15 hours.

The middle does not rescue it. At 30 to 60 seconds the radio does reach idle, and it pays the
full tail on every emission, which still costs 7 to 14 times the idle floor. Getting close to
idle needs tens of minutes: GSMA's own IoT guidance recommends 29 minutes as a default polling
interval, and at that interval there is no anonymity left to talk about.

### So the honest statement is that this does not run on a phone

The three constraints do not have a common solution. Five seconds is where precedent and the
data budget agree, and it is half the shortest measured RRC timer, so it pins the radio awake
permanently.

WHITEPAPER §6.11 already concedes that constrained devices are exempt from cover traffic and
are therefore not anonymous, and frames that around battery-powered sensors. **The measurement
says the exemption is much wider than the concession.** It covers any battery-powered device at
any interval short enough to be useful, which includes the phone in a pocket that most of this
design's plausible users would be carrying.

That is not a reason to change the parameter. It is a reason to state which device the
parameter is for: **the shipping set assumes a client that is plugged in**, or one that accepts
a day of battery rather than weeks. A phone-shaped deployment needs either a different
mechanism or an explicit statement that it is not anonymous, and inventing a third option here
would be inventing it.

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
