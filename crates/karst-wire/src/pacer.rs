//! Emission that does not depend on demand.
//!
//! A link that sends when there is something to send is a traffic analysis oracle, and it
//! makes every guarantee at L4 decorative: an observer who can see *when* a party transmits
//! learns who is talking and when, which is most of what mixing is for. Timing alone is enough
//! to link sender and receiver (Danezis, *Statistical Disclosure Attacks*, 2003).
//!
//! The pacer therefore draws its schedule with no reference to the queue. When an emission
//! comes due it takes a real packet if one is waiting and a cover packet otherwise, so the
//! process an observer sees is the same either way. Loopix establishes this construction and
//! its analysis (Piotrowska, Hayes, Elahi, Meiser, Danezis, *The Loopix Anonymity System*,
//! USENIX Security 2017).
//!
//! Emission is a Poisson process rather than a fixed tick. Superposition of Poisson processes
//! is Poisson, so a mix's output stream is analytically the same object as its inputs, which
//! is what makes the end to end argument in Loopix go through. A fixed tick also hides content
//! but composes into a lockstep an observer can count against.
//!
//! # The cost this cannot hide
//!
//! Offering more than the schedule can carry does not produce more packets. It produces a
//! longer queue, and the message is late. **Volume above the cover rate is visible as latency
//! rather than concealed**, which is the honest form of the anonymity trilemma (Das, Meiser,
//! Mohammadi, Kate, S&P 2018): bandwidth here is fixed by choice, so load shows up in delay.

use std::collections::VecDeque;

use karst_mix::clock::Clock;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacerStats {
    pub real: u64,
    pub cover: u64,
    pub offered: u64,
    pub refused: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

/// Generic over what is being paced.
///
/// A sender usually needs to carry more than the packet: which node it enters at, which
/// attempt it is. Keeping that alongside the packet in a second list is a bug waiting to
/// happen, because the two orders diverge the moment anything is dropped.
pub struct Pacer<T> {
    /// Mean emissions per second.
    lambda: f64,
    clock: Clock,
    next_emit: u64,
    queue: VecDeque<T>,
    capacity: usize,
    /// Dedicated to the schedule so that no other draw can shift it, and so the schedule is
    /// reproducible in a test independently of anything the queue does.
    schedule_rng: rand::rngs::StdRng,
    stats: PacerStats,
}

impl<T> Pacer<T> {
    pub const DEFAULT_CAPACITY: usize = 4096;

    pub fn new(lambda_per_sec: f64) -> Self {
        Self::seeded(lambda_per_sec, rand::random())
    }

    pub fn seeded(lambda_per_sec: f64, seed: u64) -> Self {
        assert!(
            lambda_per_sec > 0.0,
            "a link that never emits is a link that reveals it has nothing to say"
        );
        let mut p = Pacer {
            lambda: lambda_per_sec,
            clock: Clock::new(),
            next_emit: 0,
            queue: VecDeque::new(),
            capacity: Self::DEFAULT_CAPACITY,
            schedule_rng: <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed),
            stats: PacerStats::default(),
        };
        p.next_emit = p.draw();
        p
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Inter-emission time from an exponential distribution.
    fn draw(&mut self) -> u64 {
        use rand::Rng;
        let u: f64 = self.schedule_rng.gen_range(f64::MIN_POSITIVE..1.0);
        let secs = -u.ln() / self.lambda;
        (secs * 1000.0).round() as u64
    }

    /// Hand a packet to the link. It leaves when the schedule says, not now.
    pub fn offer(&mut self, p: T) -> Result<(), QueueFull> {
        self.stats.offered += 1;
        if self.queue.len() >= self.capacity {
            self.stats.refused += 1;
            return Err(QueueFull);
        }
        self.queue.push_back(p);
        Ok(())
    }

    /// Advance to `reading_ms` and return everything the schedule says to emit.
    ///
    /// `cover` is called only when a slot comes due with nothing real waiting. It must always
    /// produce a packet: a slot that cannot be filled is a gap, and a gap is the signal this
    /// whole module exists to remove.
    pub fn tick(&mut self, reading_ms: u64, mut cover: impl FnMut() -> T) -> Vec<T> {
        let now = self.clock.advance(reading_ms);
        let mut out = Vec::new();
        while self.next_emit <= now {
            match self.queue.pop_front() {
                Some(p) => {
                    self.stats.real += 1;
                    out.push(p);
                }
                None => {
                    self.stats.cover += 1;
                    out.push(cover());
                }
            }
            let gap = self.draw().max(1);
            self.next_emit = self.next_emit.saturating_add(gap);
        }
        out
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    pub fn stats(&self) -> PacerStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_mix::packet::{Hop, MixKey, Packet};

    fn a_packet() -> Packet {
        let k = MixKey::from_seed([5u8; 32]);
        Packet::wrap(
            &[Hop {
                id: 0,
                public: k.public(),
                delay_ms: 1,
            }],
            b"m",
            rand::random(),
        )
        .unwrap()
    }

    fn cover_packet() -> Packet {
        let k = MixKey::from_seed([5u8; 32]);
        Packet::cover(
            &[Hop {
                id: 0,
                public: k.public(),
                delay_ms: 1,
            }],
            rand::random(),
        )
        .unwrap()
    }

    /// Run a pacer for a while and record exactly when it emitted.
    fn schedule_of(mut p: Pacer<Packet>, offer_every: Option<u64>, ms: u64) -> Vec<u64> {
        let mut times = Vec::new();
        for t in 0..ms {
            if let Some(k) = offer_every {
                if t % k == 0 {
                    let _ = p.offer(a_packet());
                }
            }
            for _ in p.tick(t, cover_packet) {
                times.push(t);
            }
        }
        times
    }

    /// The emission schedule must be identical whether or not there is anything to send.
    ///
    /// This is the property, and it is asserted exactly rather than statistically. Two pacers
    /// with the same schedule seed, one saturated and one silent, must emit at the same
    /// instants. Any dependence of timing on the queue, however slight, breaks this.
    #[test]
    fn emission_timing_is_identical_whether_saturated_or_silent() {
        let silent = schedule_of(Pacer::seeded(20.0, 99), None, 20_000);
        let busy = schedule_of(Pacer::seeded(20.0, 99), Some(5), 20_000);
        assert!(
            silent.len() > 300,
            "vacuous: only {} emissions",
            silent.len()
        );
        assert_eq!(
            silent, busy,
            "the queue changed when packets left, so the link is an oracle"
        );
    }

    /// A silent link must emit as much as a busy one, and all of it cover.
    #[test]
    fn a_silent_link_emits_a_full_stream_of_cover() {
        let mut p = Pacer::seeded(20.0, 7);
        for t in 0..10_000 {
            p.tick(t, cover_packet);
        }
        let s = p.stats();
        assert_eq!(s.real, 0);
        assert!(
            s.cover > 150,
            "expected roughly 200 emissions, got {}",
            s.cover
        );
    }

    /// Offering beyond the schedule produces latency, not packets.
    ///
    /// Stating the limit is the point. The link cannot conceal volume above its cover rate; it
    /// can only delay it.
    #[test]
    fn volume_above_the_cover_rate_becomes_latency_not_bandwidth() {
        let mut p = Pacer::seeded(5.0, 3);
        let mut emitted = 0;
        for t in 0..10_000 {
            // Ten times the rate the link will carry.
            if t % 20 == 0 {
                let _ = p.offer(a_packet());
            }
            emitted += p.tick(t, cover_packet).len();
        }
        assert!(
            emitted < 80,
            "the link emitted {emitted}, so demand leaked into the schedule"
        );
        assert!(
            p.queued() > 300,
            "the backlog should be visible as a queue, not as extra packets"
        );
    }

    /// Emission must be Poisson rather than a fixed tick.
    ///
    /// A fixed tick conceals content but composes into a lockstep an observer can count
    /// against. The check is coarse on purpose: a constant interval has zero variance, and a
    /// Poisson process has variance equal to its mean.
    #[test]
    fn the_schedule_is_poisson_and_not_a_metronome() {
        let times = schedule_of(Pacer::seeded(50.0, 11), None, 40_000);
        let gaps: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
        assert!(gaps.len() > 1000);
        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        assert!(
            (mean - 20.0).abs() < 3.0,
            "mean gap {mean} should be near 1000/50"
        );
        // Exponential: standard deviation equals the mean.
        assert!(
            (var.sqrt() / mean - 1.0).abs() < 0.25,
            "gap sd/mean is {}, not exponential",
            var.sqrt() / mean
        );
    }

    /// A stalled clock must not let the schedule run away and then burst.
    #[test]
    fn a_hostile_clock_cannot_make_the_link_burst() {
        let mut p = Pacer::seeded(20.0, 5);
        for _ in 0..100 {
            let _ = p.offer(a_packet());
        }
        // One reading, a year into the future.
        let out = p.tick(86_400_000 * 365, cover_packet);
        assert!(
            out.len() <= (Clock::MAX_ADVANCE_MS as f64 * 20.0 / 1000.0) as usize + 20,
            "a single hostile reading emitted {} packets at once",
            out.len()
        );
    }

    /// A full queue refuses rather than growing.
    #[test]
    fn a_full_queue_refuses() {
        let mut p = Pacer::seeded(1.0, 1).with_capacity(4);
        for _ in 0..4 {
            assert!(p.offer(a_packet()).is_ok());
        }
        assert_eq!(p.offer(a_packet()), Err(QueueFull));
        assert_eq!(p.stats().refused, 1);
    }
}
