//! A clock a node can defend.
//!
//! Every timing guarantee in L4 rests on elapsed time being what the node thinks it is. A node
//! reads time from one source and cannot detect that source lying, so two things must hold.
//!
//! The reading must be **monotonic** rather than wall time. Monotonic clocks are not settable
//! and are not stepped by NTP, which matters because NTP is attacker-influenceable (Malhotra,
//! Cohen, Brakke, Goldberg, *Attacking the Network Time Protocol*, NDSS 2016). A node whose
//! time can be pushed forward releases everything it is holding with no delay, which is a
//! mixing bypass obtained without touching a single packet.
//!
//! And the node must clamp anyway, because the requirement above is a requirement on somebody
//! else's code. Time here never runs backwards and never advances faster than `MAX_ADVANCE_MS`
//! per reading, so a wrong or hostile reading costs throughput rather than anonymity.
//!
//! The reference is the **highest reading ever presented** rather than the most recent one.
//! Measuring against the most recent reading lets a source rewind to reset the baseline and
//! then jump forward again, manufacturing a full clamped step per cycle and draining a queue
//! as fast as it can call. Against a high-water mark, rewinding buys nothing: advancing
//! internal time requires exceeding every reading given so far.
//!
//! What remains is that internal time advances at most one clamped step per reading, and the
//! node decides when to read. The bound is therefore the node's own poll rate, which is the
//! one input in this chain an adversary does not supply.

#[derive(Debug, Clone)]
pub struct Clock {
    internal: u64,
    high_water: Option<u64>,
    max_advance_ms: u64,
}

impl Clock {
    /// The most the internal clock moves for one reading.
    ///
    /// Well above any sane poll interval and well below the longest a node will hold a packet,
    /// so no single reading can flush a full queue.
    pub const MAX_ADVANCE_MS: u64 = 5_000;

    pub fn new() -> Self {
        Clock {
            internal: 0,
            high_water: None,
            max_advance_ms: Self::MAX_ADVANCE_MS,
        }
    }

    pub fn with_max_advance(max_advance_ms: u64) -> Self {
        Clock {
            max_advance_ms,
            ..Clock::new()
        }
    }

    /// Take a reading and return internal time.
    pub fn advance(&mut self, reading: u64) -> u64 {
        match self.high_water {
            None => self.high_water = Some(reading),
            Some(hw) if reading > hw => {
                let delta = (reading - hw).min(self.max_advance_ms);
                self.internal = self.internal.saturating_add(delta);
                self.high_water = Some(reading);
            }
            Some(_) => {}
        }
        self.internal
    }

    pub fn now(&self) -> u64 {
        self.internal
    }
}

impl Default for Clock {
    fn default() -> Self {
        Clock::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_never_runs_backwards() {
        let mut c = Clock::new();
        c.advance(1_000);
        c.advance(2_000);
        let t = c.now();
        c.advance(0);
        assert_eq!(c.now(), t);
        c.advance(1);
        assert_eq!(c.now(), t, "a rewound source moved internal time");
    }

    /// A source alternating between a huge reading and a small one must gain nothing.
    ///
    /// This is the sawtooth in its most profitable form: each large reading would be a full
    /// clamped step if the reference were the previous reading.
    #[test]
    fn an_aggressive_sawtooth_gains_one_step_in_total() {
        let mut c = Clock::new();
        c.advance(0);
        for _ in 0..10_000 {
            c.advance(u64::MAX);
            c.advance(1);
        }
        assert_eq!(c.now(), Clock::MAX_ADVANCE_MS);
    }

    #[test]
    fn a_forward_jump_is_clamped_to_one_step() {
        let mut c = Clock::new();
        c.advance(0);
        c.advance(u64::MAX);
        assert_eq!(c.now(), Clock::MAX_ADVANCE_MS);
    }

    #[test]
    fn honest_readings_pass_through_unchanged() {
        let mut c = Clock::new();
        c.advance(100_000);
        for i in 1..=50 {
            c.advance(100_000 + i * 20);
        }
        assert_eq!(c.now(), 1_000, "honest small steps were distorted");
    }

    /// A source that rewinds and then advances must not be able to replay the same interval.
    #[test]
    fn a_sawtooth_source_cannot_manufacture_extra_time() {
        let mut c = Clock::new();
        c.advance(0);
        for _ in 0..1000 {
            c.advance(1_000);
            c.advance(0);
        }
        // The first cycle contributes 1000ms. Every cycle after it contributes nothing,
        // because no later reading exceeds the high-water mark.
        assert_eq!(c.now(), 1_000);
    }
}
