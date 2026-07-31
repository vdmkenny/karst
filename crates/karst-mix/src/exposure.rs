//! What constant-rate emission looks like to your own ISP.
//!
//! The BKA operation against Boystown (2019 to 2021) ended with a court order to Telefónica
//! to identify which o2 subscriber had connected to a particular node. Timing analysis found
//! the node; **legal process on the access provider turned the node into a person.**
//!
//! That final step is the one KARST has never examined. L3 makes the bytes unrecognisable.
//! It does not make the *shape* of the traffic unrecognisable, and L4 mandates a shape that
//! nothing else on a residential line produces: a fixed packet rate, continuously, forever.
//!
//! Ordinary traffic is bursty. A constant-rate emitter has near-zero rate variance. Separating
//! those needs no machine learning and no payload inspection, only a byte counter, which is
//! something every access provider already runs for billing.

/// Coefficient of variation of a per-interval packet count. Zero means perfectly constant.
pub fn rate_variability(counts: &[u64]) -> f64 {
    if counts.is_empty() {
        return 0.0;
    }
    let n = counts.len() as f64;
    let mean = counts.iter().sum::<u64>() as f64 / n;
    if mean <= 0.0 {
        return 0.0;
    }
    let var = counts
        .iter()
        .map(|c| (*c as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    var.sqrt() / mean
}

/// A bursty profile: idle stretches punctuated by activity, which is what a person browsing,
/// streaming and sleeping produces.
pub fn bursty_profile(intervals: usize, seed: u64) -> Vec<u64> {
    let mut s = seed | 1;
    (0..intervals)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            // Mostly quiet, occasionally a burst.
            match s % 10 {
                0..=5 => 0,
                6..=8 => (s >> 8) % 40,
                _ => 200 + (s >> 16) % 800,
            }
        })
        .collect()
}

/// What L4 mandates.
pub fn constant_rate_profile(intervals: usize, rate: u64) -> Vec<u64> {
    vec![rate; intervals]
}

/// How separable the two are, given a variability threshold. Returns the classifier's
/// accuracy, where 0.5 is a coin flip.
pub fn classifier_accuracy(threshold: f64, samples: usize) -> f64 {
    let mut correct = 0usize;
    for i in 0..samples {
        if rate_variability(&bursty_profile(200, i as u64 * 2 + 1)) > threshold {
            correct += 1;
        }
        if rate_variability(&constant_rate_profile(200, 50)) <= threshold {
            correct += 1;
        }
    }
    correct as f64 / (samples * 2) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_traffic_is_bursty() {
        for seed in 1..8u64 {
            let v = rate_variability(&bursty_profile(200, seed));
            assert!(v > 0.8, "seed {seed} gave variability {v:.2}");
        }
    }

    #[test]
    fn constant_rate_emission_has_no_variability_at_all() {
        assert_eq!(rate_variability(&constant_rate_profile(200, 50)), 0.0);
    }

    /// **The finding.** An access provider separates KARST users from everyone else with a
    /// byte counter. No payload inspection, no protocol fingerprint, no machine learning.
    ///
    /// L3 hides what the bytes are. It does not hide that they arrive at a metronomic rate,
    /// and nothing else on a residential line does that.
    #[test]
    fn an_isp_separates_the_two_with_a_byte_counter() {
        let acc = classifier_accuracy(0.5, 64);
        assert!(
            acc > 0.99,
            "expected near-perfect separation, got {:.3}",
            acc
        );
    }

    /// The anonymity set that matters here is not "everyone on the network", it is "everyone
    /// on this ISP who emits at a constant rate". Early in deployment that is a very short
    /// list, and it is a list the ISP can produce on request.
    #[test]
    fn the_defence_is_adoption_and_nothing_else() {
        // Identification probability among constant-rate subscribers on one provider.
        for users in [1usize, 10, 1_000, 100_000] {
            let identification = 1.0 / users as f64;
            if users < 100 {
                assert!(
                    identification > 0.01,
                    "small deployments give the ISP a workable shortlist"
                );
            }
        }
    }
}
