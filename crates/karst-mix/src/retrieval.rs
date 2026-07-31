//! What a fetch reveals, and when mixing is not enough.
//!
//! L15 makes announcement an obligation of *authorship* rather than *holding*, so replicating
//! an object is not observable. That protects the holder. **It says nothing about the
//! fetcher**, and content addressing means a request names exactly one object by hash.
//!
//! L4 conceals *who* is asking. It does not conceal *what* is asked for, and for a rare
//! enough object those are the same fact: if one person in the world wants a given document,
//! observing a request for it identifies them regardless of how well the sender is hidden.
//!
//! This module measures where that line falls. The answer sets the scope of the problem that
//! private information retrieval would have to solve, which matters because PIR is expensive
//! and applying it to everything is not affordable.

/// Requester anonymity for one object.
#[derive(Clone, Copy, Debug)]
pub struct RequestPrivacy {
    /// How many distinct parties plausibly want this object in the observation window.
    pub interested: usize,
    /// The population the fetcher is drawn from.
    pub population: usize,
    /// Probability an observer correctly names the fetcher.
    pub identification: f64,
}

impl RequestPrivacy {
    /// Whether mixing alone suffices. False means the request itself identifies the
    /// requester and no amount of sender anonymity helps.
    pub fn mixing_suffices(&self, threshold: f64) -> bool {
        self.identification <= threshold
    }
}

/// Anonymity of a request, given how many parties plausibly want the object.
///
/// The fetcher is hidden among the *interested*, not among the population. L4 hides which
/// member of the population sent a packet; it cannot hide that whoever sent it wanted this
/// specific hash, because the hash is the request.
pub fn request_privacy(interested: usize, population: usize) -> RequestPrivacy {
    let n = interested.clamp(1, population.max(1));
    RequestPrivacy {
        interested: n,
        population,
        identification: 1.0 / n as f64,
    }
}

/// A Zipf-ish popularity curve, which is what real content catalogues look like: a few
/// objects everybody wants and a very long tail nobody else does.
pub fn interested_at_rank(rank: usize, population: usize, exponent: f64) -> usize {
    let r = rank.max(1) as f64;
    ((population as f64) / r.powf(exponent)).round().max(1.0) as usize
}

/// Fraction of a catalogue for which mixing alone is insufficient.
pub fn tail_fraction(catalogue: usize, population: usize, exponent: f64, threshold: f64) -> f64 {
    let exposed = (1..=catalogue)
        .filter(|r| {
            let p = request_privacy(interested_at_rank(*r, population, exponent), population);
            !p.mixing_suffices(threshold)
        })
        .count();
    exposed as f64 / catalogue as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_popular_object_hides_its_requester() {
        // Everybody wants it, so wanting it says nothing.
        let p = request_privacy(10_000, 10_000);
        assert!(p.mixing_suffices(0.01));
        assert!(p.identification <= 0.0001);
    }

    /// **The hole.** For an object only one party wants, the request *is* the identity.
    #[test]
    fn a_unique_interest_identifies_the_requester_completely() {
        let p = request_privacy(1, 10_000);
        assert_eq!(p.identification, 1.0);
        assert!(
            !p.mixing_suffices(0.5),
            "no amount of sender anonymity helps when the request names you"
        );
    }

    #[test]
    fn anonymity_tracks_interest_not_population() {
        // A huge population does not help if only three people want the thing.
        let small = request_privacy(3, 100);
        let large = request_privacy(3, 10_000_000);
        assert_eq!(small.identification, large.identification);
    }

    /// Nearly half the catalogue sits in the exposed region even when the catalogue is
    /// *smaller* than the population, which is the flattering case.
    #[test]
    fn about_half_the_catalogue_is_exposed_when_readers_outnumber_objects() {
        let exposed = tail_fraction(10_000, 100_000, 1.0, 0.05);
        assert!(
            (0.45..0.55).contains(&exposed),
            "expected roughly half, got {:.1}%",
            exposed * 100.0
        );
    }

    /// The realistic case, and the one that matters. Real catalogues hold far more objects
    /// than the network holds people, so almost everything is tail.
    #[test]
    fn nearly_everything_is_exposed_when_objects_outnumber_readers() {
        let exposed = tail_fraction(100_000, 10_000, 1.0, 0.05);
        assert!(
            exposed > 0.98,
            "expected nearly the whole catalogue exposed, got {:.1}%",
            exposed * 100.0
        );
    }

    #[test]
    fn a_flatter_popularity_curve_exposes_less() {
        let steep = tail_fraction(10_000, 100_000, 1.2, 0.05);
        let flat = tail_fraction(10_000, 100_000, 0.6, 0.05);
        assert!(
            flat < steep,
            "flatter demand should expose less: {flat:.3} vs {steep:.3}"
        );
    }

    /// Where the boundary sits, for the record. Mixing suffices down to the rank at which
    /// twenty parties still want the object, at a 5% identification threshold.
    #[test]
    fn the_boundary_is_at_the_reciprocal_of_the_threshold() {
        for threshold in [0.5f64, 0.1, 0.05, 0.01] {
            let needed = (1.0 / threshold).ceil() as usize;
            assert!(request_privacy(needed, 1_000_000).mixing_suffices(threshold));
            assert!(!request_privacy(needed - 1, 1_000_000).mixing_suffices(threshold));
        }
    }
}
