//! KARST L4 Mixing.
//!
//! The layer that defends against the global passive adversary: someone who watches every
//! link in the network at once. Onion routing explicitly declines to defend against this,
//! and that decision is the single largest architectural difference between KARST and Tor.
//!
//! Encryption solves content and does nothing about **volume** or **timing**, both of
//! which survive any number of encryption layers. This layer removes both:
//!
//! - [`packet`] gives fixed size, per-hop unlinkable packets with sender-chosen delays, so
//!   nothing about a packet's appearance or length carries information.
//! - Constant rate emission means volume carries nothing: an idle node and a node
//!   streaming a film are indistinguishable.
//! - Poisson per-hop delay means timing carries nothing: a packet leaving a mix has no
//!   timing relationship to the packet that entered.
//! - [`sim`] measures whether that actually works, against an adversary observing
//!   everything.
//!
//! Design follows Loopix (Piotrowska et al., USENIX Security 2017). See
//! `docs/05-anonymity.md`.
//!
//! # Status
//!
//! The packet format implements the Sphinx construction: a per-hop header MAC verified before
//! any processing, a wide-block payload cipher so modification randomises rather than marks,
//! constant-length headers with proper filler, and replay tags. That closes the tagging attack
//! class the 2014 CMU/CERT campaign against Tor exploited.
//!
//! Two deviations remain and are documented in [`packet`]: the group element is re-derived
//! rather than blinded, because X25519 clamping does not compose the way the proof assumes,
//! and the primitives are BLAKE3-based rather than the paper's. It is not a reviewed
//! implementation.
//!
//! The simulators model the design rather than an implementation. Passing here is necessary
//! and nowhere near sufficient.

pub mod active;
pub mod exposure;
pub mod frontier;
pub mod intersection;
pub mod loops;
pub mod packet;
pub mod retrieval;
pub mod sim;

pub use active::{
    batch_under_skew, drain_cost, n_minus_one, ActiveConfig, ActiveResult, Discipline, SkewResult,
};
pub use packet::{Hop, MixError, MixKey, Packet, Peeled, SeenTags, PACKET_BYTES, MAX_HOPS};
pub use sim::{run, SimConfig, SimResult};

/// Traffic classes, per `docs/05-anonymity.md` section 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// The default. Full Poisson delay, resists a global passive adversary, latency in
    /// seconds.
    Deferred,
    /// Opt in. Forwarded promptly, approximately Tor's guarantee, does **not** resist a
    /// global passive adversary.
    ///
    /// Selecting this is observable and puts the user in a smaller anonymity set. A
    /// client must say so at the point of choice rather than in documentation.
    Prompt,
}

impl Default for Class {
    fn default() -> Self {
        // Anonymity is the default path, not a mode. If the anonymous option is a special
        // slow mode, only those who badly need it turn it on, and turning it on marks
        // them.
        Class::Deferred
    }
}

impl Class {
    pub fn resists_global_passive_adversary(&self) -> bool {
        matches!(self, Class::Deferred)
    }

    /// The warning a client is required to show when the user selects this class.
    pub fn advisory(&self) -> &'static str {
        match self {
            Class::Deferred => "Resists an observer watching the whole network.",
            Class::Prompt => {
                "Faster, and NOT protected against an observer watching both ends. \
                 Choosing this is itself visible."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_anonymous_class_is_the_default() {
        assert_eq!(Class::default(), Class::Deferred);
        assert!(Class::default().resists_global_passive_adversary());
    }

    #[test]
    fn the_fast_class_admits_what_it_does_not_do() {
        assert!(!Class::Prompt.resists_global_passive_adversary());
        assert!(Class::Prompt.advisory().contains("NOT protected"));
    }
}
