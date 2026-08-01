//! L7 Streams: carrying things too large for the mix network.
//!
//! A client emitting 60 fixed-size packets a second sends about 41 KB/s, so an hour of video
//! takes over ten hours. Raising the rate until video fits multiplies the constant cost for
//! **every** client, including the ones who only send text, because constant-rate emission is
//! constant whether or not anyone is speaking. `karst-bulkcost` prints the table.
//!
//! This is not an implementation problem. Das, Meiser, Mohammadi and Kate (*Anonymity
//! Trilemma*, IEEE S&P 2018) prove that strong anonymity, low bandwidth overhead and low
//! latency are not simultaneously achievable; constant-rate emission is this design choosing
//! the first two and paying in the third. **No amount of engineering removes it.**
//!
//! So bulk moves another way, and the exposure is written down rather than hoped away.
//!
//! # The asymmetry that makes the split safe
//!
//! A manifest is signed and names every chunk by content address. A chunk fetched over any
//! path at all is checked against the manifest's merkle tree, so:
//!
//! > **Integrity survives the exposed path. Privacy does not.**
//!
//! A hostile carrier of bulk can refuse to serve, serve slowly, or serve garbage that is
//! detected immediately. It cannot substitute. That is why the split is a privacy decision
//! rather than a trust one, and why it can be made per fetch by the reader rather than being
//! fixed by the publisher.
//!
//! # What a direct fetch reveals
//!
//! Everything in [`Exposure`], and it is worth reading rather than summarising. The sharpest
//! part is that a chunk's content address is **stable across every reader**, which is what
//! makes deduplication work and equally makes a chunk identifier a durable fingerprint: an
//! adversary who once learns that a chunk belongs to some work knows it for every reader who
//! ever fetches it. Deduplication and unlinkability are in direct opposition here, and this
//! design takes deduplication.

use karst_object::Cid;

/// How a reader chose to fetch something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carriage {
    /// Over the mix network. Sender and receiver concealed, at roughly 41 KB/s.
    Mixed,
    /// Straight to a provider. Fast, and everything in [`Exposure`] applies.
    Direct,
}

/// What a carriage choice reveals, enumerated so a caller cannot claim they were not told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exposure {
    /// The carrier learns the reader's network address.
    pub reader_address: bool,
    /// The carrier learns which content addresses the reader asked for.
    pub content_requested: bool,
    /// An observer of the link learns how much was transferred and when.
    pub volume_and_timing: bool,
    /// The carrier can serve wrong bytes without being caught.
    pub can_substitute: bool,
}

impl Carriage {
    pub fn exposure(&self) -> Exposure {
        match self {
            Carriage::Mixed => Exposure {
                reader_address: false,
                content_requested: false,
                volume_and_timing: false,
                // Never, at either carriage. The manifest's merkle tree decides.
                can_substitute: false,
            },
            Carriage::Direct => Exposure {
                reader_address: true,
                content_requested: true,
                volume_and_timing: true,
                can_substitute: false,
            },
        }
    }

    /// Bytes per second a client can expect.
    pub fn throughput(&self, packets_per_sec: f64) -> f64 {
        match self {
            Carriage::Mixed => packets_per_sec * crate::frame::DATA_BYTES as f64,
            // Whatever the link does. Quoted as a round figure only to make the ratio in
            // `plan` meaningful; nothing depends on the exact value.
            Carriage::Direct => 10.0 * 1024.0 * 1024.0,
        }
    }
}

/// What a reader intends to fetch, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchPlan {
    /// Fetched over the mix network. Small and worth concealing.
    pub mixed: Vec<Cid>,
    /// Fetched directly. Large, and the exposure applies.
    pub direct: Vec<Cid>,
    /// Bytes that will cross the exposed path.
    pub exposed_bytes: u64,
}

impl FetchPlan {
    /// Whether anything at all crosses the exposed path.
    pub fn leaks(&self) -> bool {
        !self.direct.is_empty()
    }

    /// How long the whole fetch takes if it all goes over the mix network instead.
    ///
    /// Offered so a caller choosing exposure can see the price of not choosing it. Refusing to
    /// compute this would make the safe option invisible.
    pub fn seconds_if_all_mixed(&self, packets_per_sec: f64) -> f64 {
        self.exposed_bytes as f64 / Carriage::Mixed.throughput(packets_per_sec)
    }
}

/// The largest object that goes over the mix network by default.
///
/// A manifest and a document sit far below this; a media chunk sits far above. The threshold
/// is a policy rather than a law, which is why `plan` takes it.
pub const DEFAULT_MIXED_LIMIT: u64 = 64 * 1024;

/// Decide carriage per object.
///
/// The **manifest always goes over the mix network**, whatever it costs, because it is what
/// names everything else. A reader who fetches a manifest directly has told the carrier what
/// work they are about to read, and no amount of care about the chunks afterwards undoes that.
pub fn plan(manifest: Cid, chunks: &[(Cid, u64)], mixed_limit: u64) -> FetchPlan {
    let mut mixed = vec![manifest];
    let mut direct = Vec::new();
    let mut exposed_bytes = 0u64;

    for (cid, size) in chunks {
        if *size <= mixed_limit {
            mixed.push(*cid);
        } else {
            direct.push(*cid);
            exposed_bytes += size;
        }
    }
    FetchPlan {
        mixed,
        direct,
        exposed_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_blob::Manifest;

    fn cid(n: u8) -> Cid {
        Cid::of(&[n])
    }

    /// A chunk that crossed the exposed path must still be verified.
    ///
    /// This is what makes the split a privacy decision rather than a trust one. A hostile
    /// carrier can refuse, stall, or corrupt, and corruption is caught immediately.
    #[test]
    fn a_chunk_fetched_over_the_exposed_path_is_still_verified() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let (m, chunks) = Manifest::build("film", "video/mp4", &data);

        for (i, chunk) in chunks.iter().enumerate() {
            let proof = m.proof(i).expect("chunk exists");
            assert!(m.verify_chunk(i, chunk, &proof), "honest chunk {i} refused");

            // The carrier substitutes.
            let mut tampered = chunk.clone();
            tampered[0] ^= 0x01;
            assert!(
                !m.verify_chunk(i, &tampered, &proof),
                "a substituted chunk {i} was accepted from the exposed path"
            );
        }
    }

    /// Neither carriage permits substitution, which is the point of stating exposure as a set
    /// of separate facts rather than one word.
    #[test]
    fn no_carriage_permits_substitution() {
        assert!(!Carriage::Mixed.exposure().can_substitute);
        assert!(!Carriage::Direct.exposure().can_substitute);
    }

    /// The direct path reveals strictly more than the mixed one, and says which parts.
    #[test]
    fn the_direct_path_reveals_more_and_enumerates_what() {
        let m = Carriage::Mixed.exposure();
        let d = Carriage::Direct.exposure();
        assert!(!m.reader_address && d.reader_address);
        assert!(!m.content_requested && d.content_requested);
        assert!(!m.volume_and_timing && d.volume_and_timing);
    }

    /// The manifest must never be planned onto the exposed path.
    ///
    /// It names everything else, so fetching it directly tells the carrier which work is about
    /// to be read, and being careful with the chunks afterwards does not undo that.
    #[test]
    fn the_manifest_always_goes_over_the_mix_network() {
        let big = [(cid(1), 10_000_000u64), (cid(2), 10_000_000)];
        let p = plan(cid(0), &big, DEFAULT_MIXED_LIMIT);
        assert!(p.mixed.contains(&cid(0)));
        assert!(!p.direct.contains(&cid(0)));

        // Even with a limit of zero, which would otherwise push everything out.
        let p = plan(cid(0), &big, 0);
        assert_eq!(p.mixed, vec![cid(0)]);
        assert_eq!(p.direct.len(), 2);
    }

    /// Small content stays on the mix network entirely, and reports no leak.
    #[test]
    fn small_content_never_leaves_the_mix_network() {
        let small = [(cid(1), 900u64), (cid(2), 4_000), (cid(3), 64 * 1024)];
        let p = plan(cid(0), &small, DEFAULT_MIXED_LIMIT);
        assert!(p.direct.is_empty());
        assert!(!p.leaks());
        assert_eq!(p.exposed_bytes, 0);
        assert_eq!(p.mixed.len(), 4);
    }

    /// A plan must be able to tell a reader what the safe option would have cost.
    ///
    /// A design that makes exposure convenient and hides the price of avoiding it has decided
    /// for the reader while appearing to offer a choice.
    #[test]
    fn a_plan_reports_what_the_private_path_would_have_cost() {
        let hour_of_video = 1_610_612_736u64;
        let p = plan(cid(0), &[(cid(1), hour_of_video)], DEFAULT_MIXED_LIMIT);
        assert!(p.leaks());
        let secs = p.seconds_if_all_mixed(60.0);
        assert!(
            secs > 30_000.0,
            "an hour of video should take many hours over the mix network, got {secs:.0}s"
        );
    }

    /// Deduplication and unlinkability pull against each other, and this takes deduplication.
    ///
    /// A chunk's content address is identical for every reader and every publisher, which is
    /// what makes storage efficient and equally makes a chunk identifier a durable
    /// fingerprint. Two publishers of the same film produce the same chunk addresses, so an
    /// adversary who learns the mapping once knows it for everyone.
    #[test]
    fn identical_content_produces_identical_addresses_for_everyone() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (a, a_chunks) = Manifest::build("film", "video/mp4", &data);
        let (b, b_chunks) = Manifest::build("a different name", "video/mp4", &data);

        // Different manifests, because the name differs.
        assert_ne!(a.cid(), b.cid());
        // Identical chunks, which is the whole of the benefit and the whole of the leak.
        assert_eq!(a_chunks, b_chunks);
        assert_eq!(a.chunks, b.chunks);
    }
}
