//! KARST L6/L7 file serving.
//!
//! What IPFS does, as a native part of the stack rather than a separate network you
//! bridge to. Files are split into content-addressed chunks under a merkle manifest.
//! That buys four things at once, none of which today's web has:
//!
//! 1. **Deduplication is automatic and global.** Identical chunks have identical names,
//!    so storing the same bytes twice costs nothing, anywhere, ever.
//! 2. **Verified random access.** Any single chunk verifies against the manifest root
//!    with a merkle proof, so you can seek into the middle of a two-hour film and trust
//!    what you got without trusting whoever served it, and without fetching the rest.
//! 3. **Every reader is a server.** A peer that holds a chunk can serve it, and the
//!    bytes prove themselves. There is no trusted origin, so there is no origin to
//!    subpoena, rate-limit, or bill.
//! 4. **The origin uploads once.** [`Swarm`] measures this: origin egress stays flat
//!    while the audience grows. That is the entire economic argument against the content
//!    delivery industry, and it is a number rather than a claim.
//!
//! A stream (L7) is the same structure with the manifest still being appended to. Live
//! and archived are one object; the stream simply stops growing.

use std::collections::{BTreeMap, BTreeSet};

use karst_object::{Cid, Enc};

/// Default chunk size. Small enough that a peer joining late is useful quickly, large
/// enough that manifest overhead stays negligible.
pub const CHUNK_SIZE: usize = 64 * 1024;

fn hash_pair(l: &Cid, r: &Cid) -> Cid {
    let mut e = Enc::new();
    e.str("karst.blob.node").cid(l).cid(r);
    e.hash()
}

fn merkle_root(leaves: &[Cid]) -> Cid {
    if leaves.is_empty() {
        return Cid::of(b"karst.blob.empty");
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(hash_pair(&pair[0], &pair[1]));
            } else {
                // Odd node is promoted unchanged.
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// A merkle inclusion proof for one chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub index: usize,
    /// `(sibling_is_on_the_right, sibling_hash)` from leaf upward.
    pub siblings: Vec<(bool, Cid)>,
}

impl Proof {
    /// Bytes on the wire for this proof. Logarithmic in file size: a 4 GiB file needs
    /// 16 sibling hashes, which is 512 bytes, to verify any 64 KiB chunk.
    pub fn wire_len(&self) -> usize {
        self.siblings.len() * 32
    }
}

/// The description of a file: its chunk list and the merkle root over them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub mime: String,
    pub total_len: u64,
    pub chunk_size: u32,
    pub chunks: Vec<Cid>,
    pub root: Cid,
}

impl Manifest {
    /// Split data into chunks and build the manifest. Returns the manifest and the
    /// chunk bodies, which are ordinary objects anyone may hold and serve.
    pub fn build(name: &str, mime: &str, data: &[u8]) -> (Manifest, Vec<Vec<u8>>) {
        Manifest::build_with_chunk_size(name, mime, data, CHUNK_SIZE)
    }

    pub fn build_with_chunk_size(
        name: &str,
        mime: &str,
        data: &[u8],
        chunk_size: usize,
    ) -> (Manifest, Vec<Vec<u8>>) {
        assert!(chunk_size > 0, "chunk size must be positive");
        let bodies: Vec<Vec<u8>> = if data.is_empty() {
            Vec::new()
        } else {
            data.chunks(chunk_size).map(|c| c.to_vec()).collect()
        };
        let chunks: Vec<Cid> = bodies.iter().map(|b| Cid::of(b)).collect();
        let root = merkle_root(&chunks);
        (
            Manifest {
                name: name.to_string(),
                mime: mime.to_string(),
                total_len: data.len() as u64,
                chunk_size: chunk_size as u32,
                chunks,
                root,
            },
            bodies,
        )
    }

    /// The manifest's own content address.
    pub fn cid(&self) -> Cid {
        let mut e = Enc::new();
        e.str("karst.manifest.v1")
            .str(&self.name)
            .str(&self.mime)
            .u64(self.total_len)
            .u64(self.chunk_size as u64)
            .cid(&self.root)
            .u64(self.chunks.len() as u64);
        for c in &self.chunks {
            e.cid(c);
        }
        e.hash()
    }

    /// Merkle proof for one chunk, so a peer can verify a seek target in isolation.
    pub fn proof(&self, index: usize) -> Option<Proof> {
        if index >= self.chunks.len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut level = self.chunks.clone();
        let mut idx = index;

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for (i, pair) in level.chunks(2).enumerate() {
                if pair.len() == 2 {
                    if i * 2 == idx {
                        siblings.push((true, pair[1]));
                    } else if i * 2 + 1 == idx {
                        siblings.push((false, pair[0]));
                    }
                    next.push(hash_pair(&pair[0], &pair[1]));
                } else {
                    next.push(pair[0]);
                }
            }
            idx /= 2;
            level = next;
        }
        Some(Proof { index, siblings })
    }

    /// Verify one chunk against the root without holding any other chunk.
    ///
    /// This is what lets you trust a stranger who hands you the middle of a film.
    pub fn verify_chunk(&self, index: usize, data: &[u8], proof: &Proof) -> bool {
        if proof.index != index || index >= self.chunks.len() {
            return false;
        }
        let mut acc = Cid::of(data);
        for (sibling_on_right, sib) in &proof.siblings {
            acc = if *sibling_on_right {
                hash_pair(&acc, sib)
            } else {
                hash_pair(sib, &acc)
            };
        }
        acc == self.root
    }

    /// Which chunk indices cover a byte range, for seeking.
    pub fn chunks_for_range(&self, offset: u64, len: u64) -> Vec<usize> {
        if len == 0 || offset >= self.total_len {
            return Vec::new();
        }
        let cs = self.chunk_size as u64;
        let end = (offset + len).min(self.total_len);
        let first = (offset / cs) as usize;
        let last = ((end - 1) / cs) as usize;
        (first..=last).filter(|i| *i < self.chunks.len()).collect()
    }
}

/// A content-addressed chunk store. Deduplication is a consequence of the naming
/// scheme, not a feature anyone implemented.
#[derive(Default, Clone)]
pub struct BlobStore {
    chunks: BTreeMap<Cid, Vec<u8>>,
}

impl BlobStore {
    pub fn new() -> Self {
        BlobStore::default()
    }

    pub fn put(&mut self, data: &[u8]) -> Cid {
        let cid = Cid::of(data);
        self.chunks.entry(cid).or_insert_with(|| data.to_vec());
        cid
    }

    pub fn put_all(&mut self, bodies: &[Vec<u8>]) -> Vec<Cid> {
        bodies.iter().map(|b| self.put(b)).collect()
    }

    pub fn get(&self, cid: &Cid) -> Option<&[u8]> {
        self.chunks.get(cid).map(|v| v.as_slice())
    }

    pub fn has(&self, cid: &Cid) -> bool {
        self.chunks.contains_key(cid)
    }

    pub fn distinct_chunks(&self) -> usize {
        self.chunks.len()
    }

    pub fn bytes_stored(&self) -> usize {
        self.chunks.values().map(|v| v.len()).sum()
    }

    /// Reassemble a file, verifying every chunk against the manifest as it goes.
    /// Returns `None` if any chunk is missing or fails verification.
    pub fn assemble(&self, m: &Manifest) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(m.total_len as usize);
        for (i, cid) in m.chunks.iter().enumerate() {
            let data = self.get(cid)?;
            let proof = m.proof(i)?;
            if !m.verify_chunk(i, data, &proof) {
                return None;
            }
            out.extend_from_slice(data);
        }
        if out.len() as u64 != m.total_len {
            return None;
        }
        Some(out)
    }

    /// Read a byte range, fetching and verifying only the chunks it touches.
    pub fn read_range(&self, m: &Manifest, offset: u64, len: u64) -> Option<Vec<u8>> {
        let needed = m.chunks_for_range(offset, len);
        if needed.is_empty() {
            return Some(Vec::new());
        }
        let cs = m.chunk_size as u64;
        let mut buf = Vec::new();
        for i in &needed {
            let data = self.get(&m.chunks[*i])?;
            let proof = m.proof(*i)?;
            if !m.verify_chunk(*i, data, &proof) {
                return None;
            }
            buf.extend_from_slice(data);
        }
        let base = needed[0] as u64 * cs;
        let start = (offset - base) as usize;
        let end = ((offset + len).min(m.total_len) - base) as usize;
        Some(buf[start..end.min(buf.len())].to_vec())
    }
}

/// What a distribution run cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub audience: usize,
    /// Bytes the publisher had to push. The number the CDN industry sells you.
    pub origin_bytes: usize,
    /// Bytes peers served to each other.
    pub peer_bytes: usize,
    /// Bytes actually delivered to readers.
    pub delivered_bytes: usize,
}

impl Stats {
    /// How many times the origin's upload was multiplied by the swarm.
    pub fn amplification(&self) -> f64 {
        if self.origin_bytes == 0 {
            return 0.0;
        }
        self.delivered_bytes as f64 / self.origin_bytes as f64
    }
}

/// A minimal swarm model, to make the delivery claim measurable rather than rhetorical.
///
/// Every peer fetches the whole file. A peer prefers any other peer that already holds
/// the chunk, and falls back to the origin only when nobody else has it yet. This is
/// the same insight BitTorrent shipped in 2001.
pub struct Swarm {
    pub origin: BlobStore,
    pub peers: Vec<BlobStore>,
}

impl Swarm {
    pub fn new(origin: BlobStore, audience: usize) -> Self {
        Swarm {
            origin,
            peers: vec![BlobStore::new(); audience],
        }
    }

    pub fn distribute(&mut self, m: &Manifest) -> Stats {
        let mut origin_bytes = 0usize;
        let mut peer_bytes = 0usize;
        let mut delivered = 0usize;

        // Track which peers hold which chunk, so later peers can source from earlier ones.
        let mut holders: BTreeMap<Cid, BTreeSet<usize>> = BTreeMap::new();

        for p in 0..self.peers.len() {
            for cid in &m.chunks {
                // Already held, so nothing moves. A file that repeats a chunk is fetched
                // once, which is deduplication doing real work rather than a special case.
                if self.peers[p].has(cid) {
                    continue;
                }

                let source_peer = holders
                    .get(cid)
                    .and_then(|set| set.iter().find(|&&other| other != p).copied());

                let data = match source_peer {
                    Some(src) => {
                        let d = self.peers[src]
                            .get(cid)
                            .expect("holder set is only updated after a successful store")
                            .to_vec();
                        peer_bytes += d.len();
                        d
                    }
                    None => {
                        let d = self
                            .origin
                            .get(cid)
                            .expect("origin holds every chunk it published")
                            .to_vec();
                        origin_bytes += d.len();
                        d
                    }
                };

                delivered += data.len();
                self.peers[p].put(&data);
                holders.entry(*cid).or_default().insert(p);
            }
        }

        Stats {
            audience: self.peers.len(),
            origin_bytes,
            peer_bytes,
            delivered_bytes: delivered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64, period 2^64-1.
    ///
    /// The first version of this helper was `(i as u8).wrapping_mul(31)`, which has a
    /// period of 256 bytes, so with 1 KiB chunks every chunk of a file was byte for byte
    /// identical and deduplication collapsed the whole thing to two distinct chunks. The
    /// tests below failed and the code was right. Worth keeping the note: content
    /// addressing makes degenerate test data disappear, so test fixtures need real
    /// entropy or they measure nothing.
    fn data_of(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn round_trips_through_chunking() {
        let data = data_of(10_000, 1);
        let (m, bodies) = Manifest::build_with_chunk_size("f.bin", "application/octet-stream", &data, 1024);
        let mut store = BlobStore::new();
        store.put_all(&bodies);
        assert_eq!(store.assemble(&m).unwrap(), data);
    }

    #[test]
    fn empty_and_single_chunk_files_work() {
        for len in [0usize, 1, 1024] {
            let data = data_of(len, 3);
            let (m, bodies) = Manifest::build_with_chunk_size("f", "b", &data, 1024);
            let mut s = BlobStore::new();
            s.put_all(&bodies);
            assert_eq!(s.assemble(&m).unwrap(), data, "failed at len {len}");
        }
    }

    #[test]
    fn every_chunk_verifies_against_the_root_in_isolation() {
        let data = data_of(9_000, 2);
        let (m, bodies) = Manifest::build_with_chunk_size("f", "b", &data, 1024);
        for (i, body) in bodies.iter().enumerate() {
            let p = m.proof(i).unwrap();
            assert!(m.verify_chunk(i, body, &p), "chunk {i} failed");
        }
    }

    #[test]
    fn a_corrupted_chunk_is_rejected_even_from_a_trusted_peer() {
        let data = data_of(9_000, 2);
        let (m, bodies) = Manifest::build_with_chunk_size("f", "b", &data, 1024);
        let p = m.proof(3).unwrap();
        let mut evil = bodies[3].clone();
        evil[0] ^= 0xff;
        assert!(!m.verify_chunk(3, &evil, &p));

        // and assembly refuses the file entirely
        let mut store = BlobStore::new();
        store.put_all(&bodies);
        store.chunks.insert(m.chunks[3], evil);
        assert!(store.assemble(&m).is_none());
    }

    #[test]
    fn a_proof_cannot_be_replayed_at_another_index() {
        let data = data_of(9_000, 5);
        let (m, bodies) = Manifest::build_with_chunk_size("f", "b", &data, 1024);
        let p0 = m.proof(0).unwrap();
        assert!(!m.verify_chunk(1, &bodies[1], &p0));
    }

    #[test]
    fn proofs_are_logarithmic() {
        let data = data_of(64 * 1024, 7);
        let (m, _) = Manifest::build_with_chunk_size("f", "b", &data, 1024);
        assert_eq!(m.chunks.len(), 64);
        assert_eq!(m.proof(0).unwrap().siblings.len(), 6); // log2(64)
    }

    #[test]
    fn identical_content_deduplicates_across_different_files() {
        let shared = data_of(4096, 9);
        let mut a = shared.clone();
        a.extend_from_slice(&data_of(1024, 1));
        let mut b = shared.clone();
        b.extend_from_slice(&data_of(1024, 2));

        let (ma, ba) = Manifest::build_with_chunk_size("a", "b", &a, 1024);
        let (mb, bb) = Manifest::build_with_chunk_size("b", "b", &b, 1024);

        let mut store = BlobStore::new();
        store.put_all(&ba);
        let after_first = store.distinct_chunks();
        store.put_all(&bb);
        let after_second = store.distinct_chunks();

        assert_eq!(after_first, 5);
        // Only the one differing chunk is new; four shared chunks cost nothing.
        assert_eq!(after_second, 6);
        assert_ne!(ma.root, mb.root);
        assert_eq!(store.assemble(&ma).unwrap(), a);
        assert_eq!(store.assemble(&mb).unwrap(), b);
    }

    #[test]
    fn seeking_fetches_only_the_chunks_it_needs() {
        let data = data_of(10_000, 4);
        let (m, bodies) = Manifest::build_with_chunk_size("f", "b", &data, 1024);
        let mut store = BlobStore::new();
        store.put_all(&bodies);

        assert_eq!(m.chunks_for_range(5000, 100), vec![4]);
        assert_eq!(m.chunks_for_range(1020, 10), vec![0, 1]);
        assert_eq!(store.read_range(&m, 5000, 100).unwrap(), &data[5000..5100]);
        assert_eq!(store.read_range(&m, 0, 1).unwrap(), &data[0..1]);
        assert_eq!(
            store.read_range(&m, 9990, 100).unwrap(),
            &data[9990..10_000]
        );
    }

    #[test]
    fn origin_egress_stays_flat_as_the_audience_grows() {
        let data = data_of(64_000, 11);
        let (m, bodies) = Manifest::build_with_chunk_size("film", "video/x", &data, 1024);
        let mut origin = BlobStore::new();
        origin.put_all(&bodies);

        let small = Swarm::new(origin.clone(), 10).distribute(&m);
        let large = Swarm::new(origin.clone(), 1000).distribute(&m);

        // The publisher pushes the file exactly once in both cases.
        assert_eq!(small.origin_bytes, data.len());
        assert_eq!(large.origin_bytes, data.len());

        assert_eq!(large.delivered_bytes, data.len() * 1000);
        assert!(large.amplification() > 999.0);
        assert!(small.amplification() > 9.0);
    }
}
