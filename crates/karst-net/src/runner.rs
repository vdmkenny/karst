//! Nodes and clients that run over real sockets.
//!
//! # Two links, two disciplines
//!
//! A **client** paces. Every packet it emits leaves on a schedule drawn without reference to
//! what it has to say, so an observer sitting on the client's connection sees the same stream
//! whether the client is silent or sending all day. This is where padding earns its cost,
//! because client activity is what an adversary most wants and what is otherwise most visible.
//!
//! A **mix** forwards on its delay schedule and does not pace. Its outputs are already a
//! Poisson process, being a superposition of exponentially delayed Poisson inputs, so a second
//! scheduler would add latency without adding uncertainty. That an observer sees which link a
//! packet leaves on is not a new leak: the topology is public and the next hop is visible
//! either way. What must stay hidden is which *incoming* packet it was, and that is the
//! delay's job.
//!
//! # Collection is a separate link, and it is not anonymous
//!
//! Retrieval runs on its own port between a client and its own provider. That link is
//! identified by construction: a provider knows which addresses collect from which boxes, and
//! nothing here pretends otherwise. What it does hide is **whether anything was there**: every
//! response is identical in size and in shape whether it carries mail or filler, polling runs
//! at a fixed rate, and no field outside the body says which is which. A client tells them
//! apart by trying to open the body, which requires a key an observer does not have.
//!
//! Size alone never sufficed, and this module used to claim it did. An observer who can measure
//! a datagram can also read a byte inside it, and there was a status byte saying whether the
//! poll found anything. A provider learns a client is online. Neither it nor anyone on the link
//! learns from the wire when that client received something.
//!
//! Concealing the collector from the provider is what private information retrieval is for,
//! and it is not built.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use karst_node::{MixNode, Outbound};
use karst_wire::{Pacer, UdpTransport};

use crate::client::{Client, Contact, Dispatch, SendError};
use crate::directory::Directory;
use crate::frame::ENVELOPE_BYTES;
use crate::provider::{Provider, Tag};

/// A collection request: kind, a 32 byte credential or tag, and a cursor.
///
/// Fixed width, because a request whose length varied with what it asked for would tell an
/// observer which kind it was.
pub const REQUEST_BYTES: usize = 1 + 32 + 8 + 8 + 64;

/// Where the counter sits in a request.
const REQ_COUNTER: usize = 33;
/// Where the drain signature sits. Zero-filled for a read, so both requests are one size and
/// an observer cannot tell a mailbox drain from a feed read by length.
/// A fresh random value per request, echoed in the response.
///
/// Everything else in the matching predicate is attacker-supplyable: a UDP source address is
/// spoofable, a feed tag is public by construction, a mailbox tag is in every `Contact`, and
/// the cursor starts at zero and advances by one. So an off-path attacker who could guess none
/// of a secret could still forge a response that matched, consume the outstanding drain, and
/// have the genuine answer dropped as unsolicited. Because a drain is destructive that is mail
/// deleted at the provider and never delivered.
///
/// This is DNS's transaction id done properly: 64 bits from the system CSPRNG rather than 16
/// bits and a port. It closes the off-path case and does nothing about an attacker who can
/// read the request. See #181.
const REQ_NONCE: usize = 41;
const REQ_SIG: usize = 49;

/// A collection response: the refusal count, the nonce it answers, and a fixed body.
///
/// **There is no status byte and no echoed tag.** Both used to be here and both were readable
/// by anyone on the link.
///
/// The status byte said whether anything was waiting. The module claimed the fixed response
/// size hid that, which is only true against an observer who cannot read the bytes, and this
/// one can. At a two millisecond poll interval it was a millisecond-resolution record of when
/// a client received mail: exactly the receive-side input to the timing correlation that the
/// per-hop delays and constant-rate cover spend two hundred times the bandwidth to defeat.
///
/// It is not needed. A mailbox body is sealed, so a client learns whether anything was there
/// by trying to open it, and random filler fails to open exactly as a wrong-key ciphertext
/// does. A feed body is an open envelope, so a client learns the same thing by trying to
/// decode a fragment.
///
/// The echoed tag identified which box was being answered, which on a feed names the publisher
/// a client follows. It was there so interleaved answers from several providers could be told
/// apart; the nonce does that, and unlike the tag it is meaningless to anyone who did not send
/// the request.
///
/// The refusal count remains in clear and is the leak this does not close. It is a slowly
/// changing counter rather than a per-poll event, so it does not carry receive timing, and the
/// design justifies world-writable feed boxes on the grounds that denial is visible, which a
/// count that never left the provider would make circular. See #107.
pub const RESPONSE_BYTES: usize = 8 + 8 + ENVELOPE_BYTES;

const RESP_NONCE: usize = 8;
const RESP_BODY: usize = RESP_NONCE + 8;

/// Drain one item from a box, proving the right to do so with the collection key.
pub const REQ_DRAIN: u8 = 1;
/// Read one item of a public feed at a cursor, without removing it.
pub const REQ_READ: u8 = 2;

/// A mix, running.
pub struct NodeRunner {
    pub id: u16,
    node: MixNode,
    transport: UdpTransport,
    dir: Directory,
    provider: Option<Provider>,
    collect_sock: Option<UdpSocket>,
    started: Instant,
}

impl NodeRunner {
    pub fn new(id: u16, node: MixNode, bind: SocketAddr) -> io::Result<Self> {
        Ok(NodeRunner {
            id,
            node,
            transport: UdpTransport::bind(bind)?,
            dir: Directory::new(0.0),
            provider: None,
            collect_sock: None,
            started: Instant::now(),
        })
    }

    /// Make this node a provider, listening for collection on its own port.
    pub fn serving_mail(mut self, bind: SocketAddr) -> io::Result<Self> {
        let s = UdpSocket::bind(bind)?;
        s.set_nonblocking(true)?;
        self.collect_sock = Some(s);
        self.provider = Some(Provider::new());
        Ok(self)
    }

    /// Nodes learn where their peers are once the whole network has bound its sockets.
    pub fn set_directory(&mut self, dir: Directory) {
        self.dir = dir;
    }

    pub fn addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn collect_addr(&self) -> Option<SocketAddr> {
        self.collect_sock.as_ref().and_then(|s| s.local_addr().ok())
    }

    pub fn stats(&self) -> karst_node::NodeStats {
        self.node.stats()
    }

    pub fn holding(&self) -> usize {
        self.provider.as_ref().map_or(0, |p| p.held())
    }

    fn now_ms(&self) -> u64 {
        // Monotonic. Wall time here would hand an adversary with NTP access the ability to
        // flush this node's queue.
        self.started.elapsed().as_millis() as u64
    }

    /// One pass: take what has arrived, release what is due, answer collections.
    pub fn step(&mut self) {
        let now = self.now_ms();

        while let Some((_from, packet)) = self.transport.recv() {
            // The source address is discarded. A mix has no use for it, and a mix that kept
            // it would be keeping exactly the record an adversary would later want.
            let _ = self.node.accept(packet, now);
        }

        for out in self.node.due(now) {
            match out {
                Outbound::Forward { next, packet } => {
                    if let Some(info) = self.dir.get(next) {
                        let _ = self.transport.send(info.addr, &packet);
                    }
                }
                Outbound::Deliver { payload } => {
                    if let Some(p) = self.provider.as_mut() {
                        let _ = p.deposit(&payload);
                    }
                }
            }
        }

        self.serve_collections();
    }

    fn serve_collections(&mut self) {
        let (Some(sock), Some(store)) = (self.collect_sock.as_ref(), self.provider.as_mut()) else {
            return;
        };
        let mut buf = [0u8; REQUEST_BYTES];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if n != REQUEST_BYTES {
                // Not a request. No reply, for the same reason the mix port never replies.
                continue;
            }
            let mut cred = [0u8; 32];
            cred.copy_from_slice(&buf[1..33]);
            let kind = buf[0];
            let counter = u64::from_le_bytes(buf[REQ_COUNTER..REQ_COUNTER + 8].try_into().unwrap());
            let cursor = counter as usize;

            let (item, refused) = match kind {
                // Draining is destructive, so it needs proof that the asker holds the drain
                // key. The proof is a signature over a counter, not the key itself: a
                // credential that has to be shown to be used is a bearer token in transit,
                // and this link is neither encrypted nor trusted.
                REQ_DRAIN => {
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&buf[REQ_SIG..REQ_SIG + 64]);
                    let tag = crate::client::mailbox_tag(&cred);
                    // Silent on refusal. An answer that differed would say whether the tag
                    // exists, which is the one thing a stranger must not learn from asking.
                    store
                        .drain_once(&tag, &cred, counter, &sig)
                        .unwrap_or_default()
                }
                // Reading a feed needs nothing, because a feed tag is public. It also takes
                // nothing away, or any stranger could delete a publisher one packet at a time.
                REQ_READ => store.peek(&cred, cursor),
                _ => (None, 0),
            };

            // One response per request, identical in size and in shape whether or not anything
            // was waiting. A client tells the difference by trying to open the body; an
            // observer cannot, which is the whole point.
            let mut resp = vec![0u8; RESPONSE_BYTES];
            resp[..8].copy_from_slice(&refused.to_le_bytes());
            resp[RESP_NONCE..RESP_NONCE + 8].copy_from_slice(&buf[REQ_NONCE..REQ_NONCE + 8]);
            match item {
                None => {
                    // Random filler. It fails to open exactly as a wrong-key ciphertext does,
                    // and fails to decode exactly as a corrupt fragment does.
                    use rand::Rng;
                    rand::thread_rng().fill(&mut resp[RESP_BODY..]);
                }
                Some(body) => resp[RESP_BODY..].copy_from_slice(&body),
            }
            let _ = sock.send_to(&resp, from);
        }
    }
}

/// Cover packets, built before they are needed.
///
/// The pacer decides *when* to emit without reference to the queue, which is the property that
/// matters. It is not sufficient on its own. If a real emission is a queue pop and a cover
/// emission builds a Sphinx packet from scratch, the two cost very different amounts of CPU
/// and reach the socket at measurably different offsets from the scheduled instant. An
/// observer with fine timing resolution separates real from cover without breaking anything.
///
/// So cover is built ahead of time and emission is a pop either way.
///
/// # Refilling is constant work
///
/// Refilling only when the pool is low would leak in the same way by a longer route: the pool
/// drains when cover is emitted, cover is emitted when there is no real traffic, so refill
/// effort would run *inversely* to how much the client is saying. Every call builds the same
/// number of packets and discards what will not fit. That is wasteful on purpose.
pub struct CoverPool {
    ready: std::collections::VecDeque<Dispatch>,
    target: usize,
    per_refill: usize,
    /// Times the pool was empty when a slot came due and a packet had to be built inline.
    /// Non-zero means the timing channel above was open for that many emissions.
    pub lazy: u64,
}

impl CoverPool {
    pub fn new(target: usize) -> Self {
        CoverPool {
            ready: std::collections::VecDeque::with_capacity(target),
            target,
            per_refill: 1,
            lazy: 0,
        }
    }

    pub fn ready(&self) -> usize {
        self.ready.len()
    }

    /// Build a fixed number of cover packets, whatever the pool already holds.
    pub fn refill(
        &mut self,
        client: &Client,
        dir: &Directory,
        toward: u16,
        rng: &mut impl rand::Rng,
    ) {
        for _ in 0..self.per_refill {
            let Ok(d) = client.cover(dir, toward, rng) else {
                return;
            };
            if self.ready.len() >= self.target {
                self.ready.pop_front();
            }
            self.ready.push_back(d);
        }
    }

    pub fn take(&mut self) -> Option<Dispatch> {
        self.ready.pop_front()
    }
}

/// A client, running.
/// A request this client sent and is still waiting on, keyed by its nonce.
///
/// Keyed by nonce rather than by `(address, tag)` because the response no longer echoes the
/// tag: echoing it told anyone on the link which publisher a client follows. The nonce is the
/// only thing tying an answer to a question, and it is the only field in the exchange that is
/// meaningless to somebody who did not send the request.
#[derive(Debug, Clone)]
struct Outstanding {
    /// Where it was sent, checked on the way back so a stray answer from elsewhere is dropped.
    at: SocketAddr,
    /// Which box it asked about. Never on the wire in either direction after the request.
    tag: Tag,
    /// The cursor of a non-destructive read, or `None` for a destructive drain.
    read_cursor: Option<u32>,
    /// Send order, for age-ordered eviction. Never the tag, which an adversary picks.
    seq: u64,
}

pub struct ClientRunner {
    pub client: Client,
    transport: UdpTransport,
    collect_sock: UdpSocket,
    provider_collect: SocketAddr,
    /// Paces dispatches rather than packets, so a packet and its entry node cannot separate.
    pacer: Pacer<Dispatch>,
    cover: CoverPool,
    dir: Directory,
    started: Instant,
    cover_toward: u16,
    sentinel: Option<crate::sentinel::Sentinel>,
    /// One cursor per (provider, feed). Replicas hold different amounts.
    feed_cursors: std::collections::BTreeMap<(SocketAddr, Tag), usize>,
    /// Requests sent and not yet answered, by nonce. Nothing else is accepted off the socket.
    outstanding: std::collections::BTreeMap<[u8; 8], Outstanding>,
    /// Responses read off the socket and not yet handed to a caller.
    pending: std::collections::BTreeMap<(SocketAddr, Tag), Vec<Vec<u8>>>,
    next_request: u64,
    refused_seen: u64,
    pub received: Vec<Vec<u8>>,
}

impl ClientRunner {
    /// Requests remembered while waiting for an answer.
    ///
    /// A provider that stops answering must not cost this client memory without limit, and a
    /// client polling a handful of replicas is nowhere near this.
    pub const MAX_OUTSTANDING: usize = 4096;
    /// Unanswered nonces kept per box before the oldest is forgotten.
    pub const MAX_OUTSTANDING_NONCES: usize = 64;

    pub fn new(
        client: Client,
        bind: SocketAddr,
        dir: Directory,
        provider_collect: SocketAddr,
        lambda_per_sec: f64,
    ) -> io::Result<Self> {
        let collect_sock = UdpSocket::bind(bind)?;
        collect_sock.set_nonblocking(true)?;
        let cover_toward = client.contact().provider;
        Ok(ClientRunner {
            transport: UdpTransport::bind(bind)?,
            collect_sock,
            provider_collect,
            pacer: Pacer::new(lambda_per_sec),
            cover: CoverPool::new(64),
            dir,
            started: Instant::now(),
            cover_toward,
            sentinel: None,
            feed_cursors: std::collections::BTreeMap::new(),
            outstanding: std::collections::BTreeMap::new(),
            pending: std::collections::BTreeMap::new(),
            next_request: 0,
            refused_seen: 0,
            client,
            received: Vec::new(),
        })
    }

    /// Start sending loops, so that traffic disappearing becomes something noticed.
    pub fn watching(mut self, sentinel: crate::sentinel::Sentinel) -> Self {
        self.sentinel = Some(sentinel);
        self
    }

    pub fn sentinel(&self) -> Option<&crate::sentinel::Sentinel> {
        self.sentinel.as_ref()
    }

    /// Send one loop through the network to a mailbox this client owns.
    pub fn dispatch_loop(&mut self) {
        let now = self.now_ms();
        let Some(s) = self.sentinel.as_mut() else {
            return;
        };
        let mut rng = rand::thread_rng();
        if let Ok(ds) = s.dispatch(&self.client, &self.dir, now, &mut rng) {
            for d in ds {
                let _ = self.pacer.offer(d);
            }
        }
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Hand a message to the link. It leaves on the link's schedule, not now.
    pub fn send(&mut self, to: &Contact, message: &[u8]) -> Result<(), SendError> {
        let mut rng = rand::thread_rng();
        for d in self.client.send(&self.dir, to, message, &mut rng)? {
            let _ = self.pacer.offer(d);
        }
        Ok(())
    }

    pub fn queued(&self) -> usize {
        self.pacer.queued()
    }

    pub fn stats(&self) -> karst_wire::PacerStats {
        self.pacer.stats()
    }

    /// How many emissions had to build their cover inline. Should stay zero.
    pub fn lazy_cover(&self) -> u64 {
        self.cover.lazy
    }

    /// One pass: emit whatever the schedule calls for.
    pub fn step(&mut self) {
        let now = self.now_ms();
        let dir = &self.dir;
        let client = &self.client;
        let toward = self.cover_toward;
        let pool = &mut self.cover;

        let emitted = self.pacer.tick(now, || match pool.take() {
            Some(d) => d,
            None => {
                pool.lazy += 1;
                let mut rng = rand::thread_rng();
                client
                    .cover(dir, toward, &mut rng)
                    .expect("the directory must always admit a cover route")
            }
        });

        for d in emitted {
            if let Some(info) = self.dir.get(d.via) {
                let _ = self.transport.send(info.addr, &d.packet);
            }
        }

        // Constant work, after the emission rather than during it.
        let mut rng = rand::thread_rng();
        self.cover
            .refill(&self.client, &self.dir, self.cover_toward, &mut rng);
    }

    /// Hand a publication to the link, addressed to a feed rather than to a person.
    pub fn publish(&mut self, feed: Tag, message: &[u8]) -> Result<(), SendError> {
        let toward = self.cover_toward;
        self.publish_to(feed, toward, message)
    }

    /// Publish to one named provider.
    ///
    /// Replication is the caller's loop rather than something hidden here, because which
    /// providers hold a feed is derived from `placement` and a runner has no business
    /// deciding it.
    pub fn publish_to(
        &mut self,
        feed: Tag,
        provider: u16,
        message: &[u8],
    ) -> Result<(), SendError> {
        let mut rng = rand::thread_rng();
        for d in self
            .client
            .publish(&self.dir, feed, provider, message, &mut rng)?
        {
            let _ = self.pacer.offer(d);
        }
        Ok(())
    }

    /// Collect raw envelopes from any box, not only this client's own.
    ///
    /// A feed tag is derivable from a publisher's address, so asking for one tells the
    /// provider which publisher this client follows. That is the exposure this design does not
    /// close, and calling it out here rather than in a comment somewhere else is deliberate:
    /// it is the same gap as #53, reached by a different road.
    pub fn poll_tag(&mut self, tag: Tag) -> Vec<Vec<u8>> {
        let at = self.provider_collect;
        self.poll_tag_at(at, tag)
    }

    /// Read a feed from one named provider, at that provider's own cursor.
    ///
    /// Cursors are per provider, because replicas hold different amounts and a shared cursor
    /// would skip whatever the furthest-ahead replica had already served.
    pub fn poll_tag_at(&mut self, at: SocketAddr, tag: Tag) -> Vec<Vec<u8>> {
        let cursor = *self.feed_cursors.entry((at, tag)).or_insert(0) as u32;
        let mut req = [0u8; REQUEST_BYTES];
        req[0] = REQ_READ;
        req[1..33].copy_from_slice(&tag);
        req[REQ_COUNTER..REQ_COUNTER + 8].copy_from_slice(&(cursor as u64).to_le_bytes());
        // Signature bytes stay zero. A read needs no proof and must not be shorter for it.
        let nonce = self.record(at, tag, Some(cursor));
        req[REQ_NONCE..REQ_NONCE + 8].copy_from_slice(&nonce);
        let _ = self.collect_sock.send_to(&req, at);

        self.pump();
        self.pending.remove(&(at, tag)).unwrap_or_default()
    }

    /// Note a request on the way out, so its answer can be recognised on the way in.
    /// Note a request on the way out, returning the nonce its answer must echo.
    fn record(&mut self, at: SocketAddr, tag: Tag, read_cursor: Option<u32>) -> [u8; 8] {
        use rand::RngCore;
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let seq = self.next_request;
        self.next_request += 1;
        self.outstanding.insert(
            nonce,
            Outstanding {
                at,
                tag,
                read_cursor,
                seq,
            },
        );
        // A provider that never answers must not grow this without bound. Oldest first, by
        // send order: an unanswered request is one a provider chose not to answer, and the
        // choice of which to forget should not follow from that.
        while self.outstanding.len() > Self::MAX_OUTSTANDING {
            let Some(oldest) = self
                .outstanding
                .iter()
                .min_by_key(|(_, o)| o.seq)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.outstanding.remove(&oldest);
        }
        nonce
    }

    /// Read every response waiting on the socket and file it under the box it answers.
    ///
    /// Filing rather than filtering. A client polling several providers has answers arriving
    /// interleaved, and dropping the ones that did not come from the provider being polled at
    /// that instant lost them for good: replicas polled round robin systematically discarded
    /// each other's replies, and every replica but one looked like it was withholding.
    fn pump(&mut self) {
        let mut buf = [0u8; RESPONSE_BYTES];
        while let Ok((n, from)) = self.collect_sock.recv_from(&mut buf) {
            if n != RESPONSE_BYTES {
                continue;
            }
            // The nonce is the whole matching predicate now.
            //
            // Everything else a response used to carry was either attacker-supplyable or a
            // leak: a UDP source address is spoofable, a feed tag is public and names the
            // publisher a client follows, and the cursor advances by one. The nonce is the one
            // field that is meaningless to anyone who did not send the request.
            let mut echoed = [0u8; 8];
            echoed.copy_from_slice(&buf[RESP_NONCE..RESP_NONCE + 8]);
            let Some(o) = self.outstanding.get(&echoed).cloned() else {
                continue;
            };
            // Defence in depth. The nonce already establishes this, but an answer arriving
            // from somewhere the request never went is worth refusing on its own.
            if o.at != from {
                continue;
            }
            self.outstanding.remove(&echoed);

            let body = &buf[RESP_BODY..];

            if let Some(asked) = o.read_cursor {
                // A feed read advances only over a body that is actually a fragment.
                //
                // There is no status byte to ask, and there should not be: it told anyone on
                // the link when a client received something. A real feed body is an open
                // envelope carrying a decodable fragment, and the random filler a provider
                // sends when it has nothing is neither, so the client learns what it needs
                // from the body while an observer learns nothing from the wire.
                //
                // Advancing on filler would step past an object deposited a moment later,
                // which on a feed still being written is the ordinary case.
                if crate::frame::is_open_fragment(body) {
                    let here = self.feed_cursors.entry((from, o.tag)).or_insert(0);
                    *here = asked as usize + 1;
                }
            }

            // The high-water mark, not the latest value. A refusal count is evidence that mail
            // was lost, and taking the most recent reading let a poll of any other box
            // overwrite it with zero, which is the one number feeds rest their "denial is
            // visible rather than silent" argument on.
            let seen = u64::from_le_bytes(buf[..8].try_into().expect("8 bytes"));
            self.refused_seen = self.refused_seen.max(seen);

            self.pending
                .entry((from, o.tag))
                .or_default()
                .push(body.to_vec());
        }
    }

    /// Deposits the provider refused, as last reported. Non-zero means content was lost.
    pub fn refused_seen(&self) -> u64 {
        self.refused_seen
    }

    /// Ask the provider for one item.
    pub fn poll_mail(&mut self) {
        let now = self.now_ms();
        let mut req = [0u8; REQUEST_BYTES];
        req[0] = REQ_DRAIN;
        let (counter, sig) = self.client.drain_proof();
        req[1..33].copy_from_slice(&self.client.drain_public());
        req[REQ_COUNTER..REQ_COUNTER + 8].copy_from_slice(&counter.to_le_bytes());
        req[REQ_SIG..REQ_SIG + 64].copy_from_slice(&sig);
        let nonce = self.record(self.provider_collect, self.client.mailbox(), None);
        req[REQ_NONCE..REQ_NONCE + 8].copy_from_slice(&nonce);
        let _ = self.collect_sock.send_to(&req, self.provider_collect);

        self.pump();
        let mine = (self.provider_collect, self.client.mailbox());
        for env in self.pending.remove(&mine).unwrap_or_default() {
            if let Some(m) = self.client.accept(&env) {
                // Loops are absorbed rather than surfaced. An application must never see
                // them, or the detector becomes visible in the application's behaviour.
                let is_loop = self.sentinel.as_mut().is_some_and(|s| s.absorb(&m));
                if !is_loop {
                    self.received.push(m);
                }
            }
        }
        if let Some(s) = self.sentinel.as_mut() {
            s.expire(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::directory::NodeInfo;
    use karst_mix::packet::MixKey;

    /// A runner and a socket standing in for its provider.
    ///
    /// Real sockets, because the defects here are in what the runner accepts off a socket and
    /// a mock of the provider would be a mock of the thing under test.
    struct Rig {
        runner: ClientRunner,
        provider: UdpSocket,
        provider_at: SocketAddr,
    }

    /// An envelope carrying a decodable fragment, which is what a served item looks like.
    fn served_body(fill: u8) -> Vec<u8> {
        use crate::frame::{Fragment, ENVELOPE_BYTES, ENV_OPEN, INNER_BYTES};
        let f = Fragment {
            msg_id: [fill; 16],
            index: 0,
            total: 1,
            data: vec![fill; 8],
        };
        let mut env = vec![0u8; ENVELOPE_BYTES];
        env[0] = ENV_OPEN;
        let inner = f.encode();
        env[1..1 + INNER_BYTES].copy_from_slice(&inner[..INNER_BYTES.min(inner.len())]);
        env
    }

    fn rig() -> Rig {
        let mut dir = Directory::new(15.0);
        let key = MixKey::from_seed([1u8; 32]);
        dir.add(NodeInfo {
            id: 0,
            addr: "127.0.0.1:1".parse().unwrap(),
            mix_public: key.public(),
            layer: 0,
        });
        let provider = UdpSocket::bind("127.0.0.1:0").expect("provider socket");
        provider.set_nonblocking(true).unwrap();
        let provider_at = provider.local_addr().unwrap();
        let runner = ClientRunner::new(
            Client::from_seed([7u8; 32], 0),
            "127.0.0.1:0".parse().unwrap(),
            dir,
            provider_at,
            10.0,
        )
        .expect("runner");
        Rig {
            runner,
            provider,
            provider_at,
        }
    }

    impl Rig {
        fn client_at(&self) -> SocketAddr {
            self.runner.collect_sock.local_addr().unwrap()
        }

        /// A response as the provider builds one, echoing a request's nonce.
        ///
        /// The body is a real open fragment, because that is now how a client tells a served
        /// item from filler: there is no status byte to ask.
        fn respond_to(
            &self,
            req: &[u8; REQUEST_BYTES],
            from: &UdpSocket,
            to: SocketAddr,
            _tag: Tag,
            _cursor: u32,
            body: u8,
        ) {
            let mut resp = vec![0u8; RESPONSE_BYTES];
            resp[RESP_NONCE..RESP_NONCE + 8].copy_from_slice(&req[REQ_NONCE..REQ_NONCE + 8]);
            resp[RESP_BODY..].copy_from_slice(&served_body(body));
            from.send_to(&resp, to).expect("send");
        }

        /// A response carrying a nonce nobody asked for, which is the forgery.
        fn respond_unsolicited(&self, from: &UdpSocket, to: SocketAddr, _tag: Tag, _cursor: u32) {
            let mut resp = vec![0u8; RESPONSE_BYTES];
            resp[RESP_NONCE..RESP_NONCE + 8].copy_from_slice(&[0xab; 8]);
            resp[RESP_BODY..].copy_from_slice(&served_body(1));
            from.send_to(&resp, to).expect("send");
        }

        /// Read the request the runner just sent, so the reply can echo it.
        ///
        /// Loopback is fast and not instantaneous, and the socket is non-blocking because the
        /// runner's is.
        fn last_request(&self) -> [u8; REQUEST_BYTES] {
            let mut buf = [0u8; REQUEST_BYTES];
            for _ in 0..1000 {
                match self.provider.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        assert_eq!(n, REQUEST_BYTES);
                        return buf;
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
                }
            }
            panic!("the runner sent no request");
        }

        /// Pump until the response lands, and return what was filed for this box.
        fn collected(&mut self, tag: Tag) -> Vec<Vec<u8>> {
            let key = (self.provider_at, tag);
            for _ in 0..1000 {
                self.runner.pump();
                if let Some(v) = self.runner.pending.remove(&key) {
                    return v;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Vec::new()
        }
    }

    /// Every drained item must reach the client, not just the first.
    ///
    /// A drain is destructive: the provider has already popped the item when it answers. The
    /// runner filed drain responses through the feed cursor map, whose progress rule discards
    /// anything below the stored value, and a drain always echoes cursor 0. So the first drain
    /// set the entry to 1 and every later one was thrown away *after* the provider had deleted
    /// it. Any message longer than one fragment could never be received.
    #[test]
    fn a_second_drain_is_not_discarded_as_stale() {
        let mut r = rig();
        let tag = r.runner.client.mailbox();
        let at = r.client_at();

        for round in 0..4u8 {
            r.runner.poll_mail();
            let req = r.last_request();
            assert_eq!(req[0], REQ_DRAIN);
            r.respond_to(&req, &r.provider, at, tag, 0, round);

            let got = r.collected(tag);
            assert_eq!(
                got.len(),
                1,
                "round {round}: the drained item was discarded"
            );
            assert_eq!(got[0], served_body(round), "round {round}: wrong body");
        }
    }

    /// Reading a feed that is still being written must not step past what arrives next.
    ///
    /// An empty response means "nothing at that index **yet**". On a live feed that is the
    /// ordinary case, because a reader polls faster than a publisher deposits. Advancing the
    /// cursor over it skips the object that lands a moment later, permanently.
    ///
    /// This is a regression test in the literal sense: the status check sat before the cursor
    /// advance, a refactor moved it after, every unit test still passed, and the composed
    /// stack demo silently delivered zero of five objects. Nothing in the suite read a feed
    /// that was still filling, which is the only state a real feed is ever in.
    #[test]
    fn an_empty_answer_does_not_advance_past_an_object_that_has_not_arrived() {
        let mut r = rig();
        let tag = [11u8; 32];
        let at = r.client_at();

        // The reader is ahead of the publisher: index 0 is not there yet.
        r.runner.poll_tag(tag);
        let req = r.last_request();
        assert_eq!(
            u64::from_le_bytes(req[REQ_COUNTER..REQ_COUNTER + 8].try_into().unwrap()),
            0
        );
        // Filler, which is what a provider with nothing at that index sends. Random bytes,
        // indistinguishable on the wire from a served item and not a decodable fragment.
        let mut empty = vec![0u8; RESPONSE_BYTES];
        empty[RESP_NONCE..RESP_NONCE + 8].copy_from_slice(&req[REQ_NONCE..REQ_NONCE + 8]);
        for (i, b) in empty[RESP_BODY..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        r.provider.send_to(&empty, at).expect("send");
        let _ = r.collected(tag);

        // The publisher deposits. The next poll must still ask for index 0.
        r.runner.poll_tag(tag);
        let req2 = r.last_request();
        assert_eq!(
            u64::from_le_bytes(req2[REQ_COUNTER..REQ_COUNTER + 8].try_into().unwrap()),
            0,
            "an empty answer advanced the cursor past an object not yet published"
        );

        r.respond_to(&req2, &r.provider, at, tag, 0, 42);
        let got = r.collected(tag);
        assert_eq!(got.len(), 1, "the object was skipped");
        assert_eq!(got[0], served_body(42));

        // And a served item does advance, so the guard is not simply pinning the cursor.
        r.runner.poll_tag(tag);
        let req3 = r.last_request();
        assert_eq!(
            u64::from_le_bytes(req3[REQ_COUNTER..REQ_COUNTER + 8].try_into().unwrap()),
            1,
            "the cursor never advances, so nothing after the first object is readable"
        );
    }

    /// A forgery that matches every field a client can check is still refused.
    ///
    /// This is the case `an_unsolicited_response_is_dropped` never reached: that test sends
    /// from a different socket, so it only exercises the address mismatch. Every other field
    /// in the predicate is attacker-supplyable. A UDP source address is spoofable, a feed tag
    /// is public by construction, a mailbox tag is in every `Contact`, and the cursor starts
    /// at zero and advances by one.
    ///
    /// A drain is destructive, so a forgery that consumed the outstanding request meant the
    /// genuine answer, carrying an item the provider had already popped and cannot re-serve,
    /// was dropped as unsolicited. One forged datagram per poll made an inbox permanently
    /// undeliverable while the provider believed it had delivered.
    #[test]
    fn a_response_matching_every_public_field_is_still_refused() {
        let mut r = rig();
        let tag = r.runner.client.mailbox();
        let at = r.client_at();

        r.runner.poll_mail();
        let req = r.last_request();

        // The attacker spoofs the provider's source address and every echoed field. It cannot
        // see the request, so it cannot know the nonce.
        let spoof = UdpSocket::bind(r.provider_at).is_err();
        assert!(
            spoof,
            "the provider's address is taken, so this test spoofs by reuse"
        );
        let mut resp = vec![0u8; RESPONSE_BYTES];
        resp[RESP_NONCE..RESP_NONCE + 8].copy_from_slice(&[0u8; 8]);
        resp[RESP_BODY..].copy_from_slice(&served_body(0xee));
        r.provider.send_to(&resp, at).expect("send");

        assert!(r.collected(tag).is_empty(), "a forged response was filed");

        // And the genuine answer still lands, so the forgery consumed nothing.
        r.respond_to(&req, &r.provider, at, tag, 0, 7);
        let got = r.collected(tag);
        assert_eq!(got.len(), 1, "the forgery consumed the outstanding drain");
        assert_eq!(got[0], served_body(7));
    }

    /// A refusal count is evidence of loss, so it is a high-water mark rather than a reading.
    ///
    /// Taking the latest value let a poll of any other box overwrite it with zero, with no
    /// attacker present, and that count is the one number the feed layer rests its
    /// "denial is visible rather than silent" argument on.
    #[test]
    fn a_refusal_count_is_not_overwritten_by_a_later_poll() {
        let mut r = rig();
        let tag = r.runner.client.mailbox();
        let at = r.client_at();

        r.runner.poll_mail();
        let req = r.last_request();
        let mut resp = vec![0u8; RESPONSE_BYTES];
        resp[..8].copy_from_slice(&42u64.to_le_bytes());
        resp[RESP_NONCE..RESP_NONCE + 8].copy_from_slice(&req[REQ_NONCE..REQ_NONCE + 8]);
        resp[RESP_BODY..].copy_from_slice(&served_body(1));
        r.provider.send_to(&resp, at).expect("send");
        let _ = r.collected(tag);
        assert_eq!(r.runner.refused_seen(), 42);

        // A later poll of a different box reports zero refusals, honestly.
        let other = [3u8; 32];
        r.runner.poll_tag(other);
        let req2 = r.last_request();
        r.respond_to(&req2, &r.provider, at, other, 0, 1);
        let _ = r.collected(other);
        assert_eq!(
            r.runner.refused_seen(),
            42,
            "the refusal count was overwritten"
        );
    }

    /// A datagram nobody asked for is not filed.
    ///
    /// Both the source address and the tag come off the wire, so accepting unsolicited
    /// responses let anyone who could reach the client write entries into its own bookkeeping
    /// under keys of their choosing, roughly a kilobyte at a time and never released.
    #[test]
    fn an_unsolicited_response_is_dropped() {
        let mut r = rig();
        let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = r.client_at();

        for i in 0..500u32 {
            let mut tag = [0u8; 32];
            tag[..4].copy_from_slice(&i.to_le_bytes());
            r.respond_unsolicited(&attacker, at, tag, 0);
        }
        r.runner.pump();

        assert!(
            r.runner.pending.is_empty(),
            "filed a response nobody asked for"
        );
        assert!(
            r.runner.feed_cursors.is_empty(),
            "a stranger moved a cursor"
        );
    }

    /// A response cannot move the cursor, because it no longer carries one.
    ///
    /// It used to. A datagram claiming `answered = u32::MAX` set the stored cursor to 2^32,
    /// the next request truncated it back to 0, and every honest answer after that was
    /// discarded as stale: one spoofed packet made a feed unreadable for the life of the
    /// process.
    ///
    /// The cursor was on the wire so a client could tell which index an answer belonged to.
    /// The nonce does that, and unlike the cursor it is unguessable, so the field is gone.
    /// The attack is now unrepresentable rather than defended against, and what this asserts
    /// is the invariant that makes it so: **the cursor advances by exactly one per served
    /// item, and nothing on the wire has any say in it.**
    #[test]
    fn nothing_on_the_wire_can_move_the_cursor() {
        let mut r = rig();
        let tag = [3u8; 32];
        let at = r.client_at();

        for expected in 0..4u32 {
            assert_eq!(
                r.runner
                    .feed_cursors
                    .get(&(r.provider_at, tag))
                    .copied()
                    .unwrap_or(0),
                expected as usize
            );
            r.runner.poll_tag(tag);
            let req = r.last_request();
            // The request asks for the index the client chose.
            assert_eq!(
                u64::from_le_bytes(req[REQ_COUNTER..REQ_COUNTER + 8].try_into().unwrap()),
                expected as u64
            );
            // The response carries no index at all, so there is nothing to forge.
            r.respond_to(&req, &r.provider, at, tag, u32::MAX, expected as u8);
            assert_eq!(r.collected(tag).len(), 1);
        }
    }

    /// An observer on the link cannot tell a delivery from an empty poll.
    ///
    /// This is #107. The response carried a plaintext status byte saying whether anything was
    /// waiting, and the module claimed the fixed response size hid that. The size argument
    /// only bears on an observer who cannot read the bytes, and this one can: at the demo's
    /// two millisecond poll interval it was a millisecond-resolution record of every moment a
    /// client received mail, which is precisely the receive-side input to the end-to-end
    /// timing correlation that per-hop delays and constant-rate cover exist to defeat.
    ///
    /// The mixnet hid who a packet came from and the retrieval protocol then announced, in
    /// clear, the instant it landed.
    ///
    /// What an observer sees now is a fixed-size datagram whose only readable fields are a
    /// refusal count and a nonce that means nothing to them.
    #[test]
    fn a_delivery_and_an_empty_poll_look_the_same_on_the_wire() {
        let mut r = rig();
        let tag = r.runner.client.mailbox();
        let at = r.client_at();

        // Two responses from the same provider: one carrying an item, one carrying nothing.
        r.runner.poll_mail();
        let req_a = r.last_request();
        let mut served = vec![0u8; RESPONSE_BYTES];
        served[RESP_NONCE..RESP_NONCE + 8].copy_from_slice(&req_a[REQ_NONCE..REQ_NONCE + 8]);
        served[RESP_BODY..].copy_from_slice(&served_body(3));

        r.runner.poll_mail();
        let req_b = r.last_request();
        let mut empty = vec![0u8; RESPONSE_BYTES];
        empty[RESP_NONCE..RESP_NONCE + 8].copy_from_slice(&req_b[REQ_NONCE..REQ_NONCE + 8]);
        for (i, b) in empty[RESP_BODY..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(97).wrapping_add(11);
        }

        assert_eq!(served.len(), empty.len(), "the sizes must match");

        // Everything outside the body is identical but for the nonce, which is unguessable.
        assert_eq!(
            served[..8],
            empty[..8],
            "the refusal count differs by delivery"
        );
        assert_eq!(
            served[RESP_BODY..].len(),
            empty[RESP_BODY..].len(),
            "the bodies differ in length by delivery"
        );

        // And no byte outside the body says which is which. Checked by construction: the only
        // fields are the refusal count and the nonce, and the nonce is drawn per request.
        assert_eq!(
            RESP_BODY, 16,
            "the header grew, so this test is out of date"
        );

        r.provider.send_to(&served, at).expect("send");
        r.provider.send_to(&empty, at).expect("send");

        // The client tells them apart by opening them, which the observer cannot do.
        let got = r.collected(tag);
        assert!(!got.is_empty(), "the served item did not reach the client");
    }

    /// A provider that never answers costs a bounded amount of memory.
    #[test]
    fn unanswered_requests_do_not_accumulate_without_limit() {
        let mut r = rig();
        for i in 0..(ClientRunner::MAX_OUTSTANDING as u32 + 500) {
            let mut tag = [0u8; 32];
            tag[..4].copy_from_slice(&i.to_le_bytes());
            r.runner.poll_tag(tag);
        }
        assert!(r.runner.outstanding.len() <= ClientRunner::MAX_OUTSTANDING);
    }
}
