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
//! nothing here pretends otherwise. What it does hide is **whether anything was there**, since
//! every response is the same size whether it carries mail or nothing, and polling runs at a
//! fixed rate. A provider learns a client is online. It does not learn from the link when that
//! client received something.
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
pub const REQUEST_BYTES: usize = 1 + 32 + 8 + 64;

/// Where the counter sits in a request.
const REQ_COUNTER: usize = 33;
/// Where the drain signature sits. Zero-filled for a read, so both requests are one size and
/// an observer cannot tell a mailbox drain from a feed read by length.
const REQ_SIG: usize = 41;

/// A collection response: status, the refusal count, the cursor it answers, and a fixed body.
///
/// The refusal count is on the wire because the design justifies world-writable feed boxes on
/// the grounds that denial is visible, and a count that never left the provider made that
/// justification circular.
///
/// The cursor is echoed because a client polling in a loop has several requests in flight, and
/// a response that did not say which index it answered was counted as progress whichever index
/// it was. That produced duplicates and silently lost the items in between.
/// The tag is echoed too, because a client polling several providers for several feeds gets
/// answers back interleaved on one socket. Without it, a response arriving while a different
/// provider was being polled had to be discarded, and discarding it lost that item entirely.
pub const RESPONSE_BYTES: usize = 1 + 8 + 4 + 32 + ENVELOPE_BYTES;

/// Offset of the body within a response.
const RESP_BODY: usize = 1 + 8 + 4 + 32;

/// Drain one item from a box, proving the right to do so with the collection key.
pub const REQ_DRAIN: u8 = 1;
/// Read one item of a public feed at a cursor, without removing it.
pub const REQ_READ: u8 = 2;

const STATUS_EMPTY: u8 = 0;
const STATUS_ITEM: u8 = 1;

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
        let (Some(sock), Some(store)) = (self.collect_sock.as_ref(), self.provider.as_mut())
        else {
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
                    match store.drain_once(&tag, &cred, counter, &sig) {
                        Ok(got) => got,
                        // Silent. A refusal that answered would say whether the tag exists.
                        Err(_) => (None, 0),
                    }
                }
                // Reading a feed needs nothing, because a feed tag is public. It also takes
                // nothing away, or any stranger could delete a publisher one packet at a time.
                REQ_READ => store.peek(&cred, cursor),
                _ => (None, 0),
            };

            // One item per request, the same size either way, so the link does not report
            // whether anything was waiting.
            let mut resp = vec![0u8; RESPONSE_BYTES];
            resp[1..9].copy_from_slice(&refused.to_le_bytes());
            resp[9..13].copy_from_slice(&(cursor as u32).to_le_bytes());
            // Echo the box this answers. For a drain the credential is not the tag, so the
            // tag is derived, and a client matching on it learns nothing it did not supply.
            let echo = if kind == REQ_DRAIN {
                crate::client::mailbox_tag(&cred)
            } else {
                cred
            };
            resp[13..45].copy_from_slice(&echo);
            match item {
                None => {
                    resp[0] = STATUS_EMPTY;
                    // Random, so an empty response is not a block of zeroes an observer spots.
                    use rand::Rng;
                    rand::thread_rng().fill(&mut resp[RESP_BODY..]);
                }
                Some(body) => {
                    resp[0] = STATUS_ITEM;
                    resp[RESP_BODY..].copy_from_slice(&body);
                }
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
/// A request this client sent and is still waiting on.
///
/// The runner used to accept any correctly sized datagram and file it under the address and
/// tag the datagram itself carried, which made a client's bookkeeping writable by anyone who
/// could send it a packet. Requests are recorded on the way out and matched on the way back.
#[derive(Debug, Clone, Copy)]
struct Outstanding {
    /// Destructive reads outstanding. Counted rather than flagged, because a drain that is
    /// answered and then discarded is mail the provider has already deleted.
    drains: u32,
    /// The cursor of the most recent non-destructive read, if any.
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
    /// Requests sent and not yet answered. Nothing else is accepted off the socket.
    outstanding: std::collections::BTreeMap<(SocketAddr, Tag), Outstanding>,
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
        let _ = self.collect_sock.send_to(&req, at);
        self.record(at, tag, |o| o.read_cursor = Some(cursor));

        self.pump();
        self.pending.remove(&(at, tag)).unwrap_or_default()
    }

    /// Note a request on the way out, so its answer can be recognised on the way in.
    fn record(&mut self, at: SocketAddr, tag: Tag, f: impl FnOnce(&mut Outstanding)) {
        let seq = self.next_request;
        self.next_request += 1;
        let o = self
            .outstanding
            .entry((at, tag))
            .or_insert(Outstanding {
                drains: 0,
                read_cursor: None,
                seq,
            });
        o.seq = seq;
        f(o);
        // A request that is never answered would otherwise be remembered forever. Oldest
        // first, by send order: an unanswered request is one a provider chose not to answer,
        // and the choice of which to forget should not follow from that.
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
            self.pending.remove(&oldest);
        }
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
            let mut tag: Tag = [0u8; 32];
            tag.copy_from_slice(&buf[13..45]);

            // Nothing is filed that this client did not ask for. The address and the tag both
            // come off the wire, so without this an unsolicited datagram writes an entry into
            // the client's own bookkeeping under a key of the sender's choosing.
            let Some(o) = self.outstanding.get_mut(&(from, tag)) else {
                continue;
            };
            let answered = u32::from_le_bytes(buf[9..13].try_into().expect("4 bytes"));

            if o.drains > 0 {
                // A drain is destructive and has no cursor. The provider has already removed
                // the item, so discarding this response is losing the mail, not deferring it.
                o.drains -= 1;
            } else if o.read_cursor == Some(answered) {
                o.read_cursor = None;
                let here = self.feed_cursors.entry((from, tag)).or_insert(0);
                *here = answered as usize + 1;
            } else {
                // A cursor other than the one asked for is an answer to a question this
                // client did not put. Accepting it moved the cursor to wherever the datagram
                // said, and a single spoofed u32::MAX made the feed unreadable for good.
                continue;
            }
            if o.drains == 0 && o.read_cursor.is_none() {
                self.outstanding.remove(&(from, tag));
            }

            self.refused_seen = u64::from_le_bytes(buf[1..9].try_into().expect("8 bytes"));
            if buf[0] != STATUS_ITEM {
                continue;
            }
            self.pending
                .entry((from, tag))
                .or_default()
                .push(buf[RESP_BODY..].to_vec());
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
        let _ = self.collect_sock.send_to(&req, self.provider_collect);
        self.record(self.provider_collect, self.client.mailbox(), |o| {
            o.drains += 1
        });

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

        /// A response as the provider builds one.
        fn respond(&self, from: &UdpSocket, to: SocketAddr, tag: Tag, cursor: u32, body: u8) {
            let mut resp = vec![0u8; RESPONSE_BYTES];
            resp[0] = STATUS_ITEM;
            resp[9..13].copy_from_slice(&cursor.to_le_bytes());
            resp[13..45].copy_from_slice(&tag);
            resp[RESP_BODY..].fill(body);
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
            r.respond(&r.provider, at, tag, 0, round);

            let got = r.collected(tag);
            assert_eq!(got.len(), 1, "round {round}: the drained item was discarded");
            assert_eq!(got[0][0], round);
        }
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
            r.respond(&attacker, at, tag, 0, 1);
        }
        r.runner.pump();

        assert!(r.runner.pending.is_empty(), "filed a response nobody asked for");
        assert!(r.runner.feed_cursors.is_empty(), "a stranger moved a cursor");
    }

    /// A forged cursor cannot put a feed permanently out of reach.
    ///
    /// One datagram carrying `answered = u32::MAX` used to set the stored cursor to 2^32. The
    /// next request truncates the cursor back into a u32, the provider answers index 0, and
    /// the response is discarded as stale. That feed is unreadable from that provider for the
    /// life of the process, from a single spoofed packet.
    #[test]
    fn a_forged_cursor_does_not_poison_a_feed() {
        let mut r = rig();
        let tag = [3u8; 32];
        let at = r.client_at();

        r.runner.poll_tag(tag);
        let _ = r.last_request();
        r.respond(&r.provider, at, tag, u32::MAX, 9);
        for _ in 0..50 {
            r.runner.pump();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(r.runner.feed_cursors.get(&(r.provider_at, tag)), Some(&0));
        assert!(r.runner.pending.is_empty(), "a forged cursor was answered");

        // The honest answer to the question actually asked still lands.
        r.runner.poll_tag(tag);
        let req = r.last_request();
        assert_eq!(
            u64::from_le_bytes(req[REQ_COUNTER..REQ_COUNTER + 8].try_into().unwrap()),
            0
        );
        r.respond(&r.provider, at, tag, 0, 9);
        assert_eq!(r.collected(tag).len(), 1);
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
