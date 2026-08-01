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
use crate::frame::SEALED_BYTES;
use crate::provider::{Provider, Tag};

/// A collection request: a bare tag.
pub const REQUEST_BYTES: usize = 32;

/// A collection response: one status byte and a fixed body, whether or not there was mail.
pub const RESPONSE_BYTES: usize = 1 + SEALED_BYTES;

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
            let mut tag: Tag = [0u8; 32];
            tag.copy_from_slice(&buf);

            // One item per request, and the same size either way, so the link does not report
            // whether mail was waiting.
            let mut resp = vec![0u8; RESPONSE_BYTES];
            let got = store.collect(&tag);
            let mut items = got.items;
            if items.is_empty() {
                resp[0] = STATUS_EMPTY;
                // Random, so an empty response is not a block of zeroes an observer can spot.
                use rand::Rng;
                rand::thread_rng().fill(&mut resp[1..]);
            } else {
                resp[0] = STATUS_ITEM;
                let first = items.remove(0);
                resp[1..].copy_from_slice(&first);
                // Put the rest back, so one request does not drain a box.
                for rest in items {
                    let mut payload = tag.to_vec();
                    payload.extend_from_slice(&rest);
                    let _ = store.deposit(&payload);
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
    pub received: Vec<Vec<u8>>,
}

impl ClientRunner {
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

    /// Ask the provider for one item.
    pub fn poll_mail(&mut self) {
        let now = self.now_ms();
        let _ = self
            .collect_sock
            .send_to(&self.client.mailbox(), self.provider_collect);

        let mut buf = [0u8; RESPONSE_BYTES];
        while let Ok((n, _)) = self.collect_sock.recv_from(&mut buf) {
            if n != RESPONSE_BYTES || buf[0] != STATUS_ITEM {
                continue;
            }
            if let Some(m) = self.client.accept(&buf[1..]) {
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
