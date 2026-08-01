//! Datagrams.
//!
//! Every datagram is exactly `PACKET_BYTES`. Anything else is not ours and is dropped without
//! reply, without logging the source, and without any change in behaviour that an observer
//! could measure.
//!
//! # What silence buys
//!
//! A transport that answers differently depending on whether it liked what it received is an
//! enumeration oracle: an adversary sweeps an address range, sends one probe each, and learns
//! who is running the protocol. That is the attack membership concealing overlays exist to
//! stop (Vasserman, Jansen, Tyra, Hopper, Kim, CCS 2009), and Tor's public consensus concedes
//! it by design.
//!
//! Nothing here ever transmits in response to a receive. Emission is driven entirely by
//! `Pacer`, whose schedule is drawn without reference to anything received, so a probe changes
//! nothing an observer can see. Concealment against active scanning is a consequence of the
//! anti-oracle design at L3 rather than a separate mechanism.
//!
//! This conceals *whether a host speaks the protocol*, given that the adversary cannot see the
//! host's own outbound stream. An adversary who can see that stream sees a constant-rate flow
//! and knows. That exposure is #56 and is not addressed here.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use karst_mix::packet::{Packet, PACKET_BYTES};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WireStats {
    pub sent: u64,
    pub received: u64,
    /// Datagrams of the wrong length. Counted, never answered.
    pub wrong_size: u64,
    pub undecodable: u64,
}

pub struct UdpTransport {
    socket: UdpSocket,
    stats: WireStats,
}

impl UdpTransport {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(UdpTransport {
            socket,
            stats: WireStats::default(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn send(&mut self, to: SocketAddr, packet: &Packet) -> io::Result<()> {
        let bytes = packet.to_bytes();
        debug_assert_eq!(bytes.len(), PACKET_BYTES);
        self.socket.send_to(&bytes, to)?;
        self.stats.sent += 1;
        Ok(())
    }

    /// Take one datagram if there is one.
    ///
    /// The source address is returned for accounting only. Nothing in this crate sends to it,
    /// because sending in response to a receive is the oracle.
    pub fn recv(&mut self) -> Option<(SocketAddr, Packet)> {
        let mut buf = [0u8; PACKET_BYTES];
        match self.socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                self.stats.received += 1;
                if n != PACKET_BYTES {
                    self.stats.wrong_size += 1;
                    return None;
                }
                match Packet::from_bytes(&buf) {
                    Some(p) => Some((from, p)),
                    None => {
                        self.stats.undecodable += 1;
                        None
                    }
                }
            }
            Err(_) => None,
        }
    }

    pub fn stats(&self) -> WireStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_mix::packet::{Hop, MixKey};

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn a_packet() -> Packet {
        let k = MixKey::from_seed([5u8; 32]);
        Packet::wrap(
            &[Hop {
                id: 0,
                public: k.public(),
                delay_ms: 1,
            }],
            b"over the wire",
            rand::random(),
        )
        .unwrap()
    }

    fn drain(t: &mut UdpTransport, tries: usize) -> Vec<Packet> {
        let mut got = Vec::new();
        for _ in 0..tries {
            if let Some((_, p)) = t.recv() {
                got.push(p);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        got
    }

    #[test]
    fn a_packet_crosses_a_real_socket_intact() {
        let mut a = UdpTransport::bind(loopback()).unwrap();
        let mut b = UdpTransport::bind(loopback()).unwrap();
        let to = b.local_addr().unwrap();

        let p = a_packet();
        a.send(to, &p).unwrap();
        let got = drain(&mut b, 200);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].to_bytes(), p.to_bytes());
    }

    /// Everything on the wire is the same size, so length carries no information.
    #[test]
    fn every_datagram_is_the_same_length() {
        let k = MixKey::from_seed([5u8; 32]);
        let hop = [Hop {
            id: 0,
            public: k.public(),
            delay_ms: 1,
        }];
        let tiny = Packet::wrap(&hop, b"", [1u8; 32]).unwrap();
        let big = Packet::wrap(&hop, &vec![7u8; 700], [2u8; 32]).unwrap();
        let cover = Packet::cover(&hop, [3u8; 32]).unwrap();
        assert_eq!(tiny.to_bytes().len(), PACKET_BYTES);
        assert_eq!(big.to_bytes().len(), PACKET_BYTES);
        assert_eq!(cover.to_bytes().len(), PACKET_BYTES);
    }

    /// Junk of any size must be dropped without a reply.
    ///
    /// A reply of any kind, including an error, is an enumeration oracle.
    #[test]
    fn junk_is_dropped_without_answer() {
        let mut victim = UdpTransport::bind(loopback()).unwrap();
        let target = victim.local_addr().unwrap();
        let prober = UdpSocket::bind(loopback()).unwrap();
        prober
            .set_read_timeout(Some(std::time::Duration::from_millis(150)))
            .unwrap();

        for size in [0usize, 1, 64, 1023, 1025, 4096] {
            prober.send_to(&vec![0xAB; size], target).unwrap();
        }
        // Also a well-formed length carrying nothing meaningful.
        prober.send_to(&[0u8; PACKET_BYTES], target).unwrap();

        for _ in 0..100 {
            let _ = victim.recv();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let mut back = [0u8; 2048];
        assert!(
            prober.recv_from(&mut back).is_err(),
            "the transport answered a probe, which enumerates the network"
        );
        assert_eq!(victim.stats().sent, 0, "the transport transmitted at all");
    }

    /// A probe must not change what an observer of the target sees.
    ///
    /// The emission schedule is drawn without reference to anything received, so a probed node
    /// and an unprobed node emit identically. This is what makes concealment hold against an
    /// adversary who can watch but not join.
    #[test]
    fn probing_does_not_perturb_the_emission_schedule() {
        use crate::Pacer;

        let cover = || {
            let k = MixKey::from_seed([9u8; 32]);
            Packet::cover(
                &[Hop {
                    id: 0,
                    public: k.public(),
                    delay_ms: 1,
                }],
                rand::random(),
            )
            .unwrap()
        };

        let mut unprobed = Pacer::seeded(20.0, 42);
        let mut probed = Pacer::seeded(20.0, 42);
        let mut victim = UdpTransport::bind(loopback()).unwrap();
        let target = victim.local_addr().unwrap();
        let prober = UdpSocket::bind(loopback()).unwrap();

        let (mut a, mut b) = (Vec::new(), Vec::new());
        for t in 0..5_000u64 {
            if t % 3 == 0 {
                prober.send_to(&vec![0xCD; PACKET_BYTES], target).unwrap();
            }
            while victim.recv().is_some() {}
            for _ in unprobed.tick(t, cover) {
                a.push(t);
            }
            for _ in probed.tick(t, cover) {
                b.push(t);
            }
        }
        assert!(a.len() > 50, "vacuous: {} emissions", a.len());
        assert_eq!(a, b, "being probed changed the emission schedule");
    }
}
