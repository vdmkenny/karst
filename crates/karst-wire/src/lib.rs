//! L3 Wire.
//!
//! One datagram size, one emission schedule, and no relationship between the two and what the
//! sender happens to have to say.

pub mod pacer;
pub mod udp;

pub use pacer::{Pacer, PacerStats, QueueFull};
pub use udp::{UdpTransport, WireStats};
