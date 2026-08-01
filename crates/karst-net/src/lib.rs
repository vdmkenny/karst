//! A network that runs.

pub mod attacks;
pub mod client;
pub mod directory;
pub mod feed;
pub mod frame;
pub mod placement;
pub mod provider;
pub mod watch;
pub mod runner;
pub mod sentinel;

pub use client::{Client, Contact, SendError};
pub use directory::{Directory, NodeInfo, RouteError};
pub use sentinel::Sentinel;
pub use runner::{ClientRunner, CoverPool, NodeRunner};
pub use placement::{placement, DEFAULT_REPLICAS};
pub use watch::{FeedWatch, Lagging};
pub use provider::{Collected, DepositError, Provider, Tag};
pub use feed::{feed_tag, FeedReader, FeedStats};
pub use frame::{Fragment, FrameError, Reassembler};
