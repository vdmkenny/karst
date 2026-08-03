//! A network that runs.

pub mod attacks;
pub mod bulk;
pub mod client;
pub mod directory;
pub mod feed;
pub mod frame;
pub mod placement;
pub mod provider;
pub mod runner;
pub mod sentinel;
pub mod watch;

pub use bulk::{plan, plan_with, Carriage, Exposure, FetchPlan, Policy};
pub use client::{Client, Contact, SendError};
pub use directory::{Directory, NodeInfo, RouteError};
pub use feed::{feed_tag, FeedReader, FeedStats};
pub use frame::{Fragment, FrameError, Reassembler};
pub use placement::{placement, DEFAULT_REPLICAS};
pub use provider::{Collected, DepositError, Provider, Tag};
pub use runner::{ClientRunner, CoverPool, NodeRunner};
pub use sentinel::Sentinel;
pub use watch::{FeedWatch, Lagging};
