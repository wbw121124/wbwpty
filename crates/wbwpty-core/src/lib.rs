//! wbwpty-core: the reusable, terminal-semantics half of wbwpty.
//!
//! The crate is deliberately split so that nothing here can accidentally grow a
//! dependency on the injected side of the boundary:
//!
//! * [`pipe`]        — named-pipe byte transport, overlapped, pump threads
//! * [`child`]       — suspended + detached process creation, environment block
//! * [`manual_map`]  — PE parsing, PEB module walk, manual mapping, remote stub
//! * [`session`]     — the terminal session lifecycle built on top of the above
//! * [`supervisor`]  — covers every *descendant* of the target, so the whole
//!   tree creates its children with `DETACHED_PROCESS` and our pipes
//! * [`inspect`]     — process snapshots used to prove "no conhost.exe"

pub mod child;
pub mod error;
pub mod inspect;
pub mod manual_map;
pub mod pipe;
pub mod procwatch;
pub mod screen;
pub mod session;
pub mod supervisor;

pub use anyhow::{Error, Result};
pub use child::{ChildSpec, Stdio};
pub use error::Handle;
pub use pipe::{PipePair, ReadEvent};
pub use procwatch::ProcessWatch;
pub use session::{Session, SessionConfig};
pub use supervisor::{Coverage, SupervisorConfig};

