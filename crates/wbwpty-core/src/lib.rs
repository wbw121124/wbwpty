//! wbwpty-core: the reusable, terminal-semantics half of wbwpty.
//!
//! The crate is deliberately split so that nothing here can accidentally grow a
//! dependency on the injected side of the boundary:
//!
//! * [`pipe`]        — named-pipe byte transport, overlapped, pump threads
//! * [`child`]       — suspended + detached process creation, environment block
//! * [`manual_map`]  — PE parsing, PEB module walk, manual mapping, remote stub
//! * [`inject`]      — glue: map the redirect DLL and call its entry point
//! * [`session`]     — the terminal session lifecycle built on top of the above
//! * [`console`]     — host side virtual terminal state (rows/cols/code page)
//! * [`inspect`]     — process snapshots used to prove "no conhost.exe"

pub mod error;

pub use anyhow::{Error, Result};
pub use error::Handle;