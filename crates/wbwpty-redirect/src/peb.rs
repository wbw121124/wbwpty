//! PEB / `RTL_USER_PROCESS_PARAMETERS` access.
//!
//! Filled in by the `feat(dll): fake attached-console state in peb process
//! parameters` stage. Every offset used here must carry a source comment and be
//! covered by a runtime self test (AGENTS.md rule 4).