//! Redirect the target process' standard handles onto the wbwpty pipes.
//!
//! Filled in by the `feat(dll): redirect std handles to named pipes` stage.

use crate::dlog;

pub fn install() {
    dlog!("stdio::install() placeholder");
}