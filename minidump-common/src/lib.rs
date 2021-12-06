//! This crate defines [structs for the on-disk minidump format](format/index.html) as well as
//! [some common traits](traits/index.html) used by related crates.
//!
//! You probably don't want to use this crate directly, the [minidump][minidump] crate provides
//! the actual functionality of reading minidumps using the structs defined in this crate.
//!
//! [minidump]: https://crates.io/crates/minidump

#![warn(missing_debug_implementations)]

pub mod format;
pub mod traits;

mod linux_errors;
mod mac_errors;
mod windows_errors;