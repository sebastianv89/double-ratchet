//! Crate documentation provided in README.md

// TODO: include README.md documentation: https://github.com/rust-lang/rust/issues/44732
// TODO: test examples in README.md

#![no_std]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod dr;

pub use dr::*;
