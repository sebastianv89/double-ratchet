//! Crate documentation provided in README.md

// TODO: include README.md documentation
// TODO: test examples in README.md

#![no_std]
#![cfg_attr(feature = "nightly", feature(alloc))]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod dr;

pub use dr::*;
