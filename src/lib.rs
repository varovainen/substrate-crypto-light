//! This is largely based on
//! [`sp_core`](https://docs.rs/sp-core/latest/sp_core/) crate. Draft.
//!
//! Key differences here:
//!
//! - no-std compatible with arm
//! - sr25519 supports external Rng, for usability on baremetal
//! - ecdsa support based on pure Rust crate `k256`, to avoid `no-std` target
//!   compiling difficulties (original `sp-core` has ecdsa from `secp256k1`, a C
//!   wrapper crate, and as a result ecdsa parts from `sp-core` do not compile on
//!   certain `no-std` targets and create extremely large binary blob on others)
//! - ecdsa pair has zeroize on drop

#![no_std]
#![deny(unused_crate_dependencies)]

#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
extern crate alloc;

pub mod common;
#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod ed25519;
pub mod error;
#[cfg(feature = "sr25519")]
pub mod sr25519;
