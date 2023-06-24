#![no_std]
#![deny(unused_crate_dependencies)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub mod block;

#[cfg(feature = "std")]
pub mod decoder;
pub mod decoder_metal;
pub mod distributions;
pub mod encoder;
pub mod error;
pub mod mock_worst_case;
pub mod packet;

#[cfg(all(feature = "std", test))]
mod real_packets;

pub mod utils;
