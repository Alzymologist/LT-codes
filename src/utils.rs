#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use blake2_rfc::blake2b::blake2b;
use rand::distributions::{Distribution, Uniform, WeightedIndex};
use rand_core::SeedableRng;
use rand_pcg::Lcg64Xsh32;

fn make_prng(id: u16) -> Lcg64Xsh32 {
    let seed = blake2b(16, b"kampela", &id.to_be_bytes())
        .as_bytes()
        .try_into()
        .expect("static length");
    SeedableRng::from_seed(seed)
}

pub fn msg_len_as_usize(msg_len: [u8; 3]) -> usize {
    let mut msg_len_be_bytes = [0; 4];
    msg_len_be_bytes[1..4].copy_from_slice(&msg_len);
    u32::from_be_bytes(msg_len_be_bytes) as usize
}

pub fn block_numbers_for_id(
    range_distribution: &WeightedIndex<f32>,
    block_number_distribution: &Uniform<usize>,
    id: u16,
) -> Vec<usize> {
    let mut rng = make_prng(id);
    let d = range_distribution.sample(&mut rng);
    let mut block_numbers: Vec<usize> = Vec::new();
    for _n in 0..d {
        let proposed_number = block_number_distribution.sample(&mut rng);
        let mut already_at_index = None;
        for (i, block_number) in block_numbers.iter().enumerate() {
            if block_number == &proposed_number {
                already_at_index = Some(i);
                break;
            }
        }
        match already_at_index {
            Some(i) => {
                block_numbers.remove(i);
            }
            None => block_numbers.push(proposed_number),
        }
    }
    block_numbers
}
