#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use blake2_rfc::blake2b::blake2b;
use rand::distributions::{Distribution, Uniform, WeightedIndex};
use rand_core::SeedableRng;
use rand_pcg::Lcg64Xsh32;

use crate::block::BLOCK_SIZE;

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
    block_number_distribution: &Uniform<u32>,
    id: u16,
) -> Vec<usize> {
    let mut rng = make_prng(id);
    let d = range_distribution.sample(&mut rng);
    let mut block_numbers: Vec<usize> = Vec::new();
    for _n in 0..d {
        let proposed_number = block_number_distribution.sample(&mut rng) as usize;
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

pub fn number_of_blocks(msg_usize: usize) -> usize {
    if msg_usize % BLOCK_SIZE == 0 {
        msg_usize / BLOCK_SIZE
    } else {
        msg_usize / BLOCK_SIZE + 1
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {

    use super::*;
    use crate::distributions::Distributions;

    const NUMBER_OF_BLOCKS: u32 = 2;

    #[test]
    fn select_blocks_correctly_1() {
        let distributions = Distributions::calculate(NUMBER_OF_BLOCKS).unwrap();
        let variants = [vec![], vec![0], vec![1], vec![0, 1], vec![1, 0]];
        for id in 0..u16::MAX {
            let block_numbers = block_numbers_for_id(
                &distributions.range_distribution,
                &distributions.block_number_distribution,
                id,
            );
            assert!(
                variants.contains(&block_numbers),
                "Unexpected variant {block_numbers:?} at id {id}",
            );
        }
    }

    #[test]
    fn select_blocks_correctly_2() {
        let distributions = Distributions::calculate(NUMBER_OF_BLOCKS).unwrap();
        assert_eq!(
            block_numbers_for_id(
                &distributions.range_distribution,
                &distributions.block_number_distribution,
                u16::from_be_bytes([0, 0])
            ),
            vec![]
        );
    }

    #[test]
    fn select_blocks_correctly_3() {
        let distributions = Distributions::calculate(NUMBER_OF_BLOCKS).unwrap();
        assert_eq!(
            block_numbers_for_id(
                &distributions.range_distribution,
                &distributions.block_number_distribution,
                u16::from_be_bytes([0, 3])
            ),
            vec![0]
        );
    }

    #[test]
    fn select_blocks_correctly_4() {
        let distributions = Distributions::calculate(NUMBER_OF_BLOCKS).unwrap();
        assert_eq!(
            block_numbers_for_id(
                &distributions.range_distribution,
                &distributions.block_number_distribution,
                u16::from_be_bytes([0, 2])
            ),
            vec![1]
        );
    }

    #[test]
    fn select_blocks_correctly_5() {
        let distributions = Distributions::calculate(NUMBER_OF_BLOCKS).unwrap();
        assert_eq!(
            block_numbers_for_id(
                &distributions.range_distribution,
                &distributions.block_number_distribution,
                u16::from_be_bytes([0, 6])
            ),
            vec![1, 0]
        );
    }

    #[test]
    fn select_blocks_correctly_6() {
        let distributions = Distributions::calculate(NUMBER_OF_BLOCKS).unwrap();
        assert_eq!(
            block_numbers_for_id(
                &distributions.range_distribution,
                &distributions.block_number_distribution,
                u16::from_be_bytes([0, 14])
            ),
            vec![0, 1]
        );
    }
}
