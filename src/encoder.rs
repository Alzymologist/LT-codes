use rand::distributions::{Distribution, Uniform, WeightedIndex};
use rand_pcg::Lcg64Xsh32;

use crate::block::{Block, BLOCK_SIZE};
use crate::distributions::Distributions;
use crate::error::LTError;
use crate::packet::Packet;
use crate::utils::{make_prng, msg_len_as_usize};

#[derive(Debug)]
pub struct Encoder {
    id: u16,
    msg_len: [u8; 3],
    range_distribution: WeightedIndex<f32>,
    block_number_distribution: Uniform<usize>,
}

impl Encoder {
    pub fn init(msg: &[u8]) -> Result<Self, LTError> {
        let msg_usize = msg.len();
        let msg_len_bytes = (msg_usize as u32).to_be_bytes();
        let msg_len = {
            if msg_len_bytes[0] != 0 {
                return Err(LTError::DataTooLarge);
            } else {
                msg_len_bytes[1..].try_into().expect("static length")
            }
        };

        let distributions = Distributions::calculate(msg_usize)?;

        Ok(Self {
            id: 0,
            msg_len,
            range_distribution: distributions.range_distribution,
            block_number_distribution: distributions.block_number_distribution,
        })
    }

    pub fn make_packet(&mut self, msg: &[u8]) -> Result<Packet, LTError> {
        if msg.len() != msg_len_as_usize(self.msg_len) {
            return Err(LTError::LengthMismatch);
        }

        let mut rng = make_prng(self.id);

        let d = self.range_distribution.sample(&mut rng);

        let mut block = self.select_block(&mut rng, msg);
        for _n in 1..d {
            let block_addition = self.select_block(&mut rng, msg);
            block.xor_with(&block_addition);
        }
        let id = self.id;
        self.id = self.id.wrapping_add(1);
        Ok(Packet::new(self.msg_len, id, block))
    }

    fn select_block(&self, rng: &mut Lcg64Xsh32, msg: &[u8]) -> Block {
        let block_number = self.block_number_distribution.sample(rng);
        let content = match msg.get(block_number * BLOCK_SIZE..(block_number + 1) * BLOCK_SIZE) {
            Some(a) => a.try_into().expect("static size"),
            None => {
                let mut padded = [0; BLOCK_SIZE];
                let existing_slice = &msg[block_number * BLOCK_SIZE..];
                padded[..existing_slice.len()].copy_from_slice(existing_slice);
                padded
            }
        };
        Block { content }
    }
}
