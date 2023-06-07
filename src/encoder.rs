use rand::distributions::{Uniform, WeightedIndex};

use crate::block::{Block, BLOCK_SIZE};
use crate::distributions::Distributions;
use crate::error::LTError;
use crate::packet::Packet;
use crate::utils::{block_numbers_for_id, msg_len_as_usize, number_of_blocks};

#[derive(Debug)]
pub struct Encoder {
    pub(crate) id: u16,
    msg_len: [u8; 3],
    range_distribution: WeightedIndex<f32>,
    block_number_distribution: Uniform<u32>,
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

        let number_of_blocks = number_of_blocks(msg_usize);
        let distributions = Distributions::calculate(number_of_blocks as u32)?;

        Ok(Self {
            id: 0,
            msg_len,
            range_distribution: distributions.range_distribution,
            block_number_distribution: distributions.block_number_distribution,
        })
    }

    pub fn make_packet(&mut self, msg: &[u8]) -> Result<Option<Packet>, LTError> {
        if msg.len() != msg_len_as_usize(self.msg_len) {
            return Err(LTError::LengthMismatch);
        }

        let block_numbers = block_numbers_for_id(
            &self.range_distribution,
            &self.block_number_distribution,
            self.id,
        );
        let mut maybe_out: Option<Block> = None;
        for block_number in block_numbers.into_iter() {
            maybe_out = match maybe_out {
                Some(mut out) => {
                    let block_addition = self.select_block(block_number, msg);
                    out.xor_with(&block_addition);
                    Some(out)
                }
                None => Some(self.select_block(block_number, msg)),
            }
        }
        let id = self.id;
        self.id = self.id.wrapping_add(1);
        if let Some(block) = maybe_out {
            Ok(Some(Packet::new(self.msg_len, id, block)))
        } else {
            Ok(None)
        }
    }

    fn select_block(&self, block_number: usize, msg: &[u8]) -> Block {
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

#[cfg(feature = "std")]
#[cfg(test)]
mod test {

    use super::*;

    const MSG: &[u8] = &[0; 358];

    #[test]
    fn encoder_makes_blocks_1() {
        let mut encoder = Encoder::init(MSG).unwrap();
        encoder.id = u16::from_be_bytes([0, 0]);
        assert!(encoder.make_packet(MSG).unwrap().is_none());
    }

    #[test]
    fn encoder_makes_blocks_2() {
        let mut encoder = Encoder::init(MSG).unwrap();
        encoder.id = u16::from_be_bytes([0, 3]);
        assert!(encoder.make_packet(MSG).unwrap().is_some());
    }

    #[test]
    fn encoder_makes_blocks_3() {
        let mut encoder = Encoder::init(MSG).unwrap();
        encoder.id = u16::from_be_bytes([0, 2]);
        assert!(encoder.make_packet(MSG).unwrap().is_some());
    }

    #[test]
    fn encoder_makes_blocks_4() {
        let mut encoder = Encoder::init(MSG).unwrap();
        encoder.id = u16::from_be_bytes([0, 6]);
        assert!(encoder.make_packet(MSG).unwrap().is_some());
    }

    #[test]
    fn encoder_makes_blocks_5() {
        let mut encoder = Encoder::init(MSG).unwrap();
        encoder.id = u16::from_be_bytes([0, 14]);
        assert!(encoder.make_packet(MSG).unwrap().is_some());
    }
}
