use std::vec::Vec;

use rand::distributions::{Uniform, WeightedIndex};

use crate::block::{Block, IsolatedBlock, MixedBlock, BLOCK_SIZE};
use crate::distributions::Distributions;
use crate::error::LTError;
use crate::packet::Packet;
use crate::utils::{block_numbers_for_id, msg_len_as_usize, number_of_blocks};

#[derive(Debug)]
pub struct Decoder {
    range_distribution: WeightedIndex<f32>,
    block_number_distribution: Uniform<usize>,
    msg_len: [u8; 3],
    finalized_content: Vec<Option<Block>>,
    buffer: Vec<MixedBlock>,
}

impl Decoder {
    pub fn init(packet: Packet) -> Result<Self, LTError> {
        let msg_usize = msg_len_as_usize(packet.msg_len);
        let number_of_blocks = number_of_blocks(msg_usize);
        let distributions = Distributions::calculate(number_of_blocks)?;
        let mut decoder = Self {
            range_distribution: distributions.range_distribution,
            block_number_distribution: distributions.block_number_distribution,
            msg_len: packet.msg_len,
            finalized_content: vec![None; number_of_blocks],
            buffer: Vec::new(),
        };
        decoder.add_block(packet.id, packet.block);
        Ok(decoder)
    }

    fn add_block(&mut self, id: u16, current_block: Block) {
        let block_numbers = block_numbers_for_id(
            &self.range_distribution,
            &self.block_number_distribution,
            id,
        );

        if block_numbers.len() == 1 {
            let isolated_block = IsolatedBlock {
                body: current_block,
                block_number: block_numbers[0],
            };
            self.process_isolated(isolated_block);
        } else {
            let mixed_block = MixedBlock {
                body: current_block,
                block_numbers,
            };
            println!("is mixed {id}");
            self.process_mixed(mixed_block);
        }
    }

    pub fn add_packet(&mut self, packet: Packet) -> Result<(), LTError> {
        if packet.msg_len != self.msg_len {
            Err(LTError::LengthMismatch)
        } else {
            self.add_block(packet.id, packet.block);
            Ok(())
        }
    }

    pub fn is_ready(&self) -> bool {
        self.finalized_content.iter().fold(
            true,
            |total_flag, element| {
                if element.is_none() {
                    false
                } else {
                    total_flag
                }
            },
        )
    }

    pub fn try_read(&self) -> Option<Vec<u8>> {
        if self.is_ready() {
            let mut out = Vec::with_capacity(self.finalized_content.len() * BLOCK_SIZE);
            for block in self.finalized_content.iter() {
                out.extend_from_slice(
                    &block
                        .as_ref()
                        .expect("just checked to be not empty")
                        .content,
                )
            }
            let msg_usize = msg_len_as_usize(self.msg_len);
            out.truncate(msg_usize);
            Some(out)
        } else {
            None
        }
    }

    pub fn number_of_collected_blocks(&self) -> usize {
        self.finalized_content
            .iter()
            .fold(0, |total_number, element| {
                if element.is_some() {
                    total_number + 1
                } else {
                    total_number
                }
            })
    }

    pub fn total_blocks(&self) -> usize {
        let msg_usize = msg_len_as_usize(self.msg_len);
        number_of_blocks(msg_usize)
    }

    fn process_isolated(&mut self, isolated_block: IsolatedBlock) {
        if self.finalized_content[isolated_block.block_number].is_none() {
            for buffer_block in self.buffer.iter_mut() {
                if let Some(index) = buffer_block.block_number_at_index(isolated_block.block_number)
                {
                    buffer_block.body.xor_with(&isolated_block.body);
                    buffer_block.block_numbers.remove(index);
                }
            }
            self.finalized_content[isolated_block.block_number] = Some(isolated_block.body);
            while let Some(isolated_block) = self.maybe_single_from_buffer() {
                self.process_isolated(isolated_block)
            }
            self.remove_empty_from_buffer();
        }
    }

    fn maybe_single_from_buffer(&mut self) -> Option<IsolatedBlock> {
        let mut maybe_index = None;
        for (i, buffer_block) in self.buffer.iter().enumerate() {
            if buffer_block.block_numbers.len() == 1 {
                maybe_index = Some(i);
                break;
            }
        }
        maybe_index.map(|i| {
            let no_longer_mixed_block = self.buffer.remove(i);
            IsolatedBlock {
                body: no_longer_mixed_block.body,
                block_number: no_longer_mixed_block.block_numbers[0],
            }
        })
    }

    fn remove_empty_from_buffer(&mut self) {
        let mut empty_in_buffer: Vec<usize> = Vec::new();
        for (i, buffer_block) in self.buffer.iter().enumerate() {
            if buffer_block.block_numbers.is_empty() {
                empty_in_buffer.push(i)
            }
        }
        for i in empty_in_buffer.into_iter().rev() {
            self.buffer.remove(i);
        }
    }

    fn process_mixed(&mut self, mut mixed_block: MixedBlock) {
        let mut index_set_to_remove = Vec::new();
        for (i, block_number) in mixed_block.block_numbers.iter().enumerate() {
            if let Some(ref already_known_block) = self.finalized_content[*block_number] {
                index_set_to_remove.push(i);
                mixed_block.body.xor_with(already_known_block); //TODO make sure not to double xor here
            }
        }
        for i in index_set_to_remove.into_iter().rev() {
            mixed_block.block_numbers.remove(i);
        }
        match mixed_block.block_numbers.len() {
            0 => {}
            1 => {
                let new_isolated_block = IsolatedBlock {
                    body: mixed_block.body,
                    block_number: mixed_block.block_numbers[0],
                };
                self.process_isolated(new_isolated_block);
            }
            _ => {
                self.buffer.push(mixed_block);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use rand::Fill;

    use super::*;
    use crate::encoder::Encoder;
    use crate::real_packets::*;

    const MSG_LEN_LONG: usize = 500_002;
    const MSG_LEN_SHORT: usize = 357;
    const COUNTER_STOP: usize = 6000;

    fn full_cycle(msg: &[u8]) {
        let mut counter = 0usize;
        let mut encoder = Encoder::init(msg).unwrap();
        let mut maybe_decoder = None;

        loop {
            encoder.id = rand::random::<u16>();
            let maybe_packet = encoder.make_packet(msg).unwrap();
            if let Some(packet) = maybe_packet {
                maybe_decoder = match maybe_decoder {
                    None => Some(Decoder::init(packet).unwrap()),
                    Some(mut decoder) => {
                        decoder.add_packet(packet).unwrap();
                        if let Some(a) = decoder.try_read() {
                            assert_eq!(a.len(), msg.len());
                            assert_eq!(a, msg);
                            break;
                        }
                        Some(decoder)
                    }
                };
            }
            if counter > COUNTER_STOP {
                panic!("decoding takes unexpectedly long")
            }
            counter += 1;
        }
    }

    #[test]
    fn long_random_data_full_cycle() {
        let mut rng = rand::thread_rng();
        let mut msg = [0; MSG_LEN_LONG];
        msg.try_fill(&mut rng).unwrap();
        full_cycle(&msg)
    }

    #[test]
    fn short_random_data_full_cycle() {
        let mut rng = rand::thread_rng();
        let mut msg = [0; MSG_LEN_SHORT];
        msg.try_fill(&mut rng).unwrap();
        full_cycle(&msg)
    }

    #[test]
    fn short_zeroes_data_full_cycle() {
        full_cycle(&[0u8; MSG_LEN_SHORT])
    }

    #[test]
    fn real_packets() {
        let mut decoder_1 = Decoder::init(Packet::deserialize(PACKET_RAW_1)).unwrap();
        assert_eq!(decoder_1.msg_len, [0, 1, 101]);
        assert_eq!(decoder_1.total_blocks(), 2);
        assert_eq!(decoder_1.number_of_collected_blocks(), 1);
        assert!(decoder_1.finalized_content[0].is_some());
        assert!(decoder_1.finalized_content[1].is_none());
        decoder_1
            .add_packet(Packet::deserialize(PACKET_RAW_2))
            .unwrap();
        assert_eq!(decoder_1.msg_len, [0, 1, 101]);
        assert_eq!(decoder_1.total_blocks(), 2);
        assert_eq!(decoder_1.number_of_collected_blocks(), 2);
        assert!(decoder_1.finalized_content[0].is_some());
        assert!(decoder_1.finalized_content[1].is_some());
        let data_1 = decoder_1.try_read().unwrap();

        let mut decoder_2 = Decoder::init(Packet::deserialize(PACKET_RAW_1)).unwrap();
        assert_eq!(decoder_2.msg_len, [0, 1, 101]);
        assert_eq!(decoder_2.total_blocks(), 2);
        assert_eq!(decoder_2.number_of_collected_blocks(), 1);
        assert!(decoder_2.finalized_content[0].is_some());
        assert!(decoder_2.finalized_content[1].is_none());
        decoder_2
            .add_packet(Packet::deserialize(PACKET_RAW_3))
            .unwrap();
        assert_eq!(decoder_2.msg_len, [0, 1, 101]);
        assert_eq!(decoder_2.total_blocks(), 2);
        assert_eq!(decoder_2.number_of_collected_blocks(), 2);
        assert!(decoder_2.finalized_content[0].is_some());
        assert!(decoder_2.finalized_content[1].is_some());
        let data_2 = decoder_2.try_read().unwrap();

        let mut decoder_3 = Decoder::init(Packet::deserialize(PACKET_RAW_2)).unwrap();
        assert_eq!(decoder_3.msg_len, [0, 1, 101]);
        assert_eq!(decoder_3.total_blocks(), 2);
        assert_eq!(decoder_3.number_of_collected_blocks(), 1);
        assert!(decoder_3.finalized_content[0].is_none());
        assert!(decoder_3.finalized_content[1].is_some());
        decoder_3
            .add_packet(Packet::deserialize(PACKET_RAW_3))
            .unwrap();
        assert_eq!(decoder_3.msg_len, [0, 1, 101]);
        assert_eq!(decoder_3.total_blocks(), 2);
        assert_eq!(decoder_3.number_of_collected_blocks(), 2);
        assert!(decoder_3.finalized_content[0].is_some());
        assert!(decoder_3.finalized_content[1].is_some());
        assert!(decoder_3.is_ready());
        let data_3 = decoder_3.try_read().unwrap();

        assert_eq!(data_1, DATA);
        assert_eq!(data_2, DATA);
        assert_eq!(data_3, DATA);
    }
}
