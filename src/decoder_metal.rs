#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use bitvec::{bitvec, prelude::Msb0, vec::BitVec};
use rand::distributions::{Distribution, Uniform, WeightedIndex};

use crate::block::{Block, IsolatedBlock, MixedBlock, BLOCK_SIZE};
use crate::distributions::Distributions;
use crate::error::LTError;
use crate::packet::Packet;
use crate::utils::{make_prng, msg_len_as_usize};

pub trait ExternalAddress: Copy {
    fn zero() -> Self;
    fn shift(&mut self, position: usize);
}

pub struct ExternalData<A: ExternalAddress> {
    pub start_address: A,
    pub len: usize,
}

pub trait ExternalMemory<A: ExternalAddress> {
    fn write_external(&mut self, address: &A, data: &[u8]);
    fn read_external(&mut self, address: &A, len: usize) -> Vec<u8>;
}

/// Buffer element length.
///
/// Buffer element consists of usage flag, u16 id, and block itself.
const BUFFER_ELEMENT_LEN: usize = BLOCK_SIZE + 3;

pub struct DecoderMetal<A>
where
    A: ExternalAddress,
{
    pub start_address: A,
    pub msg_len: [u8; 3],
    pub finalized_content: BitVec<u8, Msb0>,
    pub number_packets_in_buffer: u16, // total u16::MAX numbers of original packets, should fit
    pub range_distribution: WeightedIndex<f32>,
    pub block_number_distribution: Uniform<usize>,
}

impl<A: ExternalAddress> DecoderMetal<A> {
    pub fn init<M: ExternalMemory<A>>(
        external_memory: &mut M,
        packet: Packet,
    ) -> Result<Self, LTError> {
        let msg_usize = msg_len_as_usize(packet.msg_len);
        let number_of_blocks = {
            if msg_usize % BLOCK_SIZE == 0 {
                msg_usize / BLOCK_SIZE
            } else {
                msg_usize / BLOCK_SIZE + 1
            }
        };
        let distributions = Distributions::calculate(msg_usize)?;
        let mut decoder = Self {
            start_address: A::zero(),
            msg_len: packet.msg_len,
            finalized_content: bitvec![u8, Msb0; 0; number_of_blocks],
            number_packets_in_buffer: 0,
            range_distribution: distributions.range_distribution,
            block_number_distribution: distributions.block_number_distribution,
        };
        decoder.add_block(external_memory, packet.id, packet.block);
        Ok(decoder)
    }

    fn add_block<M: ExternalMemory<A>>(
        &mut self,
        external_memory: &mut M,
        id: u16,
        current_block: Block,
    ) {
        let mut rng = make_prng(id);

        let d = self.range_distribution.sample(&mut rng);

        let mut block_numbers: Vec<usize> = Vec::new();
        for _n in 0..d {
            block_numbers.push(self.block_number_distribution.sample(&mut rng));
        }

        if block_numbers.len() == 1 {
            let isolated_block = IsolatedBlock {
                body: current_block,
                block_number: block_numbers[0],
            };
            self.process_isolated(external_memory, isolated_block);
        } else {
            let mixed_block = MixedBlock {
                body: current_block,
                block_numbers,
            };
            self.process_mixed(external_memory, mixed_block, id);
        }
    }

    pub fn add_packet<M: ExternalMemory<A>>(
        &mut self,
        external_memory: &mut M,
        packet: Packet,
    ) -> Result<(), LTError> {
        if packet.msg_len != self.msg_len {
            Err(LTError::LengthMismatch)
        } else {
            self.add_block(external_memory, packet.id, packet.block);
            Ok(())
        }
    }

    pub fn is_ready(&self) -> bool {
        self.finalized_content.iter().fold(
            true,
            |total_flag, element| {
                if !element.as_ref() {
                    false
                } else {
                    total_flag
                }
            },
        )
    }

    pub fn try_read(&self) -> Option<ExternalData<A>> {
        if self.is_ready() {
            Some(ExternalData {
                start_address: self.start_address,
                len: msg_len_as_usize(self.msg_len),
            })
        } else {
            None
        }
    }

    pub fn number_of_collected(&self) -> usize {
        self.finalized_content
            .iter()
            .fold(0, |total_number, element| {
                if *element {
                    total_number + 1
                } else {
                    total_number
                }
            })
    }

    fn block_numbers_for_id(&self, id: u16) -> Vec<usize> {
        let mut rng = make_prng(id);
        let d = self.range_distribution.sample(&mut rng);
        let mut block_numbers: Vec<usize> = Vec::new();
        for _n in 0..d {
            let proposed_number = self.block_number_distribution.sample(&mut rng);
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

    pub fn process_isolated<M: ExternalMemory<A>>(
        &mut self,
        external_memory: &mut M,
        isolated_block: IsolatedBlock,
    ) {
        if !self.finalized_content[isolated_block.block_number] {
            self.finalized_content
                .replace(isolated_block.block_number, true);
            self.write_isolated_block(external_memory, &isolated_block);
            for i in 0..self.number_packets_in_buffer {
                if self.read_buffer_block_active_flag(external_memory, i) {
                    let id = self.read_buffer_block_id(external_memory, i);
                    let block_numbers = self.block_numbers_for_id(id);
                    if block_numbers.contains(&isolated_block.block_number) {
                        self.xor_buffer_block(external_memory, i, &isolated_block.body);
                    }
                }
            }
            while let Some(isolated_block) = self.maybe_single_from_buffer(external_memory) {
                self.process_isolated(external_memory, isolated_block)
            }
            self.remove_empty_from_buffer(external_memory);
        }
    }

    pub fn maybe_single_from_buffer<M: ExternalMemory<A>>(
        &mut self,
        external_memory: &mut M,
    ) -> Option<IsolatedBlock> {
        let mut maybe_isolated_block = None;
        for i in 0..self.number_packets_in_buffer {
            if self.read_buffer_block_active_flag(external_memory, i) {
                let block_numbers = self.filter_block_numbers_active_block(external_memory, i);
                if block_numbers.len() == 1 {
                    maybe_isolated_block = Some(IsolatedBlock {
                        body: self.read_buffer_block(external_memory, i),
                        block_number: block_numbers[0],
                    });
                    self.deactivate_buffer_element(external_memory, i);
                    break;
                }
            }
        }
        maybe_isolated_block
    }

    pub fn remove_empty_from_buffer<M: ExternalMemory<A>>(&mut self, external_memory: &mut M) {
        for i in 0..self.number_packets_in_buffer {
            if self.read_buffer_block_active_flag(external_memory, i)
                && self
                    .filter_block_numbers_active_block(external_memory, i)
                    .is_empty()
            {
                self.deactivate_buffer_element(external_memory, i);
            }
        }
    }

    fn filter_block_numbers_active_block<M: ExternalMemory<A>>(
        &mut self,
        external_memory: &mut M,
        buffer_packet_index: u16,
    ) -> Vec<usize> {
        let id = self.read_buffer_block_id(external_memory, buffer_packet_index);
        let block_numbers = self.block_numbers_for_id(id);
        block_numbers
            .into_iter()
            .filter(|block_number| !self.finalized_content[*block_number])
            .collect()
    }

    pub fn process_mixed<M: ExternalMemory<A>>(
        &mut self,
        external_memory: &mut M,
        mut mixed_block: MixedBlock,
        mixed_block_id: u16,
    ) {
        let mut index_set_to_remove = Vec::new();
        for (i, block_number) in mixed_block.block_numbers.iter().enumerate() {
            if self.finalized_content[*block_number] {
                index_set_to_remove.push(i);
                let already_known_block = self.read_isolated_block(external_memory, *block_number);
                mixed_block.body.xor_with(&already_known_block);
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
                self.process_isolated(external_memory, new_isolated_block);
            }
            _ => {
                let mut address = self.address_add_to_buffer();
                self.number_packets_in_buffer += 1;
                external_memory.write_external(&address, &[1]);
                address.shift(1);
                external_memory.write_external(&address, &mixed_block_id.to_be_bytes());
                address.shift(2);
                external_memory.write_external(&address, &mixed_block.body.content);
            }
        }
    }

    fn address_isolated_block(&self, isolated_block_number: usize) -> A {
        let msg_usize = msg_len_as_usize(self.msg_len);
        let number_of_blocks = {
            if msg_usize % BLOCK_SIZE == 0 {
                msg_usize / BLOCK_SIZE
            } else {
                msg_usize / BLOCK_SIZE + 1
            }
        };
        if isolated_block_number < number_of_blocks {
            let mut address = self.start_address;
            address.shift(isolated_block_number * BLOCK_SIZE);
            address
        } else {
            panic!("requested address of non-existing isolated block {isolated_block_number}")
        }
    }

    fn read_isolated_block<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        isolated_block_number: usize,
    ) -> Block {
        let address = self.address_isolated_block(isolated_block_number);
        let block_bytes = external_memory.read_external(&address, BLOCK_SIZE);
        Block {
            content: block_bytes.try_into().expect("static length"),
        }
    }

    fn write_isolated_block<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        isolated_block: &IsolatedBlock,
    ) {
        let address = self.address_isolated_block(isolated_block.block_number);
        external_memory.write_external(&address, &isolated_block.body.content);
    }

    fn address_buffer_start(&self) -> A {
        let mut address = self.start_address;
        let msg_usize = msg_len_as_usize(self.msg_len);
        let number_of_blocks = {
            if msg_usize % BLOCK_SIZE == 0 {
                msg_usize / BLOCK_SIZE
            } else {
                msg_usize / BLOCK_SIZE + 1
            }
        };

        // start of buffer
        address.shift(number_of_blocks * BLOCK_SIZE);
        address
    }

    fn address_buffer_element(&self, buffer_element_number: u16) -> A {
        if buffer_element_number <= self.number_packets_in_buffer {
            let mut address = self.address_buffer_start();

            // shift to requested block
            address.shift(buffer_element_number as usize * BUFFER_ELEMENT_LEN);
            address
        } else {
            panic!("requested address of non-existing buffer element {buffer_element_number}")
        }
    }

    fn address_add_to_buffer(&self) -> A {
        self.address_buffer_element(self.number_packets_in_buffer)
    }

    fn read_buffer_block_active_flag<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        buffer_element_number: u16,
    ) -> bool {
        let address = self.address_buffer_element(buffer_element_number);
        let flag_byte = external_memory.read_external(&address, 1)[0];
        if flag_byte == 0 {
            false
        } else if flag_byte == 1 {
            true
        } else {
            panic!("unexpected flag byte")
        }
    }

    fn deactivate_buffer_element<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        buffer_element_number: u16,
    ) {
        let address = self.address_buffer_element(buffer_element_number);
        external_memory.write_external(&address, &[0]);
    }

    fn read_buffer_block_id<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        buffer_element_number: u16,
    ) -> u16 {
        let mut address = self.address_buffer_element(buffer_element_number);
        address.shift(1);
        let id_bytes = external_memory.read_external(&address, 2);
        u16::from_be_bytes(id_bytes.try_into().expect("static length"))
    }

    fn read_buffer_block<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        buffer_element_number: u16,
    ) -> Block {
        let mut address = self.address_buffer_element(buffer_element_number);
        address.shift(3);
        let block_bytes = external_memory.read_external(&address, BLOCK_SIZE);
        Block {
            content: block_bytes.try_into().expect("static length"),
        }
    }

    fn xor_buffer_block<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        buffer_element_number: u16,
        xor_block: &Block,
    ) {
        let mut address = self.address_buffer_element(buffer_element_number);
        address.shift(3);
        let block_bytes = external_memory.read_external(&address, BLOCK_SIZE);
        let mut block = Block {
            content: block_bytes.try_into().expect("static length"),
        };
        block.xor_with(xor_block);
        external_memory.write_external(&address, &block.content);
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use rand::Fill;

    use super::*;
    use crate::encoder::Encoder;

    const MSG_LEN: usize = 500_000;
    const COUNTER_STOP: usize = 4000;

    #[derive(Clone, Copy, Debug)]
    struct Position(usize);

    impl ExternalAddress for Position {
        fn zero() -> Self {
            Self(0)
        }
        fn shift(&mut self, position: usize) {
            self.0 += position;
        }
    }

    struct ExternalMemoryMock;

    static mut EM: [u8; 2_000_000] = [0u8; 2_000_000];

    impl ExternalMemory<Position> for ExternalMemoryMock {
        fn write_external(&mut self, address: &Position, data: &[u8]) {
            unsafe {
                EM[address.0..address.0 + data.len()].copy_from_slice(data);
            }
        }
        fn read_external(&mut self, address: &Position, len: usize) -> Vec<u8> {
            unsafe { EM[address.0..address.0 + len].to_vec() }
        }
    }

    #[test]
    fn full_cycle_metal_mock() {
        let mut rng = rand::thread_rng();

        let mut msg = [0; MSG_LEN];
        msg.try_fill(&mut rng).unwrap();

        let mut external_memory = ExternalMemoryMock;

        let mut counter = 0usize;
        let mut encoder = Encoder::init(&msg).unwrap();
        let mut maybe_decoder = None;

        loop {
            let packet = encoder.make_packet(&msg).unwrap();
            maybe_decoder = match maybe_decoder {
                None => Some(DecoderMetal::init(&mut external_memory, packet).unwrap()),
                Some(mut decoder) => {
                    decoder.add_packet(&mut external_memory, packet).unwrap();
                    if let Some(a) = decoder.try_read() {
                        assert_eq!(a.len, MSG_LEN);
                        assert_eq!(unsafe { &EM[..a.len] }, msg);
                        break;
                    }
                    Some(decoder)
                }
            };
            if counter > COUNTER_STOP {
                panic!("decoding takes unexpectedly long")
            }
            counter += 1;
        }
    }
}
