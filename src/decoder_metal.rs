#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use rand::distributions::{Uniform, WeightedIndex};

use crate::block::{Block, IsolatedBlock, MixedBlock, BLOCK_SIZE};
use crate::distributions::Distributions;
use crate::error::LTError;
use crate::packet::Packet;
use crate::utils::{block_numbers_for_id, msg_len_as_usize, number_of_blocks};

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

struct AddressBitBlockFlag<A: ExternalAddress> {
    address: A,
    bit: u8, //0..7
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
    pub number_packets_in_buffer: u16, // total u16::MAX numbers of original packets, should fit
    pub range_distribution: WeightedIndex<f32>,
    pub block_number_distribution: Uniform<u32>,
}

impl<A: ExternalAddress> DecoderMetal<A> {
    pub fn init<M: ExternalMemory<A>>(
        external_memory: &mut M,
        packet: Packet,
    ) -> Result<Self, LTError> {
        let msg_usize = msg_len_as_usize(packet.msg_len);
        let number_of_blocks = number_of_blocks(msg_usize);
        let distributions = Distributions::calculate(number_of_blocks as u32)?;
        let mut flag_writer_address = A::zero();
        let number_of_flag_bytes = number_of_flag_bytes(number_of_blocks);
        for _i in 0..number_of_flag_bytes {
            external_memory.write_external(&flag_writer_address, &[0]);
            flag_writer_address.shift(1);
        }
        let mut decoder = Self {
            start_address: A::zero(),
            msg_len: packet.msg_len,
            number_packets_in_buffer: 0,
            range_distribution: distributions.range_distribution,
            block_number_distribution: distributions.block_number_distribution,
        };
        decoder.add_block(external_memory, packet.id, packet.block);
        Ok(decoder)
    }

    fn address_finalized_block_flag(&self, block_number: usize) -> AddressBitBlockFlag<A> {
        let msg_usize = msg_len_as_usize(self.msg_len);
        let number_of_blocks = number_of_blocks(msg_usize);

        if block_number > number_of_blocks {
            panic!("block number too high")
        }

        let mut address = self.start_address;
        address.shift(block_number / BITS_IN_BYTE);

        AddressBitBlockFlag {
            address,
            bit: (block_number % BITS_IN_BYTE) as u8,
        }
    }

    fn is_block_finalized<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        block_number: usize,
    ) -> bool {
        let address_bit_block_flag = self.address_finalized_block_flag(block_number);
        let flag_set_bytes = external_memory.read_external(&address_bit_block_flag.address, 1)[0];
        (flag_set_bytes & (1 << address_bit_block_flag.bit)) != 0
    }

    fn mark_block_finalized<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        block_number: usize,
    ) {
        let address_bit_block_flag = self.address_finalized_block_flag(block_number);
        let mut flag_set_bytes =
            external_memory.read_external(&address_bit_block_flag.address, 1)[0];
        flag_set_bytes |= 1 << address_bit_block_flag.bit;
        external_memory.write_external(&address_bit_block_flag.address, &[flag_set_bytes]);
    }

    fn add_block<M: ExternalMemory<A>>(
        &mut self,
        external_memory: &mut M,
        id: u16,
        current_block: Block,
    ) {
        let block_numbers = self.block_numbers_for_id(id);

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

    pub fn is_ready<M: ExternalMemory<A>>(&self, external_memory: &mut M) -> bool {
        let mut all_finalized = true;
        let msg_usize = msg_len_as_usize(self.msg_len);
        let number_of_blocks = number_of_blocks(msg_usize);
        for i in 0..number_of_blocks {
            if !self.is_block_finalized(external_memory, i) {
                all_finalized = false;
                break;
            }
        }
        all_finalized
    }

    pub fn try_read<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
    ) -> Option<ExternalData<A>> {
        if self.is_ready(external_memory) {
            Some(ExternalData {
                start_address: self.address_isolated_block(0),
                len: msg_len_as_usize(self.msg_len),
            })
        } else {
            None
        }
    }

    pub fn number_of_collected_blocks<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
    ) -> usize {
        let mut number_of_collected = 0;
        let msg_usize = msg_len_as_usize(self.msg_len);
        let number_of_blocks = number_of_blocks(msg_usize);
        for i in 0..number_of_blocks {
            if self.is_block_finalized(external_memory, i) {
                number_of_collected += 1
            }
        }
        number_of_collected
    }

    pub fn total_blocks(&self) -> usize {
        let msg_usize = msg_len_as_usize(self.msg_len);
        number_of_blocks(msg_usize)
    }

    pub fn block_numbers_for_id(&self, id: u16) -> Vec<usize> {
        block_numbers_for_id(
            &self.range_distribution,
            &self.block_number_distribution,
            id,
        )
    }

    pub fn process_isolated<M: ExternalMemory<A>>(
        &mut self,
        external_memory: &mut M,
        isolated_block: IsolatedBlock,
    ) {
        if !self.is_block_finalized(external_memory, isolated_block.block_number) {
            self.mark_block_finalized(external_memory, isolated_block.block_number);
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
            .filter(|block_number| !self.is_block_finalized(external_memory, *block_number))
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
            if self.is_block_finalized(external_memory, *block_number) {
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
        let number_of_blocks = number_of_blocks(msg_usize);
        let number_of_flag_bytes = number_of_flag_bytes(number_of_blocks);
        if isolated_block_number < number_of_blocks {
            let mut address = self.start_address;
            address.shift(number_of_flag_bytes + isolated_block_number * BLOCK_SIZE);
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
        let number_of_blocks = number_of_blocks(msg_usize);
        let number_of_flag_bytes = number_of_flag_bytes(number_of_blocks);

        // start of buffer
        address.shift(number_of_flag_bytes + number_of_blocks * BLOCK_SIZE);
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

const BITS_IN_BYTE: usize = 8;

fn number_of_flag_bytes(number_of_blocks: usize) -> usize {
    if number_of_blocks % BITS_IN_BYTE == 0 {
        number_of_blocks / BITS_IN_BYTE
    } else {
        number_of_blocks / BITS_IN_BYTE + 1
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use rand::Fill;

    use super::*;
    use crate::encoder::Encoder;
    use crate::real_packets::*;

    const MSG_LEN_LONG: usize = 500_002;
    const COUNTER_STOP: usize = 12000;

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

    struct ExternalMemoryMockSmall([u8; 1000]);

    impl ExternalMemory<Position> for ExternalMemoryMockSmall {
        fn write_external(&mut self, address: &Position, data: &[u8]) {
            self.0[address.0..address.0 + data.len()].copy_from_slice(data)
        }
        fn read_external(&mut self, address: &Position, len: usize) -> Vec<u8> {
            self.0[address.0..address.0 + len].to_vec()
        }
    }

    fn full_cycle_metal_mock(msg: &[u8]) {
        let mut external_memory = ExternalMemoryMock;

        let mut counter = 0usize;
        let mut encoder = Encoder::init(msg).unwrap();
        let mut maybe_decoder = None;

        loop {
            encoder.id = rand::random::<u16>();
            let maybe_packet = encoder.make_packet(msg).unwrap();
            if let Some(packet) = maybe_packet {
                maybe_decoder = match maybe_decoder {
                    None => Some(DecoderMetal::init(&mut external_memory, packet).unwrap()),
                    Some(mut decoder) => {
                        decoder.add_packet(&mut external_memory, packet).unwrap();
                        if let Some(a) = decoder.try_read(&mut external_memory) {
                            assert_eq!(a.len, msg.len());
                            assert_eq!(
                                unsafe { &EM[a.start_address.0..a.start_address.0 + a.len] },
                                msg
                            );
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
    fn long_random_data_full_cycle_metal_mock() {
        let mut rng = rand::thread_rng();
        let mut msg = [0; MSG_LEN_LONG];
        msg.try_fill(&mut rng).unwrap();
        full_cycle_metal_mock(&msg)
    }
/*
    #[test]
    fn real_packets_1_metal_mock() {
        let mut external_memory = ExternalMemoryMockSmall([0u8; 1000]);

        let mut decoder_1 =
            DecoderMetal::init(&mut external_memory, Packet::deserialize(PACKET_RAW_1)).unwrap();
        assert_eq!(decoder_1.msg_len, [0, 1, 101]);
        assert_eq!(decoder_1.total_blocks(), 2);
        assert_eq!(
            decoder_1.number_of_collected_blocks(&mut external_memory),
            1
        );
        assert_eq!(decoder_1.number_packets_in_buffer, 0);
        assert!(decoder_1.is_block_finalized(&mut external_memory, 0));
        assert!(!decoder_1.is_block_finalized(&mut external_memory, 1));
        decoder_1
            .add_packet(&mut external_memory, Packet::deserialize(PACKET_RAW_2))
            .unwrap();
        assert_eq!(decoder_1.msg_len, [0, 1, 101]);
        assert_eq!(decoder_1.total_blocks(), 2);
        assert_eq!(
            decoder_1.number_of_collected_blocks(&mut external_memory),
            2
        );
        assert!(decoder_1.is_block_finalized(&mut external_memory, 0));
        assert!(decoder_1.is_block_finalized(&mut external_memory, 1));
        let external_data_1 = decoder_1.try_read(&mut external_memory).unwrap();
        let data_1 =
            external_memory.read_external(&external_data_1.start_address, external_data_1.len);

        external_memory = ExternalMemoryMockSmall([0u8; 1000]);

        let mut decoder_2 =
            DecoderMetal::init(&mut external_memory, Packet::deserialize(PACKET_RAW_1)).unwrap();
        assert_eq!(decoder_2.msg_len, [0, 1, 101]);
        assert_eq!(decoder_2.total_blocks(), 2);
        assert_eq!(
            decoder_2.number_of_collected_blocks(&mut external_memory),
            1
        );
        assert_eq!(decoder_2.number_packets_in_buffer, 0);
        assert!(decoder_2.is_block_finalized(&mut external_memory, 0));
        assert!(!decoder_2.is_block_finalized(&mut external_memory, 1));
        decoder_2
            .add_packet(&mut external_memory, Packet::deserialize(PACKET_RAW_3))
            .unwrap();
        assert_eq!(decoder_2.msg_len, [0, 1, 101]);
        assert_eq!(decoder_2.total_blocks(), 2);
        assert_eq!(
            decoder_2.number_of_collected_blocks(&mut external_memory),
            2
        );
        assert!(decoder_2.is_block_finalized(&mut external_memory, 0));
        assert!(decoder_2.is_block_finalized(&mut external_memory, 1));
        let external_data_2 = decoder_2.try_read(&mut external_memory).unwrap();
        let data_2 =
            external_memory.read_external(&external_data_2.start_address, external_data_2.len);

        external_memory = ExternalMemoryMockSmall([0u8; 1000]);

        let mut decoder_3 =
            DecoderMetal::init(&mut external_memory, Packet::deserialize(PACKET_RAW_2)).unwrap();
        assert_eq!(decoder_3.msg_len, [0, 1, 101]);
        assert_eq!(decoder_3.total_blocks(), 2);
        assert_eq!(
            decoder_3.number_of_collected_blocks(&mut external_memory),
            1
        );
        assert_eq!(decoder_3.number_packets_in_buffer, 0);
        assert!(!decoder_3.is_block_finalized(&mut external_memory, 0));
        assert!(decoder_3.is_block_finalized(&mut external_memory, 1));
        decoder_3
            .add_packet(&mut external_memory, Packet::deserialize(PACKET_RAW_3))
            .unwrap();
        assert_eq!(decoder_3.msg_len, [0, 1, 101]);
        assert_eq!(decoder_3.total_blocks(), 2);
        assert_eq!(
            decoder_3.number_of_collected_blocks(&mut external_memory),
            2
        );
        assert!(decoder_3.is_block_finalized(&mut external_memory, 0));
        assert!(decoder_3.is_block_finalized(&mut external_memory, 1));
        let external_data_3 = decoder_3.try_read(&mut external_memory).unwrap();
        let data_3 =
            external_memory.read_external(&external_data_3.start_address, external_data_3.len);

        external_memory = ExternalMemoryMockSmall([0u8; 1000]);

        let mut decoder_4 =
            DecoderMetal::init(&mut external_memory, Packet::deserialize(PACKET_RAW_3)).unwrap();
        assert_eq!(decoder_4.msg_len, [0, 1, 101]);
        assert_eq!(decoder_4.total_blocks(), 2);
        assert_eq!(
            decoder_4.number_of_collected_blocks(&mut external_memory),
            0
        );
        assert_eq!(decoder_4.number_packets_in_buffer, 1);
        assert!(!decoder_4.is_block_finalized(&mut external_memory, 0));
        assert!(!decoder_4.is_block_finalized(&mut external_memory, 1));
        decoder_4
            .add_packet(&mut external_memory, Packet::deserialize(PACKET_RAW_1))
            .unwrap();
        assert_eq!(decoder_4.msg_len, [0, 1, 101]);
        assert_eq!(decoder_4.total_blocks(), 2);
        assert_eq!(
            decoder_4.number_of_collected_blocks(&mut external_memory),
            2
        );
        assert!(decoder_4.is_block_finalized(&mut external_memory, 0));
        assert!(decoder_4.is_block_finalized(&mut external_memory, 1));
        let external_data_4 = decoder_4.try_read(&mut external_memory).unwrap();
        let data_4 =
            external_memory.read_external(&external_data_4.start_address, external_data_4.len);

        assert_eq!(data_1, DATA);
        assert_eq!(data_2, DATA);
        assert_eq!(data_3, DATA);
        assert_eq!(data_4, DATA);
    }

    #[test]
    fn real_packets_2_damaged_metal_mock() {
        let mut external_memory = ExternalMemoryMockSmall([0u8; 1000]);

        let decoder =
            DecoderMetal::init(&mut external_memory, Packet::deserialize(PACKET_RAW_4)).unwrap();
        assert_eq!(decoder.msg_len, [0, 1, 101]);
        assert_eq!(decoder.total_blocks(), 2);
        assert_eq!(decoder.number_of_collected_blocks(&mut external_memory), 0);
        assert!(!decoder.is_block_finalized(&mut external_memory, 0));
        assert!(!decoder.is_block_finalized(&mut external_memory, 1));
        assert_eq!(decoder.number_packets_in_buffer, 0);
    }

    #[test]
    fn real_packets_3_metal_mock() {
        let mut external_memory = ExternalMemoryMockSmall([0u8; 1000]);

        // [1, 0] sequence
        let mut decoder =
            DecoderMetal::init(&mut external_memory, Packet::deserialize(PACKET_RAW_3)).unwrap();

        // add [0, 1] sequence, block goes to buffer, still no blocks ready
        decoder
            .add_packet(&mut external_memory, Packet::deserialize(PACKET_RAW_5))
            .unwrap();
        assert_eq!(decoder.total_blocks(), 2);
        assert_eq!(decoder.number_of_collected_blocks(&mut external_memory), 0);
        assert!(!decoder.is_block_finalized(&mut external_memory, 0));
        assert!(!decoder.is_block_finalized(&mut external_memory, 1));
        assert_eq!(decoder.number_packets_in_buffer, 2);

        // add [0], solved
        decoder
            .add_packet(&mut external_memory, Packet::deserialize(PACKET_RAW_1))
            .unwrap();
        assert_eq!(decoder.total_blocks(), 2);
        assert_eq!(decoder.number_of_collected_blocks(&mut external_memory), 2);
        assert!(decoder.is_block_finalized(&mut external_memory, 0));
        assert!(decoder.is_block_finalized(&mut external_memory, 1));
        assert_eq!(decoder.number_packets_in_buffer, 2);
        let external_data = decoder.try_read(&mut external_memory).unwrap();
        let data = external_memory.read_external(&external_data.start_address, external_data.len);

        assert_eq!(data, DATA);
    }

    #[test]
    fn real_packets_4_metal_mock() {
        let mut external_memory = ExternalMemoryMockSmall([0u8; 1000]);

        // [0, 1] sequence
        let mut decoder =
            DecoderMetal::init(&mut external_memory, Packet::deserialize(PACKET_RAW_5)).unwrap();

        // add [1, 0] sequence, block goes to buffer, still no blocks ready
        decoder
            .add_packet(&mut external_memory, Packet::deserialize(PACKET_RAW_3))
            .unwrap();
        assert_eq!(decoder.total_blocks(), 2);
        assert_eq!(decoder.number_of_collected_blocks(&mut external_memory), 0);
        assert!(!decoder.is_block_finalized(&mut external_memory, 0));
        assert!(!decoder.is_block_finalized(&mut external_memory, 1));
        assert_eq!(decoder.number_packets_in_buffer, 2);

        // add [0], solved
        decoder
            .add_packet(&mut external_memory, Packet::deserialize(PACKET_RAW_1))
            .unwrap();
        assert_eq!(decoder.total_blocks(), 2);
        assert_eq!(decoder.number_of_collected_blocks(&mut external_memory), 2);
        assert!(decoder.is_block_finalized(&mut external_memory, 0));
        assert!(decoder.is_block_finalized(&mut external_memory, 1));
        assert_eq!(decoder.number_packets_in_buffer, 2);
        let external_data = decoder.try_read(&mut external_memory).unwrap();
        let data = external_memory.read_external(&external_data.start_address, external_data.len);

        assert_eq!(data, DATA);
    }
*/
}
