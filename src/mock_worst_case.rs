use crate::block::{Block, BLOCK_SIZE};
use crate::decoder_metal::{ExternalAddress, ExternalData, ExternalMemory, AddressBitBlockFlag, BITS_IN_BYTE, number_of_flag_bytes};
use crate::error::LTError;
use crate::packet::Packet;
use crate::utils::{msg_len_as_usize, number_of_blocks};

#[derive(Debug)]
pub struct Encoder {
    id: u16,
    msg_len: [u8; 3],
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

        Ok(Self {
            id: 0,
            msg_len,
        })
    }

    pub fn make_packet(&mut self, msg: &[u8]) -> Result<Option<Packet>, LTError> {
        if msg.len() != msg_len_as_usize(self.msg_len) {
            return Err(LTError::LengthMismatch);
        }
        let id = self.id;
        let block = self.select_block(id, msg);

        self.id = {
            if (self.id as usize) + 1 == number_of_blocks(msg.len()) {0}
            else {self.id + 1}
        };
        Ok(Some(Packet::new(self.msg_len, id, block))) // always Some(_) in here, this is to avoid android code remake
    }

    fn select_block(&self, id: u16, msg: &[u8]) -> Block {
        let block_number = id as usize;
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

pub struct DecoderMetal<A>
where
    A: ExternalAddress,
{
    pub start_address: A,
    pub msg_len: [u8; 3],
}

impl<A: ExternalAddress> DecoderMetal<A> {
    pub fn init<M: ExternalMemory<A>>(
        external_memory: &mut M,
        packet: Packet,
    ) -> Result<Self, LTError> {
        let msg_usize = msg_len_as_usize(packet.msg_len);
        let number_of_blocks = number_of_blocks(msg_usize);
        let mut flag_writer_address = A::zero();
        let number_of_flag_bytes = number_of_flag_bytes(number_of_blocks);
        for _i in 0..number_of_flag_bytes {
            external_memory.write_external(&flag_writer_address, &[0]);
            flag_writer_address.shift(1);
        }
        let mut decoder = Self {
            start_address: A::zero(),
            msg_len: packet.msg_len,
        };
        decoder.add_block(external_memory, packet.id, packet.block);
        Ok(decoder)
    }

    fn address_finalized_block_flag(&self, id: u16) -> AddressBitBlockFlag<A> {
        let block_number = id as usize;
        let msg_usize = msg_len_as_usize(self.msg_len);
        let number_of_blocks = number_of_blocks(msg_usize);

        if block_number > number_of_blocks {
            panic!("block number too high {block_number}")
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
        id: u16,
    ) -> bool {
        let address_bit_block_flag = self.address_finalized_block_flag(id);
        let flag_set_bytes = external_memory.read_external(&address_bit_block_flag.address, 1)[0];
        (flag_set_bytes & (1 << address_bit_block_flag.bit)) != 0
    }

    fn mark_block_finalized<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        id: u16,
    ) {
        let address_bit_block_flag = self.address_finalized_block_flag(id);
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
        if !self.is_block_finalized(external_memory, id) {
            self.mark_block_finalized(external_memory, id);
            self.write_block(external_memory, id, current_block);
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
        let number_of_blocks = number_of_blocks(msg_usize) as u16;
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
                start_address: self.address_block(0),
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
        let number_of_blocks = number_of_blocks(msg_usize) as u16;
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

    fn address_block(&self, id: u16) -> A {
        let msg_usize = msg_len_as_usize(self.msg_len);
        let number_of_blocks = number_of_blocks(msg_usize);
        let number_of_flag_bytes = number_of_flag_bytes(number_of_blocks);
        if (id as usize) < number_of_blocks {
            let mut address = self.start_address;
            address.shift(number_of_flag_bytes + id as usize * BLOCK_SIZE);
            address
        } else {
            panic!("requested address of non-existing block {id}")
        }
    }

    fn write_block<M: ExternalMemory<A>>(
        &self,
        external_memory: &mut M,
        id: u16,
        current_block: Block,
    ) {
        let address = self.address_block(id);
        external_memory.write_external(&address, &current_block.content);
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use rand::Fill;
    use std::vec::Vec;

    use super::*;
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
            let packet = encoder.make_packet(msg).unwrap().unwrap();
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
            if counter > COUNTER_STOP {
                panic!("decoding takes unexpectedly long")
            }
            counter += 1;
        }
    }

    #[test]
    fn long_random_data_full_cycle_worst_case() {
        let mut rng = rand::thread_rng();
        let mut msg = [0; MSG_LEN_LONG];
        msg.try_fill(&mut rng).unwrap();
        full_cycle_metal_mock(&msg)
    }
}
