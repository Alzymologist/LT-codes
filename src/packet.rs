use crate::block::{Block, BLOCK_SIZE};

pub const PACKET_SIZE: usize = BLOCK_SIZE + 5;

#[derive(Debug)]
pub struct Packet {
    pub(crate) msg_len: [u8; 3],
    pub(crate) id: u16,
    pub(crate) block: Block,
}

impl Packet {
    pub fn new(msg_len: [u8; 3], id: u16, block: Block) -> Self {
        Self { msg_len, id, block }
    }

    pub fn serialize(&self) -> [u8; PACKET_SIZE] {
        let mut serialized = [0; PACKET_SIZE];
        serialized[..3].copy_from_slice(&self.msg_len);
        serialized[3..5].copy_from_slice(&self.id.to_be_bytes());
        serialized[5..].copy_from_slice(&self.block.content);
        serialized
    }

    pub fn deserialize(data: [u8; PACKET_SIZE]) -> Self {
        let (msg_len_bytes, tail) = data.split_at(3);
        let msg_len = msg_len_bytes.try_into().expect("static_length");
        let (id_bytes, content_bytes) = tail.split_at(2);
        let id = u16::from_be_bytes(id_bytes.try_into().expect("static length"));
        let block = Block {
            content: content_bytes.try_into().expect("static length"),
        };
        Self { msg_len, id, block }
    }
}
