#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

pub const BLOCK_SIZE: usize = 245;

#[derive(Clone, Debug)]
pub struct Block {
    pub(crate) content: [u8; BLOCK_SIZE],
}

impl Block {
    pub(crate) fn xor_with(&mut self, block: &Block) {
        for i in 0..BLOCK_SIZE {
            self.content[i] ^= block.content[i]
        }
    }
}

#[derive(Debug)]
pub struct IsolatedBlock {
    pub(crate) body: Block,
    pub(crate) block_number: usize,
}

#[derive(Debug)]
pub struct MixedBlock {
    pub(crate) body: Block,
    pub(crate) block_numbers: Vec<usize>,
}

#[cfg(feature = "std")]
impl MixedBlock {
    pub(crate) fn block_number_at_index(&self, block_number: usize) -> Option<usize> {
        self.block_numbers.iter().position(|x| *x == block_number)
    }
}
