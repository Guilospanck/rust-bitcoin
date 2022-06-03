use crate::block::{Block};

pub struct Blockchain {
  blocks: Vec<Block>,
}

impl Blockchain {
  fn add_to_blockchain(&mut self, block: Block) -> () {
    self.blocks.push(block);
  }

  fn get_blockchain_height(self) -> usize {
    self.blocks.len()
  }

  fn get_genesis_block(self) -> Block {
    self.blocks[0].clone()
  }

  fn get_block(self, height: usize) -> Block {
    self.blocks[height].clone()
  }
}
