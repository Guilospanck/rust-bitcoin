use serde::{Deserialize, Serialize};

pub type Account = String;
pub type Timestamp = u32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
  pub from: Account,
  pub to: Account,
  pub amount: f32,
}

/// BlockHeader is the head of the block.
/// The hash of the block is, actually, the hash of the block header.
/// Bitcoin networks uses the double hashing in order to get the block's header hash.
/// Note that the block hash is not included inside the block's structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeader {
  pub version: String,
  pub previous_block_hash: String,
  pub merkle_root: String,
  pub timestamp: Timestamp,
  pub bits: u32,
  pub nonce: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
  pub block_size: u32,
  pub block_header: BlockHeader,
  pub transactions_counter: u32,
  pub transactions: Vec<Transaction>,
}

// impl Block {

// }
