use serde::{Deserialize, Serialize};

pub type Account = String;
pub type Timestamp = u32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
  from: Account,
  to: Account,
  amount: f32,
}

/// BlockHeader is the head of the block.
/// The hash of the block is, actually, the hash of the block header.
/// Bitcoin networks uses the double hashing in order to get the block's header hash.
/// Note that the block hash is not included inside the block's structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeader {
  version: String,
  previous_block_hash: String,
  merkle_root: String,
  timestamp: Timestamp,
  bits: u32,
  nonce: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
  block_size: u32,
  block_header: BlockHeader,
  transactions_counter: u32,
  transactions: Vec<Transaction>,
}

// impl Block {
//   fn genesis() -> Self {
//     let first_transaction = Transaction {
//       from: "COINBASE".to_owned(),
//       to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
//       amount: 50.0,
//     };

//     let transactions = vec![first_transaction];
//     let previous_block_hash = "0".to_owned();
//     let timestamp = "2022-05-31T22:32:00Z".to_owned();

//     let data_to_mint = DataToMintBlock {
//       previous_block_hash,
//       transactions: transactions.clone(),
//       timestamp,
//     };

//     let _minted = mint_block(data_to_mint);

//     Block {
//       previous_block_hash: "0".to_owned(),
//       block_hash: "asdasd".to_owned(),
//       transactions,
//       timestamp: "2022-05-31T22:32:00Z".to_owned(),
//       nonce: 0000000,
//     }
//   }
// }
