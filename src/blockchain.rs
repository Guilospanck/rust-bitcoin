// use crate::block::{Block};
// use crate::helpers;
// use crate::transaction::Transaction;
// use chrono::prelude::*;

pub struct Blockchain {
  // blocks: Vec<Block>,
}

// impl Blockchain {
//   fn new() -> Blockchain {}

//   fn genesis_block() -> Block {
//     let first_transaction = Transaction {
//       from: "COINBASE".to_owned(),
//       to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
//       amount: 50.0,
//     };

//     let transactions = vec![first_transaction];
//     let merkle_root = helpers::get_transactions_merkle_root(&mut transactions);

//     let previous_block_hash = vec!["0"; 64].join("");

//     let dt: NaiveDateTime = NaiveDate::from_ymd(2022, 6, 3).and_hms(14, 13, 00);
//     let utc = DateTime::<Utc>::from_utc(dt, Utc);
//     let timestamp = utc.timestamp() as u32;

//     let mut block_header = BlockHeader {
//       version: "1".to_owned(),
//       previous_block_hash,
//       merkle_root,
//       timestamp,
//       bits: 486_575_299,
//       nonce: 0,
//     };

//     helpers::mine_block(&mut block_header);

//     let genesis = Block {
//       previous_block_hash,
//       transactions,
//       timestamp: "2022-05-31T22:32:00Z".to_owned(),
//       nonce: 0000000,
//     };
//   }

//   fn add_to_blockchain(&mut self, block: Block) -> () {
//     self.blocks.push(block);
//   }

//   fn get_blockchain_height(self) -> usize {
//     self.blocks.len()
//   }

//   fn get_genesis_block(self) -> Block {
//     self.blocks[0].clone()
//   }

//   fn get_block(self, height: usize) -> Block {
//     self.blocks[height].clone()
//   }
// }
