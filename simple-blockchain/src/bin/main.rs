use btc::helpers;
use btc::{BlockHeader, Transaction};
use chrono::prelude::*;
use std::time::{Instant};
use sha256::digest;
use btc::wallet;

fn test_pow() {
  // let first_transaction = Transaction {
  //   from: "COINBASE".to_owned(),
  //   to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
  //   amount: 50.0,
  // };

  // let mut transactions = vec![first_transaction];
  // let merkle_root = helpers::get_transactions_merkle_root(&mut transactions);

  let merkle_root = "bc15f9dcbe637c187bb94247057b14637316613630126fc396c22e08b89006ea".to_owned();

  let previous_block_hash = vec!["0"; 64].join("");

  let dt: NaiveDateTime = NaiveDate::from_ymd(2022, 6, 3).and_hms(14, 13, 00);
  let utc = DateTime::<Utc>::from_utc(dt, Utc);
  let timestamp = utc.timestamp() as u32;

  let mut block_header = BlockHeader {
    version: "1".to_owned(),
    previous_block_hash,
    merkle_root,
    timestamp,
    bits: 486_604_799,
    nonce: 0,
  };

  println!("{:?}\n", block_header);

  helpers::mine_block(&mut block_header);

  let stringfied = serde_json::to_string(&block_header).unwrap();
  let hash = digest(&stringfied);

  println!("Block hash: {}", hash);
  println!("Nonce: {:?}", block_header.nonce);
}

fn test_target_representation() {
  let genesis_bits = 486_604_799;
  helpers::get_target_representation(genesis_bits);
  let bits_block_730000 = 386_521_239;
  helpers::get_target_representation(bits_block_730000);
  let bits_block_277_316 = 41_668_748;
  helpers::get_target_representation(bits_block_277_316);
}

fn test_merkle_root() {
  let hashed_transactions: Vec<String> = vec![
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87".to_owned(),
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4".to_owned(),
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4".to_owned(),
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d".to_owned(),
  ];

  let merkle_root = helpers::build_merkle_root(hashed_transactions);
  println!("root {}", merkle_root);
}

fn main() {
  // println!("Mining block...");
  // let start = Instant::now();
  // test_pow();
  // let duration = start.elapsed();
  // println!("Time elapsed to mine block is: {:?}", duration);  
  let private_key = wallet::generate_private_key();
  wallet::get_public_key_from_private_key(private_key);
}
