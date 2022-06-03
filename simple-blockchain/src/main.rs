use num::bigint::BigUint;
use num::pow::pow;
use serde::{Deserialize, Serialize};
use sha256::digest;

const DIFFICULTY_LEVEL: f32 = 1.00;

///
///  Bitcoin’s difficulty level is the estimated number of hashes required to mine a block.
///
///  Difficulty Level = Difficulty Target/Current Target.
///
///  => Difficulty Target (in decimal format) = bits of the Genesis block header in the *target* format (Note that the Difficulty Target is a hexadecimal notation of the target hash whose mining difficulty is 1).///
///  => Current target (in decimal format) = In contrast, the current target is the *target* hash of the most recent block of transactions.
/// When the two values are divided, it yields a whole number which is the difficulty level of mining bitcoin

#[derive(Debug, Serialize, Deserialize)]
struct DataToMintBlock {
  previous_block_hash: String,
  transactions: Vec<Transaction>,
  timestamp: Timestamp,
}

/// This function gets the "target" representation of some "bits".
/// The formula is as follows:
///
///     target = coefficient * 2^(8*(exponent-3))
///
///     where:
///           coefficient = &bits_as_hex[2..]
///           exponent    = &bits_as_hex[..2]
///           
fn get_target_representation(bits: u32) -> String {
  let hex_representation = format!("{:x}", bits); // 1d00ffff
  let exponent = &hex_representation[..2]; // 1d
  let coefficient = &hex_representation[2..]; // 00ffff

  let decimal_exponent = u16::from_str_radix(exponent, 16).unwrap();
  let decimal_coefficient = u128::from_str_radix(coefficient, 16).unwrap();
  let target_two_pow: u16 = 8 * (decimal_exponent - 3);
  let pow_formula = pow(BigUint::from(2u8), target_two_pow as usize); // 2 ^(8*(exponent-3)
  let target = BigUint::from(decimal_coefficient * pow_formula); // target = coefficient * 2 ^(8*(exponent-3))
  let target = format!("{:x}", target);

  let hexa_length = target.len();
  let num_zeros_to_add = 64 - hexa_length;
  let mut zeros = vec!["0"; num_zeros_to_add].join("");
  zeros.push_str(&target);

  let target = zeros;
  target
}

fn get_transactions_merkle_root(transactions: &mut Vec<Transaction>) -> String {
  if transactions.len() == 0 {
    return "".to_owned();
  }

  // stringfies and hashes transactions
  let stringified_transactions: Vec<String> = transactions.iter().map(|transaction| {
    let stringfied = serde_json::to_string(transaction).unwrap();
    digest(digest(stringfied))
  }).collect();

  let merkle_root = build_merkle_root(stringified_transactions);

  merkle_root
}

fn build_merkle_root(stringified_transactions: Vec<String>) -> String {
  let mut stringified_transactions = stringified_transactions;

  // Duplicates last transaction if the length is odd
  if stringified_transactions.len() % 2 != 0 {
    let last_transaction = stringified_transactions.last().unwrap().clone();
    stringified_transactions.push(last_transaction);
  }

  let mut new_stringfied_transaction: Vec<String> = Vec::new();

  for index in (0..stringified_transactions.len()-1).step_by(2) {
    let hashed_current_tx = &stringified_transactions[index]; // HA    
    let hashed_next_tx = &stringified_transactions[index+1]; // HB
  
    let hashed_current_and_next_tx = format!("{}{}", hashed_current_tx, hashed_next_tx);

    let hash_current_and_next_tx = digest(digest(hashed_current_and_next_tx)); // HAB  

    new_stringfied_transaction.push(hash_current_and_next_tx);
  }

  if new_stringfied_transaction.len() != 1 {
    build_merkle_root(new_stringfied_transaction.clone())
  } else {  
    new_stringfied_transaction[0].clone()
  }
}

fn mint_block(data: DataToMintBlock) -> u32 {
  let stringfied = serde_json::to_string(&data).unwrap();

  let nonce: u32 = 0;
  let hash = digest(&stringfied);

  let mut zeros_count: u32 = 0;

  // for c in stringfied.chars() {
  //   if c != '0' || zeros_count >= DIFFICULTY_LEVEL {
  //     break
  //   }
  //   zeros_count = zeros_count+1;
  // }

  println!("{}", hash);

  1
}

type Account = String;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Transaction {
  from: Account,
  to: Account,
  amount: f32,
}

type Timestamp = u32;

/// BlockHeader is the head of the block.
/// The hash of the block is, actually, the hash of the block header.
/// Bitcoin networks uses the double hashing in order to get the block's header hash.
/// Note that the block hash is not included inside the block's structure.
#[derive(Debug, Serialize, Deserialize)]
struct BlockHeader {
  version: String,
  previous_block_hash: String,
  merkle_root: String,
  timestamp: Timestamp,
  difficulty_target: u32,
  nonce: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Block {
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

struct Blockchain {
  blocks: Vec<Block>,
}

impl Blockchain {
  fn add_to_blockchain(&mut self, block: Block) -> () {
    self.blocks.push(block);
  }

  fn get_blockchain_height(self) -> usize {
    self.blocks.len()
  }
}

// fn get_genesis_block() -> Block {
//   Block::genesis()
// }

fn main() {
  // let genesis = get_genesis_block();
  // println!("\nGenesis => {:?}", genesis);
  // let stringfied = serde_json::to_string(&genesis).unwrap();
  // println!("\nStringfied => {:?}", stringfied);

  // let genesis_target = get_target_representation(486604799);
  // println!("{:?}", genesis_target);

  let first_transaction = Transaction {
    from: "COINBASE".to_owned(),
    to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
    amount: 50.0,
  };

  let mut transactions = vec![first_transaction; 5];

  let merkle_root = get_transactions_merkle_root(&mut transactions);
  println!("{}", merkle_root);
}
