use num::bigint::BigUint;
use sha256::digest;
use num::pow::pow;

use crate::block::{Transaction, BlockHeader};

///  Bitcoin’s difficulty level is the estimated number of hashes required to mine a block.
///
///  `Difficulty Level = Difficulty Target/Current Target.`
///
///  - `Difficulty Target (in decimal format)` = bits of the Genesis block header in the *target* format (Note that the Difficulty Target is a hexadecimal notation of the target hash whose mining difficulty is 1).
///  - `Current Target (in decimal format)` = In contrast, the current target is the *target* hash of the most recent block of transactions.
/// 
///  When the two values are divided, it yields a whole number which is the difficulty level of mining bitcoin.
const DIFFICULTY_LEVEL: f32 = 1.00;

/// This function gets the "target" representation of some "bits".
/// It returns a String with the hexadecimal representation (32 Bytes - 64 chars) of the target.
/// The formula is as follows:
///
///     target = coefficient * 2^(8*(exponent-3))
///
///     where:
///           coefficient = &bits_as_hex[2..]
///           exponent    = &bits_as_hex[..2]
///           
/// Example:
/// ```rust
/// let genesis_target = get_target_representation(486604799);
/// println!("{:?}", genesis_target); // 00000000ffff0000000000000000000000000000000000000000000000000000
/// ```
pub fn get_target_representation(bits: u32) -> String {
  let hex_representation = format!("{:x}", bits); // 1d00ffff
  let exponent = &hex_representation[..2]; // 1d
  let coefficient = &hex_representation[2..]; // 00ffff

  let decimal_exponent = u16::from_str_radix(exponent, 16).unwrap();
  let decimal_coefficient = u128::from_str_radix(coefficient, 16).unwrap();
  let target_two_pow: u16 = 8 * (decimal_exponent - 3);
  let pow_formula = pow(BigUint::from(2u8), target_two_pow as usize); // 2 ^(8*(exponent-3)
  let target = BigUint::from(decimal_coefficient * pow_formula); // target = coefficient * 2 ^(8*(exponent-3))
  println!("{}", target);
  let target = format!("{:x}", target);

  let hexa_length = target.len();
  let num_zeros_to_add = 64 - hexa_length;
  let mut zeros = vec!["0"; num_zeros_to_add].join("");
  zeros.push_str(&target);

  let target = zeros;
  target
}

/// Gets the merkle root from a set of transactions.
/// Example:
/// ```rust
/// let first_transaction = Transaction {
/// from: "COINBASE".to_owned(),
/// to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
/// amount: 50.0,
/// };

/// let mut transactions = vec![first_transaction; 5];

/// let merkle_root = get_transactions_merkle_root(&mut transactions);
/// println!("{}", merkle_root); // dab0bcbdb46f816630e838a4588c07b313f6ee21f501ca4f497718e63ead6855
/// ```
pub fn get_transactions_merkle_root(transactions: &mut Vec<Transaction>) -> String {
  if transactions.len() == 0 {
    return "".to_owned();
  }

  // Hashes transactions
  let hashed_transactions: Vec<String> = transactions
    .iter()
    .map(|transaction| {
      let stringfied = serde_json::to_string(transaction).unwrap();
      digest(digest(stringfied))
    })
    .collect();

  let merkle_root = build_merkle_root(hashed_transactions);

  merkle_root
}

/// Helper function to build a merkle root from a vector of hashed transactions.
/// Example:
/// 
/// ```rust
/// // Hashes transactions
/// let hashed_transactions: Vec<String> = transactions.iter().map(|transaction| {
///   let stringfied = serde_json::to_string(transaction).unwrap();
///   digest(digest(stringfied))
/// }).collect();

/// let merkle_root = build_merkle_root(hashed_transactions);
/// ```
pub fn build_merkle_root(hashed_transactions: Vec<String>) -> String {
  let mut hashed_transactions = hashed_transactions;

  // Duplicates last transaction if the length is odd
  if hashed_transactions.len() % 2 != 0 {
    let last_transaction = hashed_transactions.last().unwrap().clone();
    hashed_transactions.push(last_transaction);
  }

  let mut new_stringfied_transaction: Vec<String> = Vec::new();

  for index in (0..hashed_transactions.len()-1).step_by(2) {
    let hashed_current_tx = &hashed_transactions[index]; // HA    
    let hashed_next_tx = &hashed_transactions[index+1]; // HB
  
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

pub fn mint_block(block_header: BlockHeader) -> u32 {
  let stringfied = serde_json::to_string(&block_header).unwrap();

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