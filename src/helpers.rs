use chrono::prelude::*;
use hmac::{Hmac, Mac};
use num::pow::pow;
use num_bigint::{BigInt, BigUint, Sign};
use ripemd::{Digest, Ripemd160};
use sha2::Sha512;
use sha256;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::path::PathBuf; // import without risk of name clashing

use crate::block::BlockHeader;
use crate::transaction::{
  Transaction, VIN_TRANSACTION_HASH_LENGTH_HEX, VIN_VOUT_LENGTH_IN_HEX, VOUT_AMOUNT_LENGTH_IN_HEX,
};

///  Bitcoin’s difficulty level is the estimated number of hashes required to mine a block.
///
///  `Difficulty Level = Genesis Target/Difficulty Target.`
///
///  - `Genesis Target (in decimal format)` = bits of the Genesis block header in the *target* format (hexadecimal notation of the target hash whose mining difficulty is 1).
///  - `Difficulty Target (in decimal format)` = In contrast, the difficulty target is the *target* hash of the most recent block of transactions.
///
///  When the two values are divided, it yields a whole number which is the difficulty level of mining Bitcoin.
// const DIFFICULTY_LEVEL: f32 = 1.00;
const _MAX_BITS: u32 = 486_604_799; // Genesis Block Bits = 0x1d00ffff

const MAX_NONCE: u32 = 4_294_967_295; // 32 bits 2^32 -1

/// PBKDF2 CONSTANTS
const PBKDF2_ITERATION_COUNT: u32 = 2048;
const PBKDF2_DERIVED_KEY_LENGTH_BYTES: usize = 64;

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
///
pub fn get_target_representation(bits: u32) -> String {
  let hex_representation = format!("{:x}", bits); // 1d00ffff
  let exponent = &hex_representation[..2]; // 1d
  let coefficient = &hex_representation[2..]; // 00ffff

  let decimal_exponent = u16::from_str_radix(exponent, 16).unwrap();
  let decimal_coefficient = u128::from_str_radix(coefficient, 16).unwrap();

  let mut target_two_pow: u16 = 8 * (decimal_exponent - 3);
  if decimal_exponent < 3 {
    target_two_pow = 8 * (3 - decimal_exponent);
  }

  let pow_formula = pow(BigUint::from(2u8), target_two_pow as usize); // 2 ^(8*(exponent-3)
  let target = decimal_coefficient * pow_formula; // target = coefficient * 2 ^(8*(exponent-3))
  let target = format!("{:x}", target);
  let hexa_length = target.len();
  let mut zeros = "".to_owned();

  if hexa_length < 64 {
    let num_zeros_to_add = 64 - hexa_length;
    zeros = vec!["0"; num_zeros_to_add].join("");
  }
  zeros.push_str(&target);

  zeros
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
///
pub fn get_transactions_merkle_root(transactions: &mut Vec<Transaction>) -> String {
  if transactions.is_empty() {
    return "".to_owned();
  }

  // Hashes transactions
  let hashed_transactions: Vec<String> = transactions
    .iter()
    .map(|transaction| {
      let stringfied = serde_json::to_string(transaction).unwrap();
      sha256::digest(sha256::digest(stringfied))
    })
    .collect();

  build_merkle_root(hashed_transactions)
}

/// Helper function to build a merkle root from a vector of hashed transactions.
/// Example:
///
/// ```rust
/// // Hashes transactions
/// let hashed_transactions: Vec<String> = transactions.iter().map(|transaction| {
///   let stringfied = serde_json::to_string(transaction).unwrap();
///   sha256::digest(sha256::digest(stringfied))
/// }).collect();

/// let merkle_root = build_merkle_root(hashed_transactions);
/// ```
///
pub fn build_merkle_root(hashed_transactions: Vec<String>) -> String {
  if hashed_transactions.is_empty() {
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned();
    // empty
  }

  if hashed_transactions.len() == 1 {
    return hashed_transactions[0].clone();
  }

  let mut hashed_transactions = hashed_transactions;

  // Duplicates last transaction if the length is odd
  if hashed_transactions.len() % 2 != 0 {
    let last_transaction = hashed_transactions.last().unwrap().clone();
    hashed_transactions.push(last_transaction);
  }

  let mut new_stringfied_transaction: Vec<String> = Vec::new();

  for index in (0..hashed_transactions.len() - 1).step_by(2) {
    let hashed_current_tx = &hashed_transactions[index]; // HA
    let hashed_next_tx = &hashed_transactions[index + 1]; // HB
    let hashed_current_and_next_tx = format!("{}{}", hashed_current_tx, hashed_next_tx);

    let hash_current_and_next_tx = sha256::digest(sha256::digest(hashed_current_and_next_tx)); // HAB

    new_stringfied_transaction.push(hash_current_and_next_tx);
  }

  if new_stringfied_transaction.len() != 1 {
    build_merkle_root(new_stringfied_transaction.clone())
  } else {
    new_stringfied_transaction[0].clone()
  }
}

/// This is a basic proof of work algorithm.
/// It receives a mutable `BlockHeader`, gets the
/// target representation of the `bits` (see `get_target_representation()`) and
/// finally loops through all nonces (0 - MAX_NONCE), sha256 hashing the result
/// and comparing if it is less than or equal to the bits.
///
/// When the whole nonce spectrum is used and a valid hash isn't found, it then
/// updates the block timestamp and tries again.
///
pub fn mine_block(block_header: &mut BlockHeader) {
  let target = get_target_representation(block_header.bits);
  let target_as_bytes = hex::decode(&target).unwrap();
  let target_as_decimal = BigInt::from_bytes_be(Sign::Plus, &target_as_bytes);

  for nonce in 0..MAX_NONCE {
    block_header.nonce = nonce;

    let stringfied = serde_json::to_string(&block_header).unwrap();

    let hash = sha256::digest(&stringfied);

    let decimal_hash = BigInt::parse_bytes(hash.as_bytes(), 16).unwrap();

    if decimal_hash <= target_as_decimal {
      return;
    }
  }

  // If nonce is not possible, change timestamp and try again
  let utc = Utc::now();
  let timestamp = utc.timestamp() as u32;

  block_header.timestamp = timestamp;
  mine_block(block_header);
}

/// Gets the HMAC-SHA512 one way hashing representation of
/// some data using some key.
/// It returns the representation in a string hexadecimal format.
///
pub fn hmac_sha512_hasher(key: Vec<u8>, data: Vec<u8>) -> String {
  type HmacSha512 = Hmac<Sha512>;

  let mut data_as_hmacsha512 =
    HmacSha512::new_from_slice(&key).expect("Something went wrong with HMAC-Sha512 hashing");
  data_as_hmacsha512.update(&data);
  let result = data_as_hmacsha512.finalize();

  format!("{:x}", result.into_bytes())
}

/// Gets the RIPEMD160 representation of a hexadecimal string, returning
/// its hexadecimal representation.
/// On Bitcoin it's used for generating address from a Public Key (K), like
/// `RIPEMD160(SHA256(K))`
///
pub fn ripemd160_hasher(data: String) -> String {
  let mut hasher = Ripemd160::new();
  hasher.update(hex::decode(&data).unwrap());
  let result = hasher.finalize();

  format!("{:x}", result)
}

/// Gets the HASH160 (`RIPEMD160(SHA256(K))`) of some hexadecimal data
/// and returns its hashed data in the hex format.
///
pub fn get_hash160(data: String) -> String {
  let hashed_256 = sha256::digest_bytes(&hex::decode(&data).unwrap());
  ripemd160_hasher(hashed_256)
}

/// Converts a vector of bytes from a representation to another.
///
/// See https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format
/// for more information in how it does the calculation.
///
pub fn convert_bits(from: u8, to: u8, data_bytes: Vec<u8>) -> Vec<u8> {
  let mut bits = String::new();
  for byte in data_bytes {
    let _ = write!(bits, "{:0from$b}", byte, from = from as usize);
  }

  let divisible_by_to = (bits.len() % (to as usize)) == 0;

  if !divisible_by_to {
    let bits_to_pad = (to as usize) - (bits.len() % (to as usize));
    for _i in 0..bits_to_pad {
      bits.push('0');
    }
  }

  let mut grouped: Vec<u8> = Vec::new();

  for i in (0..bits.len()).step_by(to as usize) {
    let bits_as_decimal = u8::from_str_radix(&bits[i..(i + to as usize)], 2).unwrap();
    grouped.push(bits_as_decimal);
  }

  grouped
}

/// This is a helper function that gets the PBKDF2 (Password-Based Key Derivation Function 2) of the mnemonic phrase using
/// HMAC-SHA512 and then return its seed.
/// Args:
///   - password: normalized (UTF-8 NFKD) mnemonic phrase.
///   - salt: normalized (UTF-8 NFKD) string "mnemonic" concatenated with the passphrase (empty if None).
///
/// Example:
/// ```rust
///   use unicode_normalization::UnicodeNormalization;
///
///   const MNEMONIC_STRING: &str = "mnemonic";
///
///   let mnemonic: Vec<String> = &["army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media", "make", "crunch"].to_vec();
///
///   let normalized_mnemonic: Vec<String> = mnemonic.iter().map(|w| w.nfkd().to_string()).collect();
///   let stringfied_mnemonic: String = normalized_mnemonic.join(" ");
///
///   let salt = format!("{}{}", MNEMONIC_STRING, passphrase);
///   let normalized_salt = salt.nfkd().to_string();
///
///   let seed = get_pbkdf2_sha512(stringfied_mnemonic, normalized_salt);
///
///   assert_eq!(seed, "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570".to_owned());
/// ```
///
pub fn get_pbkdf2_sha512(password: String, salt: String) -> String {
  let password = password.as_bytes();
  let salt = salt.as_bytes();

  let mut seed = [0u8; PBKDF2_DERIVED_KEY_LENGTH_BYTES];
  pbkdf2::pbkdf2::<Hmac<Sha512>>(password, salt, PBKDF2_ITERATION_COUNT, &mut seed);

  hex::encode(seed)
}

/// Helper function to read from a file and return its contents
/// as a ```Vec<String>```.
///
/// Example:
/// ```rust
///  let wordlist: Vec<String> = match read_from_a_file("./src/wordlist/english.txt".to_owned()) {
///   Ok(data) => data,
///   Err(err) => panic!("{}", err),
///  };
/// ```
///
pub fn read_from_a_file_to_a_vec_string(path: String) -> std::io::Result<Vec<String>> {
  let file = File::open(path)?;

  let buf = BufReader::new(file);
  let lines = buf
    .lines()
    .map(|l| l.expect("Could not parse line"))
    .collect();

  Ok(lines)
}

/// Simple helper function to print the derivation path that is currently
/// being solved.
pub fn print_derivation_path(dpath_string: &mut PathBuf, index: u32) {
  println!("===========================");
  dpath_string.push(format!("{}", index));
  println!("{}", dpath_string.to_str().unwrap_or(""),);
}

/// Simple helper to get the Reverse Endian representation of
/// a Hexadecimal string.
pub fn hex_to_reverse_bytes(hex_value: String) -> String {
  let mut hex_value_in_bytes = hex::decode(&hex_value).unwrap();
  hex_value_in_bytes.reverse();
  hex::encode(hex_value_in_bytes)
}

/// This helper will transform a hex string length into bytes,
/// removing empty bytes.
pub fn get_even_hex_length_bytes(hex_string: String) -> Vec<u8> {
  let mut even_script_sig = hex_string.clone();
  if hex_string.len() % 2 != 0 {
    even_script_sig = format!("0{}", hex_string);
  }

  let script_size = hex::decode(&even_script_sig).unwrap().len();
  let mut script_size_bytes_no_empty_zeroes: Vec<u8> = Vec::new();
  for elem in script_size.to_be_bytes() {
    if elem == 0 {
      continue;
    }
    script_size_bytes_no_empty_zeroes.push(elem);
  }

  script_size_bytes_no_empty_zeroes
}

pub enum TransactionType {
  Vin,
  Vout,
}

pub fn get_length_of_script_vin_or_vout(
  serialized: String,
  transaction_type: TransactionType,
) -> usize {
  let initial_values_length = match transaction_type {
    TransactionType::Vin => VIN_TRANSACTION_HASH_LENGTH_HEX + VIN_VOUT_LENGTH_IN_HEX,
    TransactionType::Vout => VOUT_AMOUNT_LENGTH_IN_HEX,
  };

  let rest_of_string_length = serialized[initial_values_length..].len();
  let mut index = 2;

  for length_of_script in (2..rest_of_string_length).step_by(2) {
    let current_script_len =
      serialized[initial_values_length..(initial_values_length + length_of_script)].to_owned();
    let length_decimal = i64::from_str_radix(&current_script_len, 16).unwrap();
    let length_of_soon_to_be_script =
      serialized[(initial_values_length + length_of_script)..].len() as i64;

    if length_decimal == (length_of_soon_to_be_script / 2)
      || length_decimal == ((length_of_soon_to_be_script + 1) / 2)
    {
      index = length_of_script;
      break;
    }
  }

  index
}
