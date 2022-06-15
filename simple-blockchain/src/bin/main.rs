use btc::helpers;
use btc::wallet;
use btc::{BlockHeader, Transaction};
use btc::bech32::{Bech32, MAIN_NET_BTC, EncodingType};
use chrono::prelude::*;
use sha256::digest;
use std::time::Instant;

fn _genesis_block() {
  let merkle_root = "bc15f9dcbe637c187bb94247057b14637316613630126fc396c22e08b89006ea".to_owned();
  let previous_block_hash = vec!["0"; 64].join("");

  let _block_header = BlockHeader {
    version: "1".to_owned(),
    previous_block_hash,
    merkle_root,
    timestamp: 1654455888,
    bits: 486_604_799,
    nonce: 750_730_123,
  };
}

fn _chrono_date() {
  let dt: NaiveDateTime = NaiveDate::from_ymd(2022, 6, 3).and_hms(14, 13, 00);

  let _utc = DateTime::<Utc>::from_utc(dt, Utc);
  let utc = Utc::now();

  let _timestamp = utc.timestamp() as u32;
}

fn _merkle_root_transactions() {
  let first_transaction = Transaction {
    from: "COINBASE".to_owned(),
    to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
    amount: 50.0,
  };

  let mut transactions = vec![first_transaction];
  let _merkle_root = helpers::get_transactions_merkle_root(&mut transactions);
}

fn test_pow() {
  println!("Mining block...");
  let start = Instant::now();

  let merkle_root = "bc15f9dcbe637c187bb94247057b14637316613630126fc396c22e08b89006ea".to_owned();
  let previous_block_hash = vec!["0"; 64].join("");

  let mut block_header = BlockHeader {
    version: "1".to_owned(),
    previous_block_hash,
    merkle_root,
    timestamp: 1654455888,
    bits: 486_604_799,
    nonce: 0, // 750_730_123
  };

  println!("{:?}\n", block_header);

  helpers::mine_block(&mut block_header);

  let stringfied = serde_json::to_string(&block_header).unwrap();
  let hash = digest(&stringfied);

  let duration = start.elapsed();
  println!("Time elapsed to mine block is: {:?}", duration);

  println!("Block hash: {}", hash);
  println!("Block mined: {:?}", block_header);
}

fn test_target_representation() {
  let genesis_bits = 486_604_799;
  helpers::get_target_representation(genesis_bits);
  let bits_block_739421 = 386_492_960;
  helpers::get_target_representation(bits_block_739421);
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

fn test_generate_bech32m_address() {
  let my_wallet = wallet::Wallet {};
  let (_dec_private_key, sha256_dec_private_key) = my_wallet.generate_private_key();
  let public_key = my_wallet.get_public_key_from_private_key(sha256_dec_private_key);
  my_wallet.generate_bech32m_address_from_public_key(public_key);
}

fn test_encode_bech32m_address() {
  let hash160_public_key = String::from("2b002b9cfbddaa36ce8458b3d11c9478efd7980f");
  let hash160_as_vec_u8 = hex::decode(&hash160_public_key).unwrap();
  let hash160_as_base32 = helpers::convert_bits(8, 5, hash160_as_vec_u8);

  // witness version
  let mut witness_version_plus_hash160 = vec![1u8];
  witness_version_plus_hash160.extend_from_slice(&hash160_as_base32);

  let bech32 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160);
  let encoded = bech32.encode(EncodingType::BECH32M);
  println!("{:?}", encoded);
}

fn test_decode_bech32m_address(){
  let bech32m_address = String::from("bc1p9vqzh88mmk4rdn5ytzeaz8y50rha0xq0tzetq3"); // bech32m
  // let bech32m_address = String::from("bc1p9vqzh88mmk4rdn5ytzeaz8y50rha0xq0tzetq3"); // bech32m
  // let bech32m_address = String::from("bc1q9vqzh88mmk4rdn5ytzeaz8y50rha0xq04q7vgc"); // bech32
  let bech32m = Bech32::empty();
  let decoded = bech32m.decode(bech32m_address);
  println!("{:?}", decoded);
}

fn main() {
  let my_wallet = wallet::Wallet {};
  
  // private key
  // let (dec_priv_key, sha256_priv_key) = my_wallet.generate_private_key();
  let dec_priv_key: u128 = 226296091940012619244294630313588417160;

  // let dec_priv_key_as_bits = format!("{:b}", dec_priv_key);
  // let sha256_priv_key_as_bytes = hex::decode(&sha256_priv_key).unwrap();
  
  // let sha256_priv_key_as_bits: String = sha256_priv_key_as_bytes.iter().map(|v| format!("{:b}", v)).collect();

  // println!("{}", &dec_priv_key_as_bits[..4]);
  // println!("{}", &sha256_priv_key_as_bits[..4]);
  
  // my_wallet.generate_mnemonic_from_entropy(dec_priv_key.to_be_bytes().to_vec());
  // my_wallet.generate_mnemonic_from_entropy([0x33, 0xE4, 0x6B, 0xB1, 0x3A, 0x74, 0x6E, 0xA4, 0x1C, 0xDD, 0xE4, 0x5C, 0x90, 0x84, 0x6A, 0x79].to_vec());
  let mnemonic = my_wallet.generate_mnemonic_from_entropy([0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0x97, 0xE1, 0x4D, 0x45, 0xF1, 0x4E, 0x1A, 0x1A].to_vec());

  // get seed from mnemonic
  my_wallet.get_seed_from_mnemonic(mnemonic, None);
}
