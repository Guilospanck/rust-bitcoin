use btc::helpers;
use btc::base58check;
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
  let my_wallet = wallet::Wallet::new();
  let (_dec_private_key, sha256_dec_private_key) = my_wallet.generate_private_key();
  let private_key_bytes = hex::decode(&sha256_dec_private_key).unwrap();

  let public_key = my_wallet.get_public_key_from_private_key(private_key_bytes);
  my_wallet.generate_bech32m_address_from_public_key(hex::encode(public_key));
}

fn test_encode_bech32m_address(hash160_public_key: String, witness_version: u8, encoding_type: EncodingType) {
  let hash160_as_vec_u8 = hex::decode(&hash160_public_key).unwrap();
  let hash160_as_base32 = helpers::convert_bits(8, 5, hash160_as_vec_u8);

  // witness version
  let mut witness_version_plus_hash160 = vec![witness_version];
  witness_version_plus_hash160.extend_from_slice(&hash160_as_base32);

  let bech32 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160);
  let encoded = bech32.encode(encoding_type);
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
  let mut my_wallet = wallet::Wallet::new();

  // Bip 84 test vector
  let mnemonic: Vec<String> = ["abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "abandon".to_owned(), "about".to_owned()].to_vec();
  let seed = my_wallet.seed_from_mnemonic(mnemonic, None);

  // BIP 32 test vector 1
  // let seed = "000102030405060708090a0b0c0d0e0f".to_owned();

  // BIP 32 test vector 2
  // let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".to_owned();

  // println!("\nSeed: {}", seed);

  println!();
  println!("Chain m:");

  my_wallet.create_master_keys_from_seed(hex::decode(&seed).unwrap());
  
  my_wallet.get_keys_from_derivation_path("m/84'/0'/0'/0/0");
  // my_wallet.get_keys_from_derivation_path("M/84/0/0/0/0");

  // Bip 84 test vector
  // let master_private_key = "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67".to_owned();
  // let master_public_key = "03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494".to_owned();
  // let master_chain_code = "7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e".to_owned();

  // BIP 32 test vector 1
  // let master_private_key = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35".to_owned();
  // let master_public_key = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2".to_owned();
  // let master_chain_code = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508".to_owned();

  // BIP 32 test vector 2
  let master_private_key = "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e".to_owned();
  let master_public_key = "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7".to_owned();
  let master_chain_code = "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689".to_owned();

  let master_private_key_bytes = hex::decode(&master_private_key).unwrap();
  let master_public_key_bytes = hex::decode(&master_public_key).unwrap();
  let master_chain_code_bytes = hex::decode(&master_chain_code).unwrap();
  
  // =========== private parent key -> private child key derivation =================
  println!();

  // println!("Chain m/84':");
  // my_wallet.ckd_private_parent_to_private_child_key(master_private_key_bytes, master_chain_code_bytes, 2_147_483_732);

  // println!("Chain m/0:");
  // my_wallet.ckd_private_parent_to_private_child_key(master_private_key_bytes, master_chain_code_bytes.clone(), 0);

  // println!("Chain m/0':");
  // my_wallet.ckd_private_parent_to_private_child_key(master_private_key_bytes, master_chain_code_bytes.clone(), 2_147_483_648); // 2^31

  
  // =========== public parent key -> public child key derivation =================
  println!();

  // error because K -> K not defined for hardened keys
  // println!("Chain M/0':");
  // my_wallet.ckd_public_parent_to_public_child_key(master_public_key_bytes, master_chain_code_bytes, 2_147_483_648); // 2^31

  // println!("Chain M/0:");
  // my_wallet.ckd_public_parent_to_public_child_key(master_public_key_bytes, master_chain_code_bytes, 0);


  // ========================= Test address ===================================
  // test_encode_bech32m_address(
  //   helpers::get_hash160("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c".to_owned()),
  //   0u8,
  //   EncodingType::BECH32
  // );

  // ================================= Test Base58Check ========================
  let child_pvd_key = "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3".to_owned();
  let base58_check = base58check::Base58Check{};
  base58_check.encode_private_key(child_pvd_key);
}
