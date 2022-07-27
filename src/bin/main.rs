use btc::bech32::{Bech32, EncodingType, MAIN_NET_BTC};
use btc::helpers;
use btc::transaction;
use btc::wallet;
use btc::BlockHeader;
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

// fn _merkle_root_transactions() {
//   let first_transaction = Transaction {
//     from: "COINBASE".to_owned(),
//     to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
//     amount: 50.0,
//   };

//   let mut transactions = vec![first_transaction];
//   let _merkle_root = helpers::get_transactions_merkle_root(&mut transactions);
// }

fn _pow() {
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

fn _target_representation() {
  let genesis_bits = 486_604_799;
  helpers::get_target_representation(genesis_bits);
  let bits_block_739421 = 386_492_960;
  helpers::get_target_representation(bits_block_739421);
  let bits_block_730000 = 386_521_239;
  helpers::get_target_representation(bits_block_730000);
  let bits_block_277_316 = 41_668_748;
  helpers::get_target_representation(bits_block_277_316);
}

fn _merkle_root() {
  let hashed_transactions: Vec<String> = vec![
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87".to_owned(),
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4".to_owned(),
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4".to_owned(),
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d".to_owned(),
  ];

  let merkle_root = helpers::build_merkle_root(hashed_transactions);
  println!("root {}", merkle_root);
}

fn _generate_bech32m_address() {
  let my_wallet = wallet::Wallet::new();
  let private_key_generated = my_wallet.generate_private_key();

  let (_dec_private_key, sha256_dec_private_key) = match private_key_generated {
    Ok(data) => data,
    Err(err) => panic!("{}", err),
  };

  let private_key_bytes = hex::decode(&sha256_dec_private_key).unwrap();

  let public_key = my_wallet.get_public_key_from_private_key(private_key_bytes);
  match my_wallet.generate_bech32m_address_from_public_key(hex::encode(public_key)) {
    Ok(addr) => println!("{}", addr),
    Err(err) => eprintln!("{}", err),
  };
}

fn _test_encode_bech32m_address(
  hash160_public_key: String,
  witness_version: u8,
  encoding_type: EncodingType,
) {
  let hash160_as_vec_u8 = hex::decode(&hash160_public_key).unwrap();
  let hash160_as_base32 = helpers::convert_bits(8, 5, hash160_as_vec_u8);

  println!("{}", hash160_public_key);

  // witness version
  let mut witness_version_plus_hash160 = vec![witness_version];
  witness_version_plus_hash160.extend_from_slice(&hash160_as_base32);

  println!("{:?}", witness_version_plus_hash160);

  let bech32 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160);
  let encoded = bech32.encode(encoding_type);
  println!("{:?}", encoded);
}

fn _test_decode_bech32m_address() {
  let bech32m_address = String::from("bc1phq8vedlv7w3cetla7l3f3xcd8xuw0cvevn0lpw"); // bech32m
                                                                                    // let bech32m_address = String::from("bc1qw0za5zsr6tggqwmnruzzg2a5pnkjlzaus8upyg"); // bech32
                                                                                    // let bech32m_address = String::from("bc1p9vqzh88mmk4rdn5ytzeaz8y50rha0xq0tzetq3"); // bech32m
                                                                                    // let bech32m_address = String::from("bc1q9vqzh88mmk4rdn5ytzeaz8y50rha0xq04q7vgc"); // bech32
  let bech32m = Bech32::empty();
  let decoded = bech32m.decode(bech32m_address);
  println!("{:?}", decoded);
}

fn main() {
  let mut vin = transaction::Vin::new();
  vin.txid = "7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18".to_owned();
  vin.vout = 0;
  vin.script_sig = "483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf".to_owned();
  vin.sequence = 4294967295;

  let serialized = vin.serialize();
  println!("Vin serialized: {}\n", serialized);

  let vin = transaction::Vin::new();
  let deserialized = vin.deserialize(serialized);
  println!("{:?}\n", deserialized);

  let mut vout = transaction::Vout::new();
  vout.value = 1_500_000; // in satoshis
  vout.script_pub_key = "76a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac".to_owned();

  let serialized = vout.serialize();
  println!("Vout serialized: {}\n", serialized);

  let vout = transaction::Vout::new();
  let deserialized = vout.deserialize(serialized);
  println!("{:?}", deserialized);
}
