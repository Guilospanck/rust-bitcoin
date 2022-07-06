use btc::helpers;
use btc::Transaction;

#[test]
fn test_helpers_get_target_representation() {
  let genesis_difficulty = 486_604_799;
  let expected = "00000000ffff0000000000000000000000000000000000000000000000000000".to_owned();

  let result = helpers::get_target_representation(genesis_difficulty);

  assert_eq!(result, expected);
}

#[test]
fn test_helpers_get_transactions_merkle_root() {
  let first_transaction = Transaction {
    from: "COINBASE".to_owned(),
    to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
    amount: 50.0,
  };
  let mut transactions = vec![first_transaction; 5];
  let expected = "dab0bcbdb46f816630e838a4588c07b313f6ee21f501ca4f497718e63ead6855".to_owned();

  let result = helpers::get_transactions_merkle_root(&mut transactions);

  assert_eq!(result, expected);
}

#[test]
fn test_helpers_() {
  let transactions_vector = vec![
    "3f67591ba6874eb78a4a494fe4f1bc1428bd7904ed22057204308b48b2a1e38b",
    "3f67591ba6874eb78a4a494fe4f1bc1428bd7904ed22057204308b48b2a1e38b",
    "3f67591ba6874eb78a4a494fe4f1bc1428bd7904ed22057204308b48b2a1e38b",
    "3f67591ba6874eb78a4a494fe4f1bc1428bd7904ed22057204308b48b2a1e38b",
    "3f67591ba6874eb78a4a494fe4f1bc1428bd7904ed22057204308b48b2a1e38b",
  ]
  .into_iter()
  .map(String::from)
  .collect();

  let expected = "dab0bcbdb46f816630e838a4588c07b313f6ee21f501ca4f497718e63ead6855".to_owned();

  let result = helpers::build_merkle_root(transactions_vector);

  assert_eq!(result, expected);
}

#[test]
fn test_helpers_hmac_sha512_hasher() {
  let key = vec![66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100];
  let data = vec![
    255, 252, 249, 246, 243, 240, 237, 234, 231, 228, 225, 222, 219, 216, 213, 210, 207, 204, 201,
    198, 195, 192, 189, 186, 183, 180, 177, 174, 171, 168, 165, 162, 159, 156, 153, 150, 147, 144,
    141, 138, 135, 132, 129, 126, 123, 120, 117, 114, 111, 108, 105, 102, 99, 96, 93, 90, 87, 84,
    81, 78, 75, 72, 69, 66,
  ];
  let expected = "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689".to_owned();

  let result = helpers::hmac_sha512_hasher(key, data);

  assert_eq!(result, expected);
}

#[test]
fn test_helpers_ripemd160_hasher() {
  let data = hex::encode("potato");
  let expected = "73320299f79b130c89172044d653a932d456cb96".to_owned();

  let result = helpers::ripemd160_hasher(data);

  assert_eq!(result, expected);
}

#[test]
#[should_panic(expected = "InvalidHexCharacter { c: 'p', index: 0 }")]
fn test_helpers_should_return_err_invalid_hex_character() {
  let data = "potato".to_owned();
  let expected = "73320299f79b130c89172044d653a932d456cb96".to_owned();

  let result = helpers::ripemd160_hasher(data);

  assert_eq!(result, expected);
}

#[test]
fn test_helpers_get_hash160() {
  let data = hex::encode("potato");
  let expected = "6f07d42c1f3a221c69718f8da628425dbf0b84e4".to_owned();

  let result = helpers::get_hash160(data);

  assert_eq!(result, expected);
}

#[test]
fn test_helpers_convert_bits() {
  let data = vec![10, 10, 10];
  let expected = vec![1, 8, 5, 0, 20];

  let result = helpers::convert_bits(8, 5, data);

  assert_eq!(result, expected);
}

#[test]
fn test_helpers_get_pbkdf2_sha512() {
  use unicode_normalization::UnicodeNormalization;
  const MNEMONIC_STRING: &str = "mnemonic";
  let mnemonic: Vec<String> = vec![
    "army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media",
    "make", "crunch",
  ]
  .into_iter()
  .map(String::from)
  .collect();
  let normalized_mnemonic: Vec<String> = mnemonic.iter().map(|w| w.nfkd().to_string()).collect();
  let stringfied_mnemonic: String = normalized_mnemonic.join(" ");
  let salt = format!("{}", MNEMONIC_STRING.to_owned());
  let normalized_salt = salt.nfkd().to_string();

  let seed = helpers::get_pbkdf2_sha512(stringfied_mnemonic, normalized_salt);

  assert_eq!(seed, "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570".to_owned());
}

#[test]
fn test_helpers_read_from_a_file_to_a_vec_string() {
  let file = "./tests/test_file.txt".to_owned();

  let wordlist = helpers::read_from_a_file_to_a_vec_string(file);

  assert!(wordlist.is_ok());
}

#[test]
#[should_panic(expected = "Os { code: 2, kind: NotFound, message: \"No such file or directory\" }")]
fn test_helpers_should_return_error_file_not_found() {
  let file = "./tests/notfound.txt".to_owned();

  helpers::read_from_a_file_to_a_vec_string(file).unwrap();
}
