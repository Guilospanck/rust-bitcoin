use btc::bech32::{Bech32Decoded, Payload};
use btc::wallet;

#[test]
fn test_wallet_should_generate_private_key() {
  let my_wallet = wallet::Wallet::new();

  let pvd_key_generated = my_wallet.generate_private_key();

  assert!(pvd_key_generated.is_ok());
}

#[test]
fn test_wallet_should_get_public_key_from_private_key() {
  let k = "e1b4519c66558ec215c55392290afc35f249e113c803bfcadf3b066b4f87d2f3".to_owned();
  let my_wallet = wallet::Wallet::new();

  let public_key = my_wallet.get_public_key_from_private_key(hex::decode(&k).unwrap());

  assert_eq!(
    hex::encode(public_key),
    "0313e8842189afb5316c3c1acfcca696a85ec3741d17767f953bc70394b3839365".to_owned()
  );
}

#[test]
#[should_panic(expected = "32 bytes, within curve order")]
fn test_wallet_should_panic_when_pvd_key_is_outside_curve_order() {
  let k = "e1b4519c66558ec215c55392290afc35f249e113c803bfcadf3b066b4f87d2f3e1b4519c66558ec215c55392290afc35f249e113c803bfcadf3b066b4f87d2f3".to_owned();
  let my_wallet = wallet::Wallet::new();

  my_wallet.get_public_key_from_private_key(hex::decode(&k).unwrap());
}

#[test]
fn test_wallet_should_generate_bech32m_address_from_public_key() {
  let public_key = "0313e8842189afb5316c3c1acfcca696a85ec3741d17767f953bc70394b3839365".to_owned();
  let bech32_address = "bc1phq8vedlv7w3cetla7l3f3xcd8xuw0cvevn0lpw".to_owned();
  let my_wallet = wallet::Wallet::new();

  let result = my_wallet.generate_bech32m_address_from_public_key(public_key);

  assert!(result.is_ok());
  assert_eq!(result.unwrap(), bech32_address);
}

#[test]
fn test_wallet_should_get_info_from_bech32m_address() {
  let bech32_address = "bc1phq8vedlv7w3cetla7l3f3xcd8xuw0cvevn0lpw".to_owned();
  let expected = Bech32Decoded {
    hrp: "bc".to_owned(),
    payload: Payload {
      witness_version: "1".to_owned(),
      program: "b80eccb7ecf3a38caffdf7e2989b0d39b8e7e199".to_owned(),
      checksum: "vn0lpw".to_owned(),
    },
  };
  let my_wallet = wallet::Wallet::new();

  let result = my_wallet.get_info_from_bech32m_address(bech32_address);

  assert!(result.is_ok());
  assert_eq!(result.unwrap(), expected);
}

#[test]
fn test_wallet_should_return_bech32_error_for_invalid_bech_address() {
  let bech32_address = "bcAphq8vedlv7w3cetla7l3f3xcd8xuw0cvevn0lpw".to_owned();
  let my_wallet = wallet::Wallet::new();

  let result = my_wallet.get_info_from_bech32m_address(bech32_address);

  assert!(result.is_err());
}

#[test]
fn test_wallet_should_get_mnemonic_from_entropy() {
  let entropy = [
    0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0x97, 0xE1, 0x4D, 0x45, 0xF1, 0x4E, 0x1A, 0x1A,
  ]
  .to_vec();
  let my_wallet = wallet::Wallet::new();

  let mnemonic = my_wallet.get_mnemonic_from_entropy(entropy);

  assert_eq!(
    mnemonic.unwrap(),
    [
      "army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media",
      "make", "crunch"
    ]
  );
}

#[test]
fn test_wallet_should_return_error_when_entropy_is_incorrect() {
  let entropy = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x77, 0x79, 0xD2, 0x97, 0xE1, 0x4D, 0x45, 0xFF, 0x4E, 0x1A, 0x1A,
    0xFF,
  ]
  .to_vec();
  let my_wallet = wallet::Wallet::new();

  let mnemonic = my_wallet.get_mnemonic_from_entropy(entropy);

  assert!(mnemonic.is_err());
}

#[test]
fn test_wallet_should_get_seed_from_mnemonic() {
  let mnemonic: Vec<_> = vec![
    "army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media",
    "make", "crunch",
  ]
  .into_iter()
  .map(String::from)
  .collect();
  let my_wallet = wallet::Wallet::new();

  let seed = my_wallet.seed_from_mnemonic(mnemonic, None);

  assert_eq!(
    seed,
    "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570".to_owned()
  );
}

#[test]
fn test_wallet_should_create_master_keys_from_seed() {
  let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".to_owned();
  let mut my_wallet = wallet::Wallet::new();

  let result = my_wallet.create_master_keys_from_seed(hex::decode(&seed).unwrap());

  assert!(result.is_ok());
  assert_eq!(
    my_wallet.master_keys,
    wallet::MasterKeys {
      private_key: "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e".to_owned(),
      public_key: "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7".to_owned(),
      chain_code: "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689".to_owned()
    }
  );
}

#[test]
fn test_wallet_should_get_keys_from_derivation_path_m() {
  let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".to_owned();
  let mut my_wallet = wallet::Wallet::new();
  my_wallet
    .create_master_keys_from_seed(hex::decode(&seed).unwrap())
    .unwrap();
  let expected_priv_key =
    hex::decode("759e246be4066c91c468ed3aee22d0116cac5b4c7e15eb050e2c937cd6723125").unwrap();
  let expected_pub_key =
    hex::decode("02171456b4edec20748bfb8187d9fcef456c089ec46a032bcde6823ad772eb19a5").unwrap();
  let expected_chain_code =
    hex::decode("1d0169359714f3e802804ccb787ae50c519ca7d2f5e29d1d58cef7abdc6b5470").unwrap();

  let result = my_wallet.get_keys_from_derivation_path("m/84'/0'/0'/0/0");

  assert!(result.is_ok());
  assert_eq!(my_wallet.current_private_key, expected_priv_key);
  assert_eq!(my_wallet.current_public_key, expected_pub_key);
  assert_eq!(my_wallet.current_chain_code, expected_chain_code);
}

#[test]
fn test_wallet_should_get_keys_from_derivation_path_uppercase_m() {
  let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".to_owned();
  let mut my_wallet = wallet::Wallet::new();
  my_wallet
    .create_master_keys_from_seed(hex::decode(&seed).unwrap())
    .unwrap();
  let expected_pub_key =
    hex::decode("03848fe3a93ebe80895aefe00d61b31fdd74492bc58ae275e3b31148a48676c5e6").unwrap();
  let expected_chain_code =
    hex::decode("4961cdb27d4b93b5838002038a299f3894e31e64e88b8dca12262602456fd31a").unwrap();

  let result = my_wallet.get_keys_from_derivation_path("M/84/0/0/0/0");

  assert!(result.is_ok());
  assert_eq!(my_wallet.current_public_key, expected_pub_key);
  assert_eq!(my_wallet.current_chain_code, expected_chain_code);
}

#[test]
fn test_wallet_should_return_error_if_path_doesnt_start_with_either_lowercase_m_or_uppercase_m() {
  let mut my_wallet = wallet::Wallet::new();

  let result = my_wallet.get_keys_from_derivation_path("B/84'/0'/0'/0/0");

  assert!(result.is_err());
  assert_eq!(
    result,
    Err(wallet::WalletError::DerivationPathMustBeginWithEithermOrM)
  )
}

#[test]
fn test_wallet_should_return_error_if_path_is_not_correct() {
  let mut my_wallet = wallet::Wallet::new();

  let result = my_wallet.get_keys_from_derivation_path("m/\\/\\84'/0'/0'/0/0");

  assert!(result.is_err());
}
