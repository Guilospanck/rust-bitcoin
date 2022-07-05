use btc::bip39;

#[test]
fn test_bip39_should_generate_mnemonic_from_entropy_correctly() {
  let entropy = [
    0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0x97, 0xE1, 0x4D, 0x45, 0xF1, 0x4E, 0x1A, 0x1A,
  ];

  let mnemonic = match bip39::generate_mnemonic_from_entropy(entropy.to_vec()) {
    Ok(data) => data,
    Err(err) => panic!("{}", err),
  };

  assert_eq!(
    mnemonic,
    [
      "army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media",
      "make", "crunch"
    ]
    .to_vec()
  );
}

/// Should return error Bip39Error::EntropyOutOfBonds when
/// entropy length is not between 128 and 256 bits.
#[test]
fn test_bip39_should_return_error_entropy_out_of_bonds() {
  let entropy = [
    0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF,
  ];

  let result = bip39::generate_mnemonic_from_entropy(entropy.to_vec());

  assert_eq!(result, Err(bip39::Bip39Error::EntropyOutOfBonds));
}

/// Should return error Bip39Error::EntropyMustBe32Multiple when
/// entropy length is not 32 multiple.
#[test]
fn test_bip39_should_return_error_entropy_must_be_32_multiple() {
  let entropy = [
    0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
  ];

  let result = bip39::generate_mnemonic_from_entropy(entropy.to_vec());

  assert_eq!(result, Err(bip39::Bip39Error::EntropyMustBe32Multiple));
}

#[test]
fn test_bip39_should_get_seed_from_mnemonic_correctly() {  
  let mnemonic: Vec<_> = vec![
    "army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media",
    "make", "crunch",
  ]
  .into_iter()
  .map(String::from)
  .collect();

  let result = bip39::get_seed_from_mnemonic(mnemonic, None);

  assert_eq!(result, "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570".to_owned());
}
