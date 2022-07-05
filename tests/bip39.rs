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
    0xFF, 0xFF
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