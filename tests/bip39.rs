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
