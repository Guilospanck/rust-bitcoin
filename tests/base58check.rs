use btc::base58check;

#[test]
fn test_base58check_should_encode_private_key_wif_compressed() {
  let base58_check = base58check::Base58Check {};

  let private_key_wif_compressed =
    "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3".to_owned();
  let base58check_private_key_wif_compressed = base58_check.encode_private_key_wif(
    private_key_wif_compressed,
    base58check::PublicKeyType::Compressed,
  );

  assert_eq!(
    base58check_private_key_wif_compressed,
    "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d".to_owned()
  );
}

#[test]
fn test_base58check_should_encode_private_key_wif_uncompressed() {
  let base58_check = base58check::Base58Check {};

  let private_key_wif_compressed =
    "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D".to_owned();
  let base58check_private_key_wif_compressed = base58_check.encode_private_key_wif(
    private_key_wif_compressed,
    base58check::PublicKeyType::Uncompressed,
  );

  assert_eq!(
    base58check_private_key_wif_compressed,
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ".to_owned()
  );
}

#[test]
fn test_base58check_should_encode_extended_key_zprv() {
  let base58_check = base58check::Base58Check {};

  // Extended private key
  let zprv = "04b2430c037ef32bdb800000004a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc00e14f274d16ca0d91031b98b162618061d03930fa381af6d4caf44b01819ab6d4".to_owned();
  let base58check_zprv = base58_check.encode_extended_key(zprv);

  assert_eq!(base58check_zprv, "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE".to_owned());
}

#[test]
fn test_base58check_should_encode_extended_key_zpub() {
  let base58_check = base58check::Base58Check {};

  // Extended public key
  let zpub = "04b24746037ef32bdb800000004a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc02707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b".to_owned();
  let base58check_zpub = base58_check.encode_extended_key(zpub);

  assert_eq!(base58check_zpub, "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs".to_owned());
}

