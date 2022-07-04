use btc::bip32;

/** System Under Test - Helpers */
struct Sut {
  private_key: Vec<u8>,
  public_key: Vec<u8>,
  chain_code: Vec<u8>,
}

fn get_index0() -> Sut {
  let master_private_key =
    "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e".to_owned();
  let master_chain_code =
    "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689".to_owned();
  let master_public_key =
    "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7".to_owned();

  let master_private_key_bytes = hex::decode(&master_private_key).unwrap();
  let master_public_key_bytes = hex::decode(&master_public_key).unwrap();
  let master_chain_code_bytes = hex::decode(&master_chain_code).unwrap();

  Sut {
    private_key: master_private_key_bytes,
    public_key: master_public_key_bytes,
    chain_code: master_chain_code_bytes,
  }
}

fn get_index1() -> Sut {
  let master_private_key =
    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35".to_owned();
  let master_public_key =
    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2".to_owned();
  let master_chain_code =
    "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508".to_owned();

  let master_private_key_bytes = hex::decode(&master_private_key).unwrap();
  let master_public_key_bytes = hex::decode(&master_public_key).unwrap();
  let master_chain_code_bytes = hex::decode(&master_chain_code).unwrap();

  Sut {
    private_key: master_private_key_bytes,
    public_key: master_public_key_bytes,
    chain_code: master_chain_code_bytes,
  }
}

fn make_sut(index: u8) -> Sut {
  match index {
    0 => get_index0(),
    1 => get_index1(),
    _ => get_index0(),
  }
}

/** Extended Private Keys: zprv */
#[test]
fn test_bip32_should_encode_pvd_key_correctly() {
  let zprv = bip32::ExtendedPrivateKey {
    chain_code: [
      240, 144, 154, 255, 170, 126, 231, 171, 229, 221, 78, 16, 5, 152, 212, 220, 83, 205, 112,
      157, 90, 92, 44, 172, 64, 231, 65, 47, 35, 47, 124, 156,
    ]
    .to_vec(),
    key: [
      171, 231, 74, 152, 246, 199, 234, 190, 224, 66, 143, 83, 121, 143, 10, 184, 170, 27, 211,
      120, 115, 153, 144, 65, 112, 60, 116, 47, 21, 172, 126, 30,
    ]
    .to_vec(),
    depth: 1,
    parent_key_fingerprint: [189, 22, 190, 229].to_vec(),
    child_number: 0,
  };

  let expected = "04b2430c01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e".to_owned();

  let result = zprv.encode();

  assert_eq!(hex::encode(result), expected)
}

#[test]
fn test_bip32_should_decode_pvd_key_correctly() {
  let zprv_encoded = [
    4, 178, 67, 12, 1, 189, 22, 190, 229, 0, 0, 0, 0, 240, 144, 154, 255, 170, 126, 231, 171, 229,
    221, 78, 16, 5, 152, 212, 220, 83, 205, 112, 157, 90, 92, 44, 172, 64, 231, 65, 47, 35, 47,
    124, 156, 0, 171, 231, 74, 152, 246, 199, 234, 190, 224, 66, 143, 83, 121, 143, 10, 184, 170,
    27, 211, 120, 115, 153, 144, 65, 112, 60, 116, 47, 21, 172, 126, 30,
  ];

  let expected_decoded_zprv = bip32::ExtendedPrivateKey {
    chain_code: [
      240, 144, 154, 255, 170, 126, 231, 171, 229, 221, 78, 16, 5, 152, 212, 220, 83, 205, 112,
      157, 90, 92, 44, 172, 64, 231, 65, 47, 35, 47, 124, 156,
    ]
    .to_vec(),
    key: [
      171, 231, 74, 152, 246, 199, 234, 190, 224, 66, 143, 83, 121, 143, 10, 184, 170, 27, 211,
      120, 115, 153, 144, 65, 112, 60, 116, 47, 21, 172, 126, 30,
    ]
    .to_vec(),
    depth: 1,
    parent_key_fingerprint: [189, 22, 190, 229].to_vec(),
    child_number: 0,
  };

  let zprv = bip32::ExtendedPrivateKey {
    ..Default::default()
  };

  let result = zprv.decode(zprv_encoded);

  assert_eq!(result, expected_decoded_zprv)
}

/** Extended Public Keys: zpub */
#[test]
fn test_bip32_should_encode_pub_key_correctly() {
  let zpub = bip32::ExtendedPublicKey {
    chain_code: [
      96, 73, 159, 128, 27, 137, 109, 131, 23, 154, 67, 116, 174, 183, 130, 42, 174, 172, 234, 160,
      219, 31, 133, 238, 62, 144, 76, 77, 239, 189, 150, 137,
    ]
    .to_vec(),
    key: [
      2, 252, 158, 90, 240, 172, 141, 155, 60, 236, 254, 42, 136, 142, 33, 23, 186, 61, 8, 157,
      133, 133, 136, 108, 156, 130, 107, 107, 34, 169, 141, 18, 234,
    ]
    .to_vec(),
    depth: 1,
    parent_key_fingerprint: [189, 22, 190, 229].to_vec(),
    child_number: 0,
  };

  let expected = "04b2474601bd16bee50000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968902fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea".to_owned();

  let result = zpub.encode();

  assert_eq!(hex::encode(result), expected)
}

#[test]
fn test_bip32_should_decode_pub_key_correctly() {
  let zpub_encoded = [
    4, 178, 71, 70, 1, 189, 22, 190, 229, 0, 0, 0, 0, 96, 73, 159, 128, 27, 137, 109, 131, 23, 154,
    67, 116, 174, 183, 130, 42, 174, 172, 234, 160, 219, 31, 133, 238, 62, 144, 76, 77, 239, 189,
    150, 137, 2, 252, 158, 90, 240, 172, 141, 155, 60, 236, 254, 42, 136, 142, 33, 23, 186, 61, 8,
    157, 133, 133, 136, 108, 156, 130, 107, 107, 34, 169, 141, 18, 234,
  ];

  let expected_zpub_decoded = bip32::ExtendedPublicKey {
    chain_code: [
      96, 73, 159, 128, 27, 137, 109, 131, 23, 154, 67, 116, 174, 183, 130, 42, 174, 172, 234, 160,
      219, 31, 133, 238, 62, 144, 76, 77, 239, 189, 150, 137,
    ]
    .to_vec(),
    key: [
      2, 252, 158, 90, 240, 172, 141, 155, 60, 236, 254, 42, 136, 142, 33, 23, 186, 61, 8, 157,
      133, 133, 136, 108, 156, 130, 107, 107, 34, 169, 141, 18, 234,
    ]
    .to_vec(),
    depth: 1,
    parent_key_fingerprint: [189, 22, 190, 229].to_vec(),
    child_number: 0,
  };

  let zpub = bip32::ExtendedPublicKey {
    ..Default::default()
  };

  let result = zpub.decode(zpub_encoded);

  assert_eq!(result, expected_zpub_decoded)
}

/** Child Key Derivation k -> k */
#[test]
fn test_bip32_should_derive_child_pvd_key_from_parent_pvd_key_m0() {
  let sut0 = make_sut(0);
  let sut1 = make_sut(1);

  let child_keys0 = bip32::ckd_private_parent_to_private_child_key(
    sut0.private_key,
    sut0.public_key,
    sut0.chain_code,
    0,
    1,
  );
  //
  let child_keys1 = bip32::ckd_private_parent_to_private_child_key(
    sut1.private_key,
    sut1.public_key,
    sut1.chain_code,
    0,
    1,
  );

  println!("{:?}", child_keys0.as_ref().unwrap().zprv);

  assert_eq!(
    child_keys0.as_ref().unwrap().child_private_key,
    hex::decode("abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e").unwrap()
  );
  assert_eq!(
    child_keys0.as_ref().unwrap().child_chain_code,
    hex::decode("f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c").unwrap()
  );
  assert_eq!(hex::encode(child_keys0.as_ref().unwrap().zprv.encode()), "04b2430c01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e");
  //
  assert_eq!(
    child_keys1.as_ref().unwrap().child_private_key,
    hex::decode("4e2cdcf2f14e802810e878cf9e6411fc4e712edf19a06bcfcc5d5572e489a3b7").unwrap()
  );
  assert_eq!(
    child_keys1.as_ref().unwrap().child_chain_code,
    hex::decode("d323f1be5af39a2d2f08f5e8f664633849653dbe329802e9847cfc85f8d7b52a").unwrap()
  );
  assert_eq!(hex::encode(child_keys1.as_ref().unwrap().zprv.encode()), "04b2430c013442193e00000000d323f1be5af39a2d2f08f5e8f664633849653dbe329802e9847cfc85f8d7b52a004e2cdcf2f14e802810e878cf9e6411fc4e712edf19a06bcfcc5d5572e489a3b7");
}

/** Child Key Derivation K -> K */
#[test]
fn test_bip32_should_derive_child_pub_key_from_parent_pub_key_big_m_0() {
  let sut0 = make_sut(0);
  let sut1 = make_sut(1);

  let child_keys0 =
    bip32::ckd_public_parent_to_public_child_key(sut0.public_key, sut0.chain_code, 0, 1);
  //
  let child_keys1 =
    bip32::ckd_public_parent_to_public_child_key(sut1.public_key, sut1.chain_code, 0, 1);

  assert_eq!(
    child_keys0.as_ref().unwrap().child_public_key,
    hex::decode("02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea").unwrap()
  );
  assert_eq!(
    child_keys0.as_ref().unwrap().child_chain_code,
    hex::decode("f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c").unwrap()
  );
  assert_eq!(hex::encode(child_keys0.as_ref().unwrap().zpub.encode()), "04b2474601bd16bee50000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968902fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea");
  //
  assert_eq!(
    child_keys1.as_ref().unwrap().child_public_key,
    hex::decode("027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c").unwrap()
  );
  assert_eq!(
    child_keys1.as_ref().unwrap().child_chain_code,
    hex::decode("d323f1be5af39a2d2f08f5e8f664633849653dbe329802e9847cfc85f8d7b52a").unwrap()
  );
  assert_eq!(hex::encode(child_keys1.as_ref().unwrap().zpub.encode()), "04b24746013442193e00000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c");
}

#[test]
/** Get normal or hardened keys */
fn test_bip32_should_get_normal_or_hardened_index_correctly() {
  let hardened_index = bip32::get_normal_or_hardened_index("84'"); // hardened
  let non_hardened_index = bip32::get_normal_or_hardened_index("84"); // non-hardened
  assert_eq!(hardened_index.unwrap(), 2_147_483_732u32); // 2^31 + 84
  assert_eq!(non_hardened_index.unwrap(), 84u32);
}