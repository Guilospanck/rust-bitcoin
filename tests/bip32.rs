use btc::bip32;

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
  let master_private_key = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35".to_owned();
  let master_public_key = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2".to_owned();
  let master_chain_code = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508".to_owned();

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
    _ => get_index0()
  }
}

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

#[test]
fn test_bip32_should_derive_child_pub_key_from_parent_pub_key_big_m_0() {
  let sut0 = make_sut(0);
  let sut1 = make_sut(1);

  let child_keys0 = bip32::ckd_public_parent_to_public_child_key(
    sut0.public_key,
    sut0.chain_code,
    0,
    1,
  );
  //
  let child_keys1 = bip32::ckd_public_parent_to_public_child_key(
    sut1.public_key,
    sut1.chain_code,
    0,
    1,
  );

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