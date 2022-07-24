use btc::bech32::{Bech32, Bech32Decoded, Bech32Error, EncodingType, Payload, MAIN_NET_BTC};

/** =================================== Bech32 ENCODE ======================================= */
#[test]
fn test_bech32_should_encode_witness_version_0_correctly() {
  // K = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
  let witness_version_plus_hash160_1 = vec![
    0, 24, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6,
    12, 7, 15, 18, 4, 7, 2,
  ];
  // K = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
  let witness_version_plus_hash160_2 = vec![
    0, 6, 17, 1, 1, 18, 15, 16, 27, 22, 28, 4, 17, 13, 26, 8, 20, 10, 20, 16, 23, 5, 19, 10, 14, 5,
    22, 30, 9, 27, 30, 0, 17,
  ];
  // K = "03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494"
  let witness_version_plus_hash160_3 = vec![
    0, 14, 15, 2, 29, 20, 2, 16, 3, 26, 11, 8, 8, 0, 14, 27, 19, 3, 28, 2, 2, 8, 10, 29, 20, 1, 19,
    22, 18, 31, 2, 29, 28,
  ];

  let bech32_1 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_1);
  let bech32_2 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_2);
  let bech32_3 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_3);
  let encoded_1 = bech32_1.encode(EncodingType::BECH32);
  let encoded_2 = bech32_2.encode(EncodingType::BECH32);
  let encoded_3 = bech32_3.encode(EncodingType::BECH32);

  assert_eq!(
    encoded_1,
    Ok("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".to_owned())
  );
  assert_eq!(
    encoded_2,
    Ok("bc1qx3ppj0smkuy3d6g525sh9n2w9k7fm7q3x30rtg".to_owned())
  );
  assert_eq!(
    encoded_3,
    Ok("bc1qw0za5zsr6tggqwmnruzzg2a5pnkjlzaus8upyg".to_owned())
  );
}

#[test]
fn test_bech32_should_encode_witness_version_1_correctly() {
  // K = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
  let witness_version_plus_hash160_1 = vec![
    1, 24, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6,
    12, 7, 15, 18, 4, 7, 2,
  ];
  // K = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
  let witness_version_plus_hash160_2 = vec![
    1, 6, 17, 1, 1, 18, 15, 16, 27, 22, 28, 4, 17, 13, 26, 8, 20, 10, 20, 16, 23, 5, 19, 10, 14, 5,
    22, 30, 9, 27, 30, 0, 17,
  ];
  // K = "03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494"
  let witness_version_plus_hash160_3 = vec![
    1, 14, 15, 2, 29, 20, 2, 16, 3, 26, 11, 8, 8, 0, 14, 27, 19, 3, 28, 2, 2, 8, 10, 29, 20, 1, 19,
    22, 18, 31, 2, 29, 28,
  ];

  let bech32m_1 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_1);
  let bech32m_2 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_2);
  let bech32m_3 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_3);
  let encoded_1 = bech32m_1.encode(EncodingType::BECH32M);
  let encoded_2 = bech32m_2.encode(EncodingType::BECH32M);
  let encoded_3 = bech32m_3.encode(EncodingType::BECH32M);

  assert_eq!(
    encoded_1,
    Ok("bc1pcr8te4kr609gcawutmrza0j4xv80jy8z0dawv4".to_owned())
  );
  assert_eq!(
    encoded_2,
    Ok("bc1px3ppj0smkuy3d6g525sh9n2w9k7fm7q3cngyrp".to_owned())
  );
  assert_eq!(
    encoded_3,
    Ok("bc1pw0za5zsr6tggqwmnruzzg2a5pnkjlzauw9mxvp".to_owned())
  );
}

#[test]
fn test_bech32_should_return_invalidlengtherror_hrp_below_min_length_encode_fn() {
  // K = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
  let witness_version_plus_hash160_1 = vec![
    0, 24, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6,
    12, 7, 15, 18, 4, 7, 2,
  ];
  let hrp_below_min_length = "".to_owned();

  let bech32_1 = Bech32::new(hrp_below_min_length, witness_version_plus_hash160_1);
  let encoded_1 = bech32_1.encode(EncodingType::BECH32);

  assert_eq!(encoded_1, Err(Bech32Error::InvalidLength));
}

#[test]
fn test_bech32_should_return_invalidlengtherror_hrp_above_max_length_encode_fn() {
  // K = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
  let witness_version_plus_hash160_1 = vec![
    0, 24, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6,
    12, 7, 15, 18, 4, 7, 2,
  ];
  let hrp_above_max_length = vec!["0"; 84].join("");

  let bech32_1 = Bech32::new(hrp_above_max_length, witness_version_plus_hash160_1);
  let encoded_1 = bech32_1.encode(EncodingType::BECH32);

  assert_eq!(encoded_1, Err(Bech32Error::InvalidLength));
}

#[test]
fn test_bech32_should_return_invaliddataerror_data_above_32_bits_encode_fn() {
  // byte above 32 bits
  let witness_version_plus_hash160_1 = vec![
    0, 45, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6,
    12, 7, 15, 18, 4, 7, 2,
  ];

  let bech32_1 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_1);
  let encoded_1 = bech32_1.encode(EncodingType::BECH32);

  assert_eq!(encoded_1, Err(Bech32Error::InvalidData));
}

/** =================================== Bech32 DECODE ======================================= */
#[test]
fn test_bech32_decode_bech32_witness_version_0() {
  let bech32_address_1 = String::from("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  let bech32_address_2 = String::from("bc1qx3ppj0smkuy3d6g525sh9n2w9k7fm7q3x30rtg");
  let bech32_address_3 = String::from("bc1qw0za5zsr6tggqwmnruzzg2a5pnkjlzaus8upyg");
  let expected_decoded_1 = Bech32Decoded {
    hrp: "bc".to_owned(),
    payload: Payload {
      witness_version: "0".to_owned(),
      program: "c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2".to_owned(),
      checksum: "306fyu".to_owned(),
    },
  };
  let expected_decoded_2 = Bech32Decoded {
    hrp: "bc".to_owned(),
    payload: Payload {
      witness_version: "0".to_owned(),
      program: "3442193e1bb70916e914552172cd4e2dbc9df811".to_owned(),
      checksum: "x30rtg".to_owned(),
    },
  };
  let expected_decoded_3 = Bech32Decoded {
    hrp: "bc".to_owned(),
    payload: Payload {
      witness_version: "0".to_owned(),
      program: "73c5da0a03d2d0803b731f04242bb40ced2f8bbc".to_owned(),
      checksum: "s8upyg".to_owned(),
    },
  };

  let bech32m_1 = Bech32::empty();
  let bech32m_2 = Bech32::empty();
  let bech32m_3 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);
  let decoded_2 = bech32m_2.decode(bech32_address_2);
  let decoded_3 = bech32m_3.decode(bech32_address_3);

  assert_eq!(decoded_1, Ok(expected_decoded_1));
  assert_eq!(decoded_2, Ok(expected_decoded_2));
  assert_eq!(decoded_3, Ok(expected_decoded_3));
}

#[test]
fn test_bech32_should_return_invalidlengtherror_address_below_min_length_decode_fn() {
  let bech32_address_1 = String::from("bc1qcr8"); // len() < 8

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidLength));
}

#[test]
fn test_bech32_should_return_invalidlengtherror_address_above_max_length_decode_fn() {
  let bech32_address_1 = vec!["a"; 91].join(""); // len() > 90

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidLength));
}

#[test]
fn test_bech32_should_return_missingseparatorerror_no_separator_decode_fn() {
  let bech32_address_1 = String::from("bcqcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"); // no separator (1)

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::MissingSeparator));
}

#[test]
fn test_bech32_should_return_invalidlengtherror_hrp_below_min_length_decode_fn() {
  let bech32_address_1 = String::from("1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"); // hrp below min len of 1

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidLength));
}

#[test]
fn test_bech32_should_return_invalidlengtherror_payload_below_checksum_length_decode_fn() {
  let bech32_address_1 = String::from("bc1qcr8t"); // payload lesser than 6 (checksum length)

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidLength));
}

#[test]
fn test_bech32_should_return_invalidhrperror_hrp_differs_from_btcmainnet_decode_fn() {
  let bech32_address_1 = String::from("b1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"); // hrp differs from "bc"

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidHRP));
}

#[test]
fn test_bech32_should_return_invalidcharerror_payload_not_alphanumeric_decode_fn() {
  let bech32_address_1 = String::from("bc1qcr$te4kr609gcawutmrza0j4xv80jy8z306fyu"); // "$" is not alphanumeric

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidChar));
}

#[test]
fn test_bech32_should_return_invalidcharerror_payload_contain_1bio_decode_fn() {
  // Non allowed payload characters: [1,b,i,o]
  let bech32_address_1 = String::from("bc1qcr8te4kr609gcawu1mrza0j4xv80jy8z306fyu"); // 1
  let bech32_address_2 = String::from("bc1qcr8te4kr609gcawubmrza0j4xv80jy8z306fyu"); // b
  let bech32_address_3 = String::from("bc1qcr8te4kr609gcawuimrza0j4xv80jy8z306fyu"); // i
  let bech32_address_4 = String::from("bc1qcr8te4kr609gcawuomrza0j4xv80jy8z306fyu"); // 0

  let bech32m_1 = Bech32::empty();
  let bech32m_2 = Bech32::empty();
  let bech32m_3 = Bech32::empty();
  let bech32m_4 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);
  let decoded_2 = bech32m_2.decode(bech32_address_2);
  let decoded_3 = bech32m_3.decode(bech32_address_3);
  let decoded_4 = bech32m_4.decode(bech32_address_4);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidChar));
  assert_eq!(decoded_2, Err(Bech32Error::InvalidChar));
  assert_eq!(decoded_3, Err(Bech32Error::InvalidChar));
  assert_eq!(decoded_4, Err(Bech32Error::InvalidChar));
}

#[test]
fn test_bech32_should_return_mixedcasererror_payload_mixed_case_decode_fn() {
  let bech32_address_1 = String::from("bc1qcr8te4kr609gcaWutmrza0j4xv80jy8z306fyu"); // mixed case not allowed

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::MixedCase));
}

#[test]
fn test_bech32_should_return_invalidchecksumrerror_payload_checksum_invalid_decode_fn() {
  let bech32_address_1 = String::from("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fy7"); // wrong checksum

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidChecksum));
}

#[test]
fn test_bech32_should_return_invalidwitnessversionerror_payload_witnessversion_invalid_decode_fn() {
  let bech32_address_1 = String::from("bc1lcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"); // witness version must be between >= 0 and  <= 16  ("l" after bc1 corresponds to 31)

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::InvalidWitnessVersion));
}

#[test]
fn test_bech32_should_return_wrongwitnessversionerror_payload_witnessversion_wrong_decode_fn() {
  let bech32_address_1 =
    String::from("bc1qqvcd2n7sm4pq5mjl35mzfa0nfqk2udg0082lqafm7klwl8pdjxhncyrfguw"); // when witness version is zero, program must be either 20 or 32 bits

  let bech32m_1 = Bech32::empty();
  let decoded_1 = bech32m_1.decode(bech32_address_1);

  assert_eq!(decoded_1, Err(Bech32Error::WrongWitnessVersion));
}
