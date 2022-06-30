use btc::bech32::{Bech32, MAIN_NET_BTC, EncodingType, Bech32Error};

/** =================================== Bech32 ENCODE ======================================= */
#[test]
fn test_bech32_should_encode_witness_version_0_correctly() {
  // K = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
  let witness_version_plus_hash160_1 = vec![0, 24, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6, 12, 7, 15, 18, 4, 7, 2];
  // K = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
  let witness_version_plus_hash160_2 = vec![0, 6, 17, 1, 1, 18, 15, 16, 27, 22, 28, 4, 17, 13, 26, 8, 20, 10, 20, 16, 23, 5, 19, 10, 14, 5, 22, 30, 9, 27, 30, 0, 17];
  // K = "03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494"
  let witness_version_plus_hash160_3 = vec![0, 14, 15, 2, 29, 20, 2, 16, 3, 26, 11, 8, 8, 0, 14, 27, 19, 3, 28, 2, 2, 8, 10, 29, 20, 1, 19, 22, 18, 31, 2, 29, 28];

  let bech32_1 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_1);
  let bech32_2 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_2);
  let bech32_3 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_3);
  let encoded_1 = bech32_1.encode(EncodingType::BECH32);
  let encoded_2 = bech32_2.encode(EncodingType::BECH32);
  let encoded_3 = bech32_3.encode(EncodingType::BECH32);

  assert_eq!(encoded_1, Ok("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".to_owned()));
  assert_eq!(encoded_2, Ok("bc1qx3ppj0smkuy3d6g525sh9n2w9k7fm7q3x30rtg".to_owned()));
  assert_eq!(encoded_3, Ok("bc1qw0za5zsr6tggqwmnruzzg2a5pnkjlzaus8upyg".to_owned()));
}

#[test]
fn test_bech32_should_encode_witness_version_1_correctly() {
  // K = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
  let witness_version_plus_hash160_1 = vec![1, 24, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6, 12, 7, 15, 18, 4, 7, 2];
  // K = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
  let witness_version_plus_hash160_2 = vec![1, 6, 17, 1, 1, 18, 15, 16, 27, 22, 28, 4, 17, 13, 26, 8, 20, 10, 20, 16, 23, 5, 19, 10, 14, 5, 22, 30, 9, 27, 30, 0, 17];
  // K = "03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494"
  let witness_version_plus_hash160_3 = vec![1, 14, 15, 2, 29, 20, 2, 16, 3, 26, 11, 8, 8, 0, 14, 27, 19, 3, 28, 2, 2, 8, 10, 29, 20, 1, 19, 22, 18, 31, 2, 29, 28];

  let bech32m_1 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_1);
  let bech32m_2 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_2);
  let bech32m_3 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_3);
  let encoded_1 = bech32m_1.encode(EncodingType::BECH32M);
  let encoded_2 = bech32m_2.encode(EncodingType::BECH32M);
  let encoded_3 = bech32m_3.encode(EncodingType::BECH32M);

  assert_eq!(encoded_1, Ok("bc1pcr8te4kr609gcawutmrza0j4xv80jy8z0dawv4".to_owned()));
  assert_eq!(encoded_2, Ok("bc1px3ppj0smkuy3d6g525sh9n2w9k7fm7q3cngyrp".to_owned()));
  assert_eq!(encoded_3, Ok("bc1pw0za5zsr6tggqwmnruzzg2a5pnkjlzauw9mxvp".to_owned()));
}

#[test]
fn test_bech32_should_return_InvalidLength_error_hrp_below_min_length_encode_fn() {
  // K = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
  let witness_version_plus_hash160_1 = vec![0, 24, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6, 12, 7, 15, 18, 4, 7, 2];
  let hrp_below_min_length = "".to_owned();

  let bech32_1 = Bech32::new(hrp_below_min_length, witness_version_plus_hash160_1);
  let encoded_1 = bech32_1.encode(EncodingType::BECH32);

  assert_eq!(encoded_1, Err(Bech32Error::InvalidLength));
}

#[test]
fn test_bech32_should_return_InvalidLength_error_hrp_above_max_length_encode_fn() {
  // K = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
  let witness_version_plus_hash160_1 = vec![0, 24, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6, 12, 7, 15, 18, 4, 7, 2];
  let hrp_above_max_length = vec!["0";84].join("");

  let bech32_1 = Bech32::new(hrp_above_max_length, witness_version_plus_hash160_1);
  let encoded_1 = bech32_1.encode(EncodingType::BECH32);

  assert_eq!(encoded_1, Err(Bech32Error::InvalidLength));
}

#[test]
fn test_bech32_should_return_InvalidData_error_data_above_32_bits_encode_fn() {
  // byte above 32 bits
  let witness_version_plus_hash160_1 = vec![0, 45, 3, 7, 11, 25, 21, 22, 3, 26, 15, 5, 8, 24, 29, 14, 28, 11, 27, 3, 2, 29, 15, 18, 21, 6, 12, 7, 15, 18, 4, 7, 2];  

  let bech32_1 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160_1);
  let encoded_1 = bech32_1.encode(EncodingType::BECH32);

  assert_eq!(encoded_1, Err(Bech32Error::InvalidData));
}

/** =================================== Bech32 DECODE ======================================= */