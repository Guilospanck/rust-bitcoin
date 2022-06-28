use sha256;
use num_bigint::{BigInt, Sign};

const BASE58_CHARSET: [char;58] = [
  '1', '2','3','4',
  '5','6','7','8',
  '9','A','B','C',
  'D','E','F','G',
  'H','J','K','L',
  'M','N','P','Q',
  'R','S','T','U',
  'V','W','X','Y',
  'Z','a','b','c',
  'd','e','f','g',
  'h','i','j','k',
  'm','n','o','p',
  'q','r','s','t',
  'u','v','w','x',
  'y','z',
];

const MAIN_NET_BASE58: &str = "80"; // 0x80
const TEST_NET_BASE58: &str = "EF"; // 0xEF
const PRV_KEY_CORRESPOND_TO_COMPRESSED_PUBLIC_KEY: &str = "01"; // 0x01

/// Base58Check is a way of representing data in Bitcoin that is widely used to represent
/// Public and Private Keys.
/// 
/// See more at: https://en.bitcoin.it/wiki/Base58Check_encoding.
/// 
pub struct Base58Check {}

impl Base58Check {
  pub fn encode_private_key(&self, data: String) -> String {
    // Adds version at the beginning of private key and adds 0x01 at the end because the K is uncompressed.
    let data = format!("{}{}{}", MAIN_NET_BASE58, data, PRV_KEY_CORRESPOND_TO_COMPRESSED_PUBLIC_KEY);

    // gets checksum
    let data_hashed_160 = sha256::digest_bytes(&hex::decode(&data.clone()).unwrap());
    let data_double_hashed_160 = sha256::digest_bytes(&hex::decode(&data_hashed_160).unwrap());
    let checksum = &data_double_hashed_160[..8];

    let data_with_checksum = format!("{}{}", data, checksum);

    // encodes to base58
    self.encode(data_with_checksum)
  }


  /// Inputs the hexadecimal format of some key (k or K) added with proper version number
  /// and checksum and then returns the Base58Check representation of it.
  /// 
  fn encode(&self, data_with_checksum: String) -> String {
    // transforms hexadecimal data into BigInt
    let data_with_checksum_as_bytes = hex::decode(&data_with_checksum).unwrap();
    let mut data_with_checksum_as_decimal = BigInt::from_bytes_be(Sign::Plus, &data_with_checksum_as_bytes);
    
    // encode to base58
    let mut encoded: Vec<String> = Vec::new();
    loop {
      let remainder: BigInt = data_with_checksum_as_decimal.clone() % 58;
      data_with_checksum_as_decimal = data_with_checksum_as_decimal / BigInt::from(58u8);
      
      encoded.push(String::from(BASE58_CHARSET[(remainder.to_signed_bytes_be()[0]) as usize]));

      if data_with_checksum_as_decimal <= BigInt::from(0u8) {
        break
      }
    }

    // reverse vector
    encoded.reverse();
    // join it
    let encoded: String = encoded.join("");

    encoded
  }
}