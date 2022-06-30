use num_bigint::{BigInt, Sign};
use sha256;

const BASE58_CHARSET: [char; 58] = [
  '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K',
  'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e',
  'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
  'z',
];

const MAIN_NET_BASE58_PRV_KEY_WIF_VERSION: &str = "80"; // 0x80
// const TEST_NET_BASE58_PRV_KEY_WIF_VERSION: &str = "EF"; // 0xEF
const PRV_KEY_CORRESPOND_TO_WIF_COMPRESSED: &str = "01"; // 0x01

#[derive(Clone, Debug)]
pub enum PublicKeyType {
  Compressed,
  Uncompressed,
}

/// Base58Check is a way of representing data in Bitcoin that is widely used to represent
/// Public and Private Keys.
///
/// See more at: https://en.bitcoin.it/wiki/Base58Check_encoding and 
/// https://reference.cash/protocol/blockchain/encoding/base58check
///
pub struct Base58Check {}

impl Base58Check {
  /// Encodes private key WIF (Wallet Import Format) compressed in Base58Check representation for the Bitcoin Mainnet.
  ///
  /// ```rust
  /// let base58_check = base58check::Base58Check{};
  ///
  /// let private_key_wif_compressed = "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3".to_owned();
  /// let base58check_private_key_wif_compressed = encode_private_key_wif(private_key, PublicKeyType::Compressed);
  ///
  /// assert_eq!(base58check_private_key_wif_compressed, "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d".to_owned());
  /// ```
  pub fn encode_private_key_wif(&self, data: String, public_key_type: PublicKeyType) -> String {
    // Adds version at the beginning of private key and, if public key is compressed, adds 0x01 at the end.
    let data = match public_key_type {
      PublicKeyType::Uncompressed => format!("{}{}", MAIN_NET_BASE58_PRV_KEY_WIF_VERSION, data),
      PublicKeyType::Compressed => format!("{}{}{}", MAIN_NET_BASE58_PRV_KEY_WIF_VERSION, data, PRV_KEY_CORRESPOND_TO_WIF_COMPRESSED),
    };   

    // gets checksum
    let checksum = self.get_checksum(data.clone());

    let data_with_checksum = format!("{}{}", data, checksum);

    // encodes to base58
    self.encode(data_with_checksum)
  }

  /// Encodes extended key (zpub or zprv) in Base58Check representation.
  ///
  /// ```rust
  /// let base58_check = base58check::Base58Check{};
  /// 
  /// // Extended public key
  /// let zpub = "04b24746037ef32bdb800000004a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc02707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b".to_owned();
  /// let base58check_zpub = base58_check.encode_extended_key(zpub);
  /// 
  /// // Extended private key
  /// let zprv = "04b2430c037ef32bdb800000004a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc00e14f274d16ca0d91031b98b162618061d03930fa381af6d4caf44b01819ab6d4".to_owned();
  /// let base58check_zprv = base58_check.encode_extended_key(zprv);
  ///
  /// assert_eq!(base58check_zpub, "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs".to_owned());
  /// assert_eq!(base58check_zprv, "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE".to_owned());
  /// ```
  /// 
  pub fn encode_extended_key(&self, data: String) -> String {
    // gets checksum
    let checksum = self.get_checksum(data.clone());

    let data_with_checksum = format!("{}{}", data, checksum);   

    // encodes to base58
    self.encode(data_with_checksum)
  }

  /// Inputs the hexadecimal format of some data added with proper version number
  /// and checksum and then returns the Base58Check representation of it.
  ///
  fn encode(&self, data_with_checksum: String) -> String {
    // transforms hexadecimal data into BigInt
    let data_with_checksum_as_bytes = hex::decode(&data_with_checksum).unwrap();
    let mut data_with_checksum_as_decimal =
      BigInt::from_bytes_be(Sign::Plus, &data_with_checksum_as_bytes);

    // encode to base58
    let mut encoded: Vec<String> = Vec::new();
    loop {
      let remainder: BigInt = data_with_checksum_as_decimal.clone() % 58;
      data_with_checksum_as_decimal = data_with_checksum_as_decimal / BigInt::from(58u8);

      encoded.push(String::from(
        BASE58_CHARSET[(remainder.to_signed_bytes_be()[0]) as usize],
      ));
      
      if data_with_checksum_as_decimal <= BigInt::from(0u8) {
        break;
      }
    }

    // reverse vector
    encoded.reverse();
    // join it
    let encoded: String = encoded.join("");

    encoded
  }

  /// Return the checksum of some data (version | key) in hexadecimal format.
  /// The checksum consists of 4 bytes (32 bits) of the double SHA256 hash
  /// of this data.
  ///
  /// ```rust
  /// let base58_check = base58check::Base58Check{};
  ///
  /// let private_key = "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3".to_owned();
  /// let checksum_private_key = get_checksum(private_key);
  ///
  /// assert_eq!(checksum_private_key, "2aebdbb8".to_owned());
  /// ```
  fn get_checksum(&self, data: String) -> String {
    let data_hashed_160 = sha256::digest_bytes(&hex::decode(&data.clone()).unwrap());
    let data_double_hashed_160 = sha256::digest_bytes(&hex::decode(&data_hashed_160).unwrap());
    let checksum = &data_double_hashed_160[..8];

    checksum.to_owned()
  }
}
