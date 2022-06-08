use num_bigint::{BigInt, Sign};
use hex;
use rand::prelude::*;
use ripemd::{Digest, Ripemd160};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha256::digest;
use std::str;

/// A wallet contains our addresses and keys.
/// 
/// From a private key (k) - usually picked up at random - we derive,
/// using elliptic curve multiplication (ECC), a public key (K).
/// From a public key we derive, using a one-way hashing function,
/// a bitcoin address (A).
///
#[derive(Debug)]
pub struct Wallet {}

impl Wallet {
  /// Generates a private key from a CSPRNG (cryptographically-secure pseudo-random number
  /// generator) entropy and returns the SHA256 format of it.
  /// 
  /// This number must be less than a constant `(n = 1.158*10^77, which is slightly less than 2^256)`,
  /// in order to be able to derive it from a ECC curve.
  /// 
  /// Example:
  /// ```rust
  /// let wallet = Wallet{};
  /// let k = wallet.generate_private_key();
  /// ```
  pub fn generate_private_key(&self) -> String {
    let maximum_private_key_value: BigInt = BigInt::from(1158u16) * BigInt::from(10u8).pow(74) - 1u8;    

    let mut random: StdRng = SeedableRng::from_entropy();
    let random: u128 = random.gen::<u128>();
    let hexadecimal_private_key = digest(random.to_string());

    let hexa_as_bytes = hex::decode(&hexadecimal_private_key).unwrap();    
    let hexa_as_bigint = BigInt::from_bytes_be(Sign::Plus, &hexa_as_bytes);

    if hexa_as_bigint > maximum_private_key_value {
      return self.generate_private_key();
    }

    println!("Private Key (k) in decimal format: {}", random);
    println!("Private Key (k) in SHA256 format: {}", hexadecimal_private_key);

    hexadecimal_private_key
  }

  /// Derives a Public Key (K) from a Private Key (k) using ECC
  /// (Elliptic Curve Cryptography) using the generator parameter
  /// known as `secp256k1`.
  /// The `private_key` argument is the SHA256 representation of it.
  /// Returns a hexadecimal string representing the Public Key.
  /// 
  /// Example:
  /// ```rust
  /// let wallet = Wallet{};
  /// let k = wallet.generate_private_key();
  /// let K = wallet.get_public_key_from_private_key(k);
  /// 
  /// // tests
  /// let k = "e1b4519c66558ec215c55392290afc35f249e113c803bfcadf3b066b4f87d2f3".to_owned();
  /// let K = wallet.get_public_key_from_private_key(k);
  /// assert_eq!(K, "0313e8842189afb5316c3c1acfcca696a85ec3741d17767f953bc70394b3839365".to_owned());
  /// ```
  pub fn get_public_key_from_private_key(&self, private_key: String) -> String {
    let private_key_bytes = hex::decode(private_key).unwrap();
    let secp = Secp256k1::new();
    let secret_key =
      SecretKey::from_slice(&private_key_bytes).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    println!("Public key (K): {}", public_key);

    public_key.to_string()
  }

  /// Generates a Bech32m address from a Public Key (K).
  /// The Public Key must not be hashed before, only in its Hex format.
  /// This function will apply the RIPEMD160(SHA256(K)) to K; get its 
  /// Base32 format and then retrieve its representation in Bech32m style 
  /// for the Bitcoin mainnet (bc).
  /// 
  /// Example:
  /// ```rust
  /// let wallet = Wallet{};
  /// let k = wallet.generate_private_key();
  /// let K = wallet.get_public_key_from_private_key(k);
  /// let bech32m_address = wallet.generate_bech32m_address_from_public_key(K);
  /// 
  /// // tests
  /// let k = "e1b4519c66558ec215c55392290afc35f249e113c803bfcadf3b066b4f87d2f3".to_owned();
  /// let K = wallet.get_public_key_from_private_key(k);
  /// assert_eq!(K, "0313e8842189afb5316c3c1acfcca696a85ec3741d17767f953bc70394b3839365".to_owned());
  /// let bech32m_address = wallet.generate_bech32m_address_from_public_key(K);
  /// assert_eq!(bech32m_address, "bc1pddprup5dlqhqtcmu6wnya4tsugngx56seuflu7".to_owned()); // witness version 1
  /// ```
  pub fn generate_bech32m_address_from_public_key(&self, public_key: String) -> String {
    let hashed_256_public_key = digest(&public_key);
    println!("SHA256 of Public Key (K): {}", hashed_256_public_key);
    let ripemd160_hashed = ripemd160_hasher(hashed_256_public_key);
    println!("Ripemd160(SHA256(K)), also known as HASH160: {}", ripemd160_hashed);
    let hash160_as_base32 = convert_to_base32(ripemd160_hashed);
    println!("HASH160 in Base32: {:?}", hash160_as_base32);

    // witness version
    let mut witness_version_plus_hash160 = vec![1u8];
    witness_version_plus_hash160.extend_from_slice(&hash160_as_base32);

    let bech32 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160);
    let encoded = bech32.encode(EncodingType::BECH32M);

    println!("Bech32m encoded: {}", encoded);
    encoded
  }
}

fn ripemd160_hasher(data: String) -> String {
  let mut hasher = Ripemd160::new();
  hasher.update(data);
  let result = hasher.finalize();

  format!("{:x}", result)
}

fn convert_to_base32(data_hex: String) -> Vec<u8> {
  let hex_as_bytes = hex::decode(&data_hex).unwrap();

  let mut bits = String::new();
  for byte in hex_as_bytes {
    bits.push_str(&format!("{:08b}", byte));
  }

  let divisible_by_five = (bits.len() % 5) == 0;

  if !divisible_by_five {
    let bits_to_pad = 5 - (bits.len() % 5);
    for _i in 0..bits_to_pad {
      bits.push('0');
    }
  }

  let mut grouped_by_five: Vec<u8> = Vec::new();

  for i in (0..bits.len()).step_by(5) {
    let bits_as_decimal = u8::from_str_radix(&bits[i..i + 5], 2).unwrap();
    grouped_by_five.push(bits_as_decimal);
  }

  grouped_by_five
}

/// Bech32 (Bech32m)
///
/// See: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki and
///      https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#Specification
///
/// Anatomy of a Bech32 address:
///
///   `{HRP}{Separator}{payload}`
///
/// - `human-readable part (HRP)`: This part MUST contain 1 to 83 US-ASCII characters. Usually is just `"bc"`
/// for the mainnet or `"tb"` for the testnet.
/// - `separator`: `'1'` (one)
/// - `payload`: at least 6 characters and only alphanumeric characters excluding `"1"`,`"b"`,`"i"` and `"o"`.
///
///   Anatomy of the payload:
///
///    `{witness-version}{program}{checksum}`
///
///   - `witness-version`: goes from 0 to 15 in the Base32 format. 0 is for Bech32 addresses and 1 forward is for Bech32m addresses.
///   - `program`: basically it's the HASH160 of your public key (K) in the Base32 format.
///   - `checksum`: uses the HRP (as bytes) and your [witness-version, program] (witness version prepended to the program base32 bytes).
///
///
#[derive(Clone)]
pub struct Bech32 {
  hrp: String,
  data: Vec<u8>,
}

const MAIN_NET_BTC: &str = "bc";

// Human-readable part and data part separator
const SEPARATOR: char = '1';

// Encoding character set. Maps data value -> char
const CHARSET: [char; 32] = [
  'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's', '3', 'j',
  'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const _CHARSET_REV: [i8; 128] = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
  -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29, -1,
  24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1,
  -1, -1, -1,
];

impl Bech32 {
  fn new(hrp: String, data: Vec<u8>) -> Self {
    Bech32 { hrp, data }
  }

  fn encode(&self, encoding_type: EncodingType) -> String {
    if self.hrp.len() < 1 || self.hrp.len() > 83 {
      // invalid length error
      return "Error: invalid length".to_owned();
    }

    let mut encoded = self.hrp.clone();
    encoded.push(SEPARATOR);

    let hrp_bytes: Vec<u8> = self.hrp.clone().into_bytes();
    let checksum = create_checksum(&hrp_bytes, &self.data, encoding_type);

    let mut combined = self.data.clone();
    combined.extend_from_slice(&checksum);

    for i in combined {
      if i >= 32 {
        return "Invalid data".to_owned();
      }

      encoded.push(CHARSET[i as usize]);
    }

    encoded
  }
}

/* Checksum functions */
enum EncodingType {
  BECH32,
  BECH32M,
}

const BECH32M_CONST: u32 = 734_539_939; // 0x2bc830a3
const BECH32_CONST: u32 = 1;

fn get_encoding_const(encoding: EncodingType) -> u32 {
  match encoding {
    EncodingType::BECH32 => BECH32_CONST,
    EncodingType::BECH32M => BECH32M_CONST,
    _ => {
      println!("Error: encoding is not valid.");
      return 0;
    }
  }
}

fn create_checksum(hrp: &Vec<u8>, data: &Vec<u8>, encoding_type: EncodingType) -> Vec<u8> {
  let mut values: Vec<u8> = hrp_expand(hrp);
  values.extend_from_slice(data);

  // Pad with 6 zeros
  values.extend_from_slice(&[0u8; 6]);

  let plm: u32 = polymod(values) ^ get_encoding_const(encoding_type);

  let mut checksum: Vec<u8> = Vec::new();
  for p in 0..6 {
    checksum.push(((plm >> 5 * (5 - p)) & 0x1f) as u8);
  }
  checksum
}

fn verify_checksum(hrp: &Vec<u8>, data: &Vec<u8>, encoding_type: EncodingType) -> bool {
  let mut exp = hrp_expand(hrp);
  exp.extend_from_slice(data);
  polymod(exp) == get_encoding_const(encoding_type)
}

fn hrp_expand(hrp: &Vec<u8>) -> Vec<u8> {
  let mut v: Vec<u8> = Vec::new();
  for b in hrp {
    v.push(*b >> 5);
  }
  v.push(0);
  for b in hrp {
    v.push(*b & 0x1f);
  }
  v
}

// Generator coefficients
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: Vec<u8>) -> u32 {
  let mut chk: u32 = 1;
  let mut b: u8;
  for v in values {
    b = (chk >> 25) as u8;
    chk = (chk & 0x1ffffff) << 5 ^ (v as u32);
    for i in 0..5 {
      if (b >> i) & 1 == 1 {
        chk ^= GEN[i]
      }
    }
  }
  chk
}
