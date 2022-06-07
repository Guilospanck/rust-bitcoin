use hex;
use rand::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha256::digest;
use ripemd::{Ripemd160, Digest};
use std::str;

/// From a private key (k) - usually picked up at random - we derive,
/// using elliptic curve multiplication (ECC), a public key (K).
/// From a public key we derive, using a one-way hashing function,
/// a bitcoin address (A).
///
/// The private key is picked at random, between 1 and 2^256. To be more accurate,
/// the private key can be any number between 1 and n-1, where n is a constant
/// `(n = 1.158*10^77, which is slightly less than 2^256)`
/// ```rust
/// let maximum_private_key_value: BigInt = BigInt::from(1158u16) * BigInt::from(10u8).pow(74);
/// 
/// // Address
/// let A = RIPEMD160(SHA256(K));
/// ```
/// 
///

pub fn generate_private_key() -> String {
  let mut random: StdRng = SeedableRng::from_entropy();
  let random: u128 = random.gen::<u128>();
  println!("Private dec: {}", random);
  let hexadecimal_private_key = digest(random.to_string());
  println!("Private hex: {}", hexadecimal_private_key);

  hexadecimal_private_key
}

pub fn get_public_key_from_private_key(private_key: String) -> String {
  let private_key_bytes = hex::decode(private_key).unwrap();
  let secp = Secp256k1::new();
  let secret_key = SecretKey::from_slice(&private_key_bytes).expect("32 bytes, within curve order");
  let public_key = PublicKey::from_secret_key(&secp, &secret_key);

  public_key.to_string()
}

pub fn generate_bech32m_address_from_public_key(public_key: String) -> String {
  // let hashed_256_public_key = digest(&public_key);
  // let ripemd160_hashed = ripemd160_hasher(hashed_256_public_key);
  let ripemd160_hashed = "ec4cf4f972275b836cddb880d7991e552d7e9828".to_owned();

  println!("Ripemd160: {}", ripemd160_hashed);

  let hash160_as_base32 = convert_to_base32(ripemd160_hashed);

  let bech32 = Bech32::new(MAIN_NET_BTC.to_owned(), hash160_as_base32);
  let encoded = bech32.encode();

  println!("Bech32m encoded: {}", encoded);
  
  
  "".to_owned()
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
    bits.push_str(&format!("{:b}", byte));
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
    let bits_as_decimal = u8::from_str_radix(&bits[i..i+5], 2).unwrap(); 
    grouped_by_five.push(bits_as_decimal);    
  }

  println!("Base32: {:?}", grouped_by_five);

  grouped_by_five
  
}


/// Bech32 (Bech32m)
/// 
/// See: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki and
///      https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#Specification
/// 
/// Bech32:
/// - human-readable part (HRP): This part MUST contain 1 to 83 US-ASCII characters.
/// - the separator: 1
/// - the data part: at least 6 characters and only alphanumeric characters
///   excluding "1", "b", "i" and "o".
///   The last 6 characters are the checksum and have no information.
/// 
#[derive(Clone)]
pub struct Bech32 {
  hrp: String,
  data: Vec<u8>
}

const MAIN_NET_BTC: &str = "bc";

// Human-readable part and data part separator
const SEPARATOR: char = '1';

// Encoding character set. Maps data value -> char
const CHARSET: [char; 32] = [
  'q',	'p',	'z',	'r',	'y',	'9',	'x',	'8',
  'g',	'f',	'2',	't',	'v',	'd',	'w',	'0',
	's',	'3',	'j',	'n',	'5',	'4',	'k',	'h',
	'c',	'e',	'6',	'm',	'u',	'a',	'7',	'l',
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const CHARSET_REV: [i8; 128] = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
];


impl Bech32 {
  fn new(hrp: String, data: Vec<u8>) -> Self {
    Bech32 {
      hrp,
      data,
    }
  }

  fn encode(&self) -> String {
    if self.hrp.len() < 1 || self.hrp.len() > 83 {
      // invalid length error
      return "Error: invalid length".to_owned();
    }

    let mut encoding = self.hrp.clone();
    encoding.push(SEPARATOR);

    let hrp_bytes: Vec<u8> = self.hrp.clone().into_bytes();
    let checksum = create_checksum(&hrp_bytes, &self.data);

    let mut combined = self.data.clone();
    combined.extend_from_slice(&checksum);

    for i in combined {
      if i >= 32 {
        return "Invalid data".to_owned();
      }

      encoding.push(CHARSET[i  as usize]);
    }


    encoding
  }
}

/* Checksum functions */
const BECH32M_CONST: u32 =  734_539_939; // 0x2bc830a3

fn create_checksum(hrp: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
  let mut values: Vec<u8> = hrp_expand(hrp);
  values.extend_from_slice(data);
  // Pad with 6 zeros
  values.extend_from_slice(&[0u8; 6]);
  let plm: u32 = polymod(values) ^ BECH32M_CONST;
  let mut checksum: Vec<u8> = Vec::new();
  for p in 0..6 {
    checksum.push(((plm >> 5 * (5 - p)) & 0x1f) as u8);
  }
  checksum
}

fn verify_checksum(hrp: &Vec<u8>, data: &Vec<u8>) -> bool {
  let mut exp = hrp_expand(hrp);
  exp.extend_from_slice(data);
  polymod(exp) == BECH32M_CONST
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

