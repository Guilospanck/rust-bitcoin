use crate::helpers::convert_bits;
use std::result;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Bech32Error {
  #[error("Invalid length")]
  InvalidLength,
  #[error("Invalid data")]
  InvalidData,
  #[error("Invalid HRP. It must be 'bc'")]
  InvalidHRP,
  #[error("Checksum is not valid")]
  InvalidChecksum,
  #[error("Invalid witness version. Must be between 0 and 16")]
  InvalidWitnessVersion,
  #[error("There must be 2 - 40 groups")]
  InvalidProgramLength,
  #[error("Wrong witness version. When program is 20 or 32 bytes, witness version must be 0")]
  WrongWitnessVersion,
  #[error("Missing separator")]
  MissingSeparator,
  #[error("Invalid program char")]
  InvalidChar,
  #[error("Invalid program: Mixed case")]
  MixedCase,
}

type Result<T> = result::Result<T, Bech32Error>;

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
#[derive(Clone, Debug)]
pub struct Bech32 {
  pub hrp: String,
  pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Bech32Decoded {
  pub hrp: String,
  pub payload: Payload,
}

#[derive(Debug, PartialEq)]
pub struct Payload {
  pub witness_version: String,
  pub program: String,
  pub checksum: String,
}

impl Bech32Decoded {
  pub fn empty() -> Self {
    Bech32Decoded {
      hrp: "".to_owned(),
      payload: Payload {
        witness_version: "".to_owned(),
        program: "".to_owned(),
        checksum: "".to_owned(),
      },
    }
  }
}

pub const MAIN_NET_BTC: &str = "bc";

// Human-readable part and payload part separator
const SEPARATOR: char = '1';

// Encoding character set. Maps payload value -> char
const CHARSET: [char; 32] = [
  'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's', '3', 'j',
  'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const CHARSET_REV: [i8; 128] = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
  -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29, -1,
  24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1,
  -1, -1, -1,
];

const MIN_HRP_LENGTH: usize = 1;
const MAX_HRP_LENGTH: usize = 83;
const SEPARATOR_LENGTH: usize = 1;
const CHECKSUM_LENGTH: usize = 6;
// Address constants
const MIN_ADDRESS_LENGTH: usize = MIN_HRP_LENGTH + SEPARATOR_LENGTH + CHECKSUM_LENGTH; // 8
const MAX_ADDRESS_LENGTH: usize = MAX_HRP_LENGTH + SEPARATOR_LENGTH + CHECKSUM_LENGTH; // 90

impl Bech32 {
  /// Returns an empty Bech32 struct.
  pub fn empty() -> Self {
    Bech32 {
      payload: Vec::<u8>::new(),
      hrp: String::new(),
    }
  }

  /// Creates a new Bech32 struct.
  /// - `hrp`: Human-readable part, usually 'bc' (BTC mainnet);
  /// - `payload`: {witness_version}{program} as Base32 vector of bytes, where:
  ///    - `witness_version`: 0..16
  ///    - `program`: Base32(HASH160(K))
  /// 
  pub fn new(hrp: String, payload: Vec<u8>) -> Self {
    Bech32 { hrp, payload }
  }

  /// Will return a encoded Bech32(m) address from a previous Bech32 struct created.
  /// If something goes wrong with the encoding, will return an error.
  /// - `encoding_type`: BECH32 or BECH32M
  /// 
  pub fn encode(&self, encoding_type: EncodingType) -> Result<String> {
    if self.hrp.len() < MIN_HRP_LENGTH || self.hrp.len() > MAX_HRP_LENGTH {
      return Err(Bech32Error::InvalidLength);
    }

    let mut encoded = self.hrp.clone();
    encoded.push(SEPARATOR);

    let hrp_bytes: Vec<u8> = self.hrp.clone().into_bytes();
    let checksum = create_checksum(&hrp_bytes, &self.payload, encoding_type.clone());

    let mut combined = self.payload.clone();
    combined.extend_from_slice(&checksum);

    for i in combined {
      if i >= 32 {
        return Err(Bech32Error::InvalidData);
      }

      encoded.push(CHARSET[i as usize]);
    }

    Ok(encoded)
  }

  /// Gets info from a Bech32(m) address. If something is not right, will return
  /// an error.
  /// - `address`: the bech32(m) address that you wanna have information about.
  pub fn decode(&self, address: String) -> Result<Bech32Decoded> {
    if address.len() < MIN_ADDRESS_LENGTH || address.len() > MAX_ADDRESS_LENGTH {
      return Err(Bech32Error::InvalidLength);
    }

    if address.find(SEPARATOR).is_none() {
      return Err(Bech32Error::MissingSeparator);
    }

    let separated_data: Vec<&str> = address.splitn(2, SEPARATOR).collect();
    let hrp: &str = separated_data[0];

    let payload: &str = separated_data[1];
    let payload_length = payload.len();

    if hrp.len() < MIN_HRP_LENGTH || payload_length < CHECKSUM_LENGTH {
      return Err(Bech32Error::InvalidLength);
    }

    if hrp != MAIN_NET_BTC {
      return Err(Bech32Error::InvalidHRP);
    }

    let hrp_bytes = hrp.to_owned().into_bytes();

    // Get witness version as base32 byte (0, 1, 2...16)
    let witness_version = get_base32_byte_representation(payload.chars().nth(0).unwrap());
    let witness_version_length = witness_version.to_string().len();

    if witness_version < 0 || witness_version > 16 {
      return Err(Bech32Error::InvalidWitnessVersion);
    }

    // Get 5 bits representation of payload ({witness_version}{program}{checksum})
    let mut payload_bytes = Vec::<u8>::new();
    validates_and_get_base32_representation_of_payload(payload, &mut payload_bytes)?;

    // Validates checksum
    let mut encoding_type: EncodingType = EncodingType::BECH32;
    if witness_version != 0 {
      encoding_type = EncodingType::BECH32M;
    }

    if !verify_checksum(&hrp_bytes, &payload_bytes, encoding_type) {
      return Err(Bech32Error::InvalidChecksum);
    }

    // Validates decoding
    let program = payload_bytes[witness_version_length..payload_length - CHECKSUM_LENGTH].to_vec();
    let program_as_8_bits = convert_bits(5, 8, program);
    validate_decode(witness_version, program_as_8_bits.clone())?;

    let program_hex = hex::encode(&program_as_8_bits);

    let checksum = &payload[payload_length - CHECKSUM_LENGTH..];

    let payload_struct = Payload {
      witness_version: format!("{:x}", witness_version),
      program: program_hex,
      checksum: checksum.to_owned(),
    };

    Ok(Bech32Decoded {
      hrp: hrp.to_owned(),
      payload: payload_struct,
    })
  }
}

/// Validates mixed case in the payload bytes, as well as
/// character validation (if it's in the ASCII range accepted).
/// Then, it modifies the `payload_bytes` to have the Base32 byte format.
fn validates_and_get_base32_representation_of_payload(
  payload: &str,
  payload_bytes: &mut Vec<u8>,
) -> Result<()> {
  let mut has_lower: bool = false;
  let mut has_upper: bool = false;

  for b in payload.bytes() {
    // Aphanumeric only
    if !((b >= b'0' && b <= b'9') || (b >= b'A' && b <= b'Z') || (b >= b'a' && b <= b'z')) {
      return Err(Bech32Error::InvalidChar);
    }
    // Excludes these characters: [1,b,i,o]
    if b == b'1' || b == b'b' || b == b'i' || b == b'o' {
      return Err(Bech32Error::InvalidChar);
    }
    // Lowercase
    if b >= b'a' && b <= b'z' {
      has_lower = true;
    }
    let mut c = b;
    // Uppercase
    if b >= b'A' && b <= b'Z' {
      has_upper = true;
      // Convert to lowercase
      c = b + (b'a' - b'A');
    }
    payload_bytes.push(CHARSET_REV[c as usize] as u8);
  }

  // Ensure no mixed case
  if has_lower && has_upper {
    return Err(Bech32Error::MixedCase);
  }

  Ok(())
}

fn validate_decode(witness_version: i8, program_as_8_bits: Vec<u8>) -> Result<()> {
  // validate 2 - 40 groups
  if program_as_8_bits.len() < 2 || program_as_8_bits.len() > 40 {
    return Err(Bech32Error::InvalidProgramLength);
  }

  // validate version and bytes of the program
  if witness_version == 0 && (program_as_8_bits.len() != 20 && program_as_8_bits.len() != 32) {
    return Err(Bech32Error::WrongWitnessVersion);
  }

  Ok(())
}

/// Get the Base32 representation of a char.
/// First it gets its ASCII representation, then uses `CHARSET_REV`
/// to get the index by which this ASCII can be represented in the
/// Base32 format.
///
/// BASE32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
///
/// Example:
///
/// ```rust
/// assert_eq!(0, get_base32_byte_representation('q'));
/// assert_eq!(1, get_base32_byte_representation('p'));
/// ```
fn get_base32_byte_representation(character: char) -> i8 {
  let character = character as u8; // ASCII representation
  CHARSET_REV[character as usize]
}

/* Checksum functions */
#[derive(Clone, Debug)]
pub enum EncodingType {
  BECH32,
  BECH32M,
}

const BECH32M_CONST: u32 = 0x2bc830a3;
const BECH32_CONST: u32 = 0x01;

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

/// Verifies if the checksum is valid. Returns true is valid, false if isn't.
///
///   - `hrp`: human-readable part as Vec<u8> bytes.
///   - `payload`: address payload made of {witness_version}{program}{checksum}
///   - `encoding_type`: BECH32 (0x01) or BECH32M (0x2bc830a3) constants.
fn verify_checksum(hrp: &Vec<u8>, payload: &Vec<u8>, encoding_type: EncodingType) -> bool {
  let mut exp = hrp_expand(hrp);
  exp.extend_from_slice(payload);
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
  let mut top: u8;
  for v in values {
    top = (chk >> 25) as u8;
    chk = (chk & 0x1ffffff) << 5 ^ (v as u32);
    for i in 0..5 {
      if ((top >> i) & 1) == 1 {
        chk ^= GEN[i];
      }
    }
  }
  chk
}
