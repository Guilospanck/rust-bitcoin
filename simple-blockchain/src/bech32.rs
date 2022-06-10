use crate::helpers::{convert_bits};

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
  hrp: String,
  payload: Vec<u8>,
}

#[derive(Debug)]
pub struct Bech32Decoded {
  hrp: String,
  payload: Payload,
}

#[derive(Debug)]
pub struct Payload {
  witness_version: String,
  program: String,
  checksum: String,
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
const SEPARATOR_LENGTH: usize = 1;
const CHECKSUM_LENGTH: usize = 6;
// Address constants
const MIN_ADDRESS_LENGTH: usize = MIN_HRP_LENGTH + SEPARATOR_LENGTH + CHECKSUM_LENGTH;
const MAX_ADDRESS_LENGTH: usize = 90;

impl Bech32 {
  pub fn empty() -> Self {
    Bech32 {
      payload: Vec::<u8>::new(),
      hrp: String::new(),
    }
  }

  pub fn new(hrp: String, payload: Vec<u8>) -> Self {
    Bech32 { hrp, payload }
  }

  pub fn encode(&self, encoding_type: EncodingType) -> String {
    if self.hrp.len() < 1 || self.hrp.len() > 83 {
      // invalid length error
      return "Error: invalid length".to_owned();
    }

    let mut encoded = self.hrp.clone();
    encoded.push(SEPARATOR);

    let hrp_bytes: Vec<u8> = self.hrp.clone().into_bytes();
    let checksum = create_checksum(&hrp_bytes, &self.payload, encoding_type.clone());

    let mut combined = self.payload.clone();
    combined.extend_from_slice(&checksum);

    for i in combined {
      if i >= 32 {
        return "Invalid data".to_owned();
      }

      encoded.push(CHARSET[i as usize]);
    }

    encoded
  }

  pub fn decode(&self, address: String) -> Bech32Decoded {
    if address.len() < MIN_ADDRESS_LENGTH || address.len() > MAX_ADDRESS_LENGTH {
      panic!("Error: Invalid length.");
    }

    let separated_data: Vec<&str> = address.split(SEPARATOR).collect();
    let hrp: &str = separated_data[0];

    let payload: &str = separated_data[1];
    let payload_length = payload.len();

    if hrp.len() < MIN_HRP_LENGTH || payload_length < CHECKSUM_LENGTH {
      panic!("Error: Invalid length.");
    }

    if hrp != MAIN_NET_BTC {
      panic!("Error: Invalid HRP. It must be 'bc'.")
    }

    let hrp_bytes = hrp.to_owned().into_bytes();

    // Get witness version as base32 byte (0, 1, 2...16)
    let witness_version = get_base32_byte_representation(payload.chars().nth(0).unwrap());
    let witness_version_length = witness_version.to_string().len();
    
    // Get 5 bits representation of payload ({witness_version}{program}{checksum})
    let mut payload_bytes = Vec::<u8>::new();
    for character in payload.chars() {
      payload_bytes.push(get_base32_byte_representation(character) as u8);
    }

    // Validates checksum
    let mut encoding_type: EncodingType = EncodingType::BECH32;
    if witness_version != 0 {
      encoding_type = EncodingType::BECH32M;
    }

    if !verify_checksum(&hrp_bytes, &payload_bytes, encoding_type) {
      panic!("Checksum is not valid.");
    }

    // Validates decoding
    let program = payload_bytes[witness_version_length..payload_length - CHECKSUM_LENGTH].to_vec();
    let program_as_8_bits = convert_bits(5, 8, program);
    let (err, err_msg) = validate_decode(witness_version, program_as_8_bits.clone());
    if err {
      panic!("{}", err_msg);
    }

    let program_hex = hex::encode(&program_as_8_bits);

    let checksum = &payload[payload_length - CHECKSUM_LENGTH..];

    let payload_struct = Payload {
      witness_version: format!("{:x}", witness_version),
      program: program_hex,
      checksum: checksum.to_owned(),
    };

    Bech32Decoded {
      hrp: hrp.to_owned(),
      payload: payload_struct,
    }
  }
}

fn validate_decode(witness_version: i8, program_as_8_bits: Vec<u8>) -> (bool, String) {
  if witness_version < 0 || witness_version > 16 {
    return (
      true,
      String::from("Wrong witness version. Must be between 0 and 16."),
    );
  }

  // validate 2 - 40 groups
  if program_as_8_bits.len() < 2 || program_as_8_bits.len() > 40 {
    return (
      true,
      String::from("Error: There must be 2 - 40 groups. Data error."),
    );
  }

  // validate version and bytes of the program
  if witness_version == 0 && (program_as_8_bits.len() != 20 && program_as_8_bits.len() != 32) {
    return (true, String::from("Error: Invalid version length."));
  }

  (false, String::new())
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
