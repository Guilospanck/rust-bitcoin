use crate::helpers::{read_from_a_file_to_a_vec_string, get_pbkdf2_sha512};
use std::result;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Error, Debug)]
pub enum Bip39Error {
  #[error("IO error: `{0}`")]
  IOError(String),
  #[error("Error: entropy out of bonds. It must be between 128 and 256.")]
  EntropyOutOfBonds,
  #[error("Error: entropy must be multiple of 32 bits.")]
  EntropyMustBe32Multiple,
  #[error("Error: initial entropy + checksum must be multiple of 11.")]
  EntropyPlusChecksumMustBe11Multiple,
}

type Result<T> = result::Result<T, Bip39Error>;

const MNEMONIC_STRING: &str = "mnemonic";

/// Generates a mnemonic from a vector of bytes (an entropy).
/// The entropy is anything that has size of 128 - 256 bits, as
/// a private key, for example - which you can generate
/// using the `generate_private_key()` method described above.
///
/// (See: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
/// ENT: initial entropy length. 128-256 bits => must be a multiple of 32 bits.
/// CS: checksum
/// MS: mnemonic sentence in words
///
/// CS = ENT / 32
///
/// MS = (ENT + CS) / 11
///
/// ```
/// |  ENT  | CS | ENT+CS |  MS  |
/// +-------+----+--------+------+
/// |  128  |  4 |   132  |  12  |
/// |  160  |  5 |   165  |  15  |
/// |  192  |  6 |   198  |  18  |
/// |  224  |  7 |   231  |  21  |
/// |  256  |  8 |   264  |  24  |
/// ```
///
/// ---
/// Example:
/// ```rust
/// let entropy = &[0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0x97, 0xE1, 0x4D, 0x45, 0xF1, 0x4E, 0x1A, 0x1A].to_vec();
///
/// let mnemonic = match generate_mnemonic_from_entropy(entropy) {
///   Ok(data) => data,
///   Err(err) => panic!("{}", err),
/// };
///
/// assert_eq!(mnemonic, &["army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media", "make", "crunch"].to_vec());
/// ```
///
pub fn generate_mnemonic_from_entropy(entropy: Vec<u8>) -> Result<Vec<String>> {
  let entropy_length = entropy.len() * 8;

  if !(128..=256).contains(&entropy_length) {
    return Err(Bip39Error::EntropyOutOfBonds);
  }

  if entropy_length % 32 != 0 {
    return Err(Bip39Error::EntropyMustBe32Multiple);
  }

  let entropy_as_bits: String = entropy.iter().map(|v| format!("{:08b}", v)).collect();

  // Get bits representation of the SHA256(entropy)
  let sha256_entropy = sha256::digest_bytes(&entropy);
  let sha256_entropy_as_bytes = hex::decode(&sha256_entropy).unwrap();
  let sha256_entropy_as_bits: String = sha256_entropy_as_bytes
    .iter()
    .map(|v| format!("{:08b}", v))
    .collect();

  // Get checksum
  let num_bits_of_checksum: usize = entropy_length / 32;
  let checksum = &sha256_entropy_as_bits[..num_bits_of_checksum];

  // Append checksum to the end of initial entropy
  let entropy = format!("{}{}", entropy_as_bits, checksum);

  if entropy.len() % 11 != 0 {
    return Err(Bip39Error::EntropyPlusChecksumMustBe11Multiple);
  }

  // group bits in groups of 11
  let mut group: Vec<u16> = Vec::new();
  for bit in (0..entropy.len()).step_by(11) {
    let value: u16 = u16::from_str_radix(&entropy[bit..bit + 11], 2).unwrap();
    group.push(value);
  }

  // read wordlist
  let wordlist: Vec<String> =
    match read_from_a_file_to_a_vec_string("./src/wordlist/english.txt".to_owned()) {
      Ok(data) => data,
      Err(err) => return Err(Bip39Error::IOError(err.to_string())),
    };

  // get mnemonic
  let mut mnemonic: Vec<String> = Vec::new();
  for value in group {
    mnemonic.push(wordlist[value as usize].clone());
  }
  println!("Mnemonic: {:?}", mnemonic);
  Ok(mnemonic)
}

/// Returns the seed that the mnemonic represents with its passphrase.
/// If a passphrase is not used, an empty string is used instead.
///
/// This function normalizees each word of the mnemonic using the UTF-8 NFKD normalization,
/// then it uses the PBKDF2 - SHA512 function (see `get_pbkdf2_sha512`) to derive the seed.
///
/// The seed is an 512 bits hexadecimal string.
///
/// ---
/// Example:
/// ```rust
/// let my_wallet = wallet::Wallet {};
/// let mnemonic: Vec<String> = &["army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media", "make", "crunch"].to_vec();
///
/// let seed = my_wallet.get_seed_from_mnemonic(mnemonic, None);
///
/// assert_eq!(seed, "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570".to_owned());
/// ```
///
pub fn get_seed_from_mnemonic(mnemonic: Vec<String>, passphrase: Option<String>) -> String {
  // Verify passphrase. If a passphrase is not used, an empty string is used instead.
  let passphrase: String = match passphrase {
    Some(pass) => pass,
    None => "".to_owned(),
  };

  let normalized_mnemonic: Vec<String> = mnemonic.iter().map(|w| w.nfkd().to_string()).collect();
  let stringfied_mnemonic: String = normalized_mnemonic.join(" ");

  let salt = format!("{}{}", MNEMONIC_STRING, passphrase);
  let normalized_salt = salt.nfkd().to_string();

  get_pbkdf2_sha512(stringfied_mnemonic, normalized_salt)
}
