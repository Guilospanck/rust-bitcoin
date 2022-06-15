use crate::bech32::{Bech32, Bech32Decoded, EncodingType, MAIN_NET_BTC};
use crate::helpers::{convert_bits, ripemd160_hasher};
use hex;
use num_bigint::{BigInt, Sign};
use pbkdf2::{
  password_hash::{PasswordHasher, Salt},
  Algorithm, Params, Pbkdf2,
};
use rand::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha256::digest;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use unicode_normalization::UnicodeNormalization;

/// A wallet contains our addresses and keys.
///
/// From a private key (k) - usually picked up at random - we derive,
/// using elliptic curve multiplication (ECC), a public key (K).
/// From a public key we derive, using a one-way hashing function,
/// a bitcoin address (A).
///
/// There are two types of wallets: non-deterministic and deterministic (seeded).
/// The first one each key is independently generated from a random number.
/// The last one, all keys derive from a master key (also known as `seed`).
///
/// The most common way of derivation is the Hierarchical Deterministic (HD).
///
///
#[derive(Debug)]
pub struct Wallet {}

const PBKDF2_ITERATION_COUNT: u32 = 2048;
const PBKDF2_DERIVED_KEY_LENGTH_BYTES: usize = 64;
const MNEMONIC_STRING: &str = "mnemonic";

impl Wallet {
  /// Generates a private key from a CSPRNG (cryptographically-secure pseudo-random number
  /// generator) entropy and returns the decimal and SHA256 representation of it.
  ///
  /// This number must be less than a constant `(n = 1.158*10^77, which is slightly less than 2^256)`,
  /// in order to be able to derive it from a ECC curve.
  ///
  /// Example:
  /// ```rust
  /// let wallet = Wallet{};
  /// let k = wallet.generate_private_key();
  /// ```
  pub fn generate_private_key(&self) -> (u128, String) {
    let maximum_private_key_value: BigInt =
      BigInt::from(1158u16) * BigInt::from(10u8).pow(74) - 1u8;

    let mut random: StdRng = SeedableRng::from_entropy();
    let random: u128 = random.gen::<u128>();
    let hexadecimal_private_key = digest(random.to_string());

    let hexa_as_bytes = hex::decode(&hexadecimal_private_key).unwrap();
    let hexa_as_bigint = BigInt::from_bytes_be(Sign::Plus, &hexa_as_bytes);

    if hexa_as_bigint > maximum_private_key_value {
      return self.generate_private_key();
    }

    println!("Private Key (k) in decimal format: {}", random);
    println!(
      "Private Key (k) in SHA256 format: {}",
      hexadecimal_private_key
    );

    (random, hexadecimal_private_key)
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
    println!(
      "Ripemd160(SHA256(K)), also known as HASH160: {}",
      ripemd160_hashed
    );
    let hash160_as_vec_u8 = hex::decode(&ripemd160_hashed).unwrap();
    let hash160_as_base32 = convert_bits(8, 5, hash160_as_vec_u8);
    println!("HASH160 in Base32: {:?}", hash160_as_base32);

    // witness version
    let mut witness_version_plus_hash160 = vec![1u8];
    witness_version_plus_hash160.extend_from_slice(&hash160_as_base32);

    let bech32 = Bech32::new(MAIN_NET_BTC.to_owned(), witness_version_plus_hash160);
    match bech32.encode(EncodingType::BECH32M) {
      Ok(encoded) => {
        println!("Bech32m encoded: {}", encoded);
        return encoded;
      }
      Err(error) => {
        eprintln!("{}", error);
        return "".to_owned();
      }
    }
  }

  /// Gets information from a Bech32 (or Bech32m) address.
  ///
  /// Example:
  /// ```rust
  /// let wallet = Wallet{};
  /// let bech32_address = "bc1pddprup5dlqhqtcmu6wnya4tsugngx56seuflu7".to_owned();
  /// let bech32_decoded = wallet.get_info_from_bech32m_address(bech32_address);
  ///
  /// // tests
  /// assert_eq!(bech32_decoded, Ok(Bech32Decoded { hrp: "bc", payload: Payload { witness_version: "1", program: "6b423e068df82e05e37cd3a64ed570e226835350", checksum: "euflu7" } }));
  /// ```
  pub fn get_info_from_bech32m_address(&self, bech32m_address: String) -> Bech32Decoded {
    let bech32m = Bech32::empty();
    match bech32m.decode(bech32m_address) {
      Ok(decoded) => {
        println!("Bech32m decoded: {:?}", decoded);
        return decoded;
      }
      Err(error) => {
        eprintln!("{}", error);
        return Bech32Decoded::empty();
      }
    }
  }

  /// Generating a mnemonic
  ///
  /// (See: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  /// ENT: initial entropy length. 128-256 bits => must be a multiple of 32 bits.
  /// CS: checksum
  /// MS: mnemonic sentence in words
  ///
  /// CS = ENT / 32
  /// MS = (ENT + CS) / 11
  ///
  /// |  ENT  | CS | ENT+CS |  MS  |
  /// +-------+----+--------+------+
  /// |  128  |  4 |   132  |  12  |
  /// |  160  |  5 |   165  |  15  |
  /// |  192  |  6 |   198  |  18  |
  /// |  224  |  7 |   231  |  21  |
  /// |  256  |  8 |   264  |  24  |
  ///
  /// If a passphrase is not used, an empty string is used instead.
  ///
  pub fn generate_mnemonic_from_entropy(&self, entropy: Vec<u8>) -> Vec<String> {
    let entropy_length = entropy.len() * 8;

    if entropy_length < 128 || entropy_length > 256 {
      println!("Error: entropy out of bonds. It must be between 128 and 256.");
      panic!();
    }

    if entropy_length % 32 != 0 {
      println!("Error: it must be multiple of 32 bits.");
      panic!();
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
      println!("Error: initial entropy + checksum must be multiple of 11");
      panic!();
    }

    // group bits in groups of 11
    let mut group: Vec<u16> = Vec::new();
    for bit in (0..entropy.len()).step_by(11) {
      let value: u16 = u16::from_str_radix(&entropy[bit..bit + 11], 2).unwrap();
      group.push(value);
    }

    // read wordlist
    let wordlist: Vec<String> = match read_from_a_file("./src/wordlist/english.txt".to_owned()) {
      Ok(data) => data,
      Err(err) => panic!("{}", err),
    };

    // get mnemonic
    let mut mnemonic: Vec<String> = Vec::new();
    for value in group {
      mnemonic.push(wordlist[value as usize].clone());
    }

    println!("Mnemonic: {:?}", mnemonic);
    mnemonic
  }

  pub fn get_seed_from_mnemonic(&self, mnemonic: Vec<String>, passphrase: Option<String>) -> () {
    // Verify passphrase. If a passphrase is not used, an empty string is used instead.
    let passphrase: String = match passphrase {
      Some(pass) => pass,
      None => "".to_owned(),
    };

    let normalized_mnemonic: Vec<String> = mnemonic.iter().map(|w| w.nfkd().to_string()).collect();
    let stringfied_mnemonic: String = normalized_mnemonic.join(" ");

    let salt = format!("{}{}", MNEMONIC_STRING, passphrase);
    let normalized_salt = salt.nfkd().to_string();

    // uses PBKDF2 function with:
    // password: mnemonic sentence
    // salt: mnemonic+passphrase
    // iteration_count: 2048
    // pseudo-random function: SHA512
    // derived key length: 512 bits (64 bytes)
    get_pbkdf2_sha512(
      stringfied_mnemonic,
      normalized_salt,
      PBKDF2_ITERATION_COUNT,
      PBKDF2_DERIVED_KEY_LENGTH_BYTES,
    );
  }
}

fn get_pbkdf2_sha512(
  password: String,
  salt: String,
  iteration_count: u32,
  derived_key_length_bytes: usize,
) -> String {
  let password = password.as_bytes();
  let salt = Salt::new(&salt).unwrap();
  let params = Params {
    rounds: iteration_count,
    output_length: derived_key_length_bytes,
  };

  // fn hash_password_customized<'a>(
  // &self, password: &[u8],
  // alg_id: Option<Ident<'a>>,
  // version: Option<Decimal>,
  // params: Params,
  // salt: impl Into<Salt<'a>>, ) -> Result<PasswordHash<'a>>
  let hash = Pbkdf2
    .hash_password_customized(
      password,
      Some(Algorithm::Pbkdf2Sha512.ident()),
      None,
      params,
      salt,
    )
    .unwrap();

  println!("Seed: {:?}", hex::encode(hash.hash.unwrap().as_bytes()));

  "".to_owned()
}

fn read_from_a_file(path: String) -> std::io::Result<Vec<String>> {
  let file = File::open(path)?;

  let buf = BufReader::new(file);
  let lines = buf
    .lines()
    .map(|l| l.expect("Could not parse line"))
    .collect();

  Ok(lines)
}
