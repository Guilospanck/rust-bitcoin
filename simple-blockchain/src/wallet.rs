use crate::bech32::{Bech32, Bech32Decoded, EncodingType, MAIN_NET_BTC};
use crate::helpers::{convert_bits, ripemd160_hasher};
use hex;
use num_bigint::{BigInt, Sign};
use rand::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha256::digest;

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
      },
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
}
