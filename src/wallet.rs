use crate::bech32;
use crate::bip32;
use crate::bip39;
use crate::helpers::{convert_bits, get_hash160, hmac_sha512_hasher, print_derivation_path};
use hex;
use num_bigint::{BigInt, Sign};
use rand::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha256::digest;
use std::path::PathBuf;
use std::result;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum WalletError {
  #[error("Bech32Error: `{0}`")]
  Bech32Error(String),
  #[error("Bip32Error: `{0}`")]
  Bip32Error(String),
  #[error("Bip39Error: `{0}`")]
  Bip39Error(String),
  #[error("HexDecodeError: `{0}`")]
  HexDecodeError(String),
  #[error("Error: Derivation path must begin with either M or m")]
  DerivationPathMustBeginWithEithermOrM,
  #[error("Error: Path conversion to string returns None")]
  PathConversionToStrReturnsNone,
  #[error("Error: Unknown derivation path")]
  UnknownDerivationPath,
}

impl std::convert::From<bip32::Bip32Error> for WalletError {
  fn from(error: bip32::Bip32Error) -> Self {
    Self::Bip32Error(format!("{}", error))
  }
}

impl std::convert::From<bip39::Bip39Error> for WalletError {
  fn from(error: bip39::Bip39Error) -> Self {
    Self::Bip39Error(format!("{}", error))
  }
}

impl std::convert::From<bech32::Bech32Error> for WalletError {
  fn from(error: bech32::Bech32Error) -> Self {
    Self::Bech32Error(format!("{}", error))
  }
}

impl std::convert::From<hex::FromHexError> for WalletError {
  fn from(error: hex::FromHexError) -> Self {
    Self::HexDecodeError(format!("{}", error))
  }
}

type Result<T> = result::Result<T, WalletError>;

const HMAC_SHA512_KEY: &str = "Bitcoin seed";
const PRIVATE_KEY_DERIVATION_PATH: &str = "m";
const PUBLIC_KEY_DERIVATION_PATH: &str = "M";

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
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Wallet {
  /// Master keys derived from seed
  pub master_keys: MasterKeys,
  /// How many derivations this key is from the master node (master is 0)
  pub depth: u8,
  /// current private key of the depth iteration
  pub current_private_key: Vec<u8>,
  /// current public key of the depth iteration
  pub current_public_key: Vec<u8>,
  /// current chain code of the depth iteration
  pub current_chain_code: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MasterKeys {
  pub private_key: String,
  pub public_key: String,
  pub chain_code: String,
}

impl MasterKeys {
  pub fn new() -> Self {
    MasterKeys {
      private_key: "".to_owned(),
      public_key: "".to_owned(),
      chain_code: "".to_owned(),
    }
  }
}

impl Wallet {
  /// Creates a new wallet structure.
  pub fn new() -> Self {
    let master_keys = MasterKeys::new();
    Wallet {
      master_keys,
      depth: 0,
      current_private_key: Vec::new(),
      current_public_key: Vec::new(),
      current_chain_code: Vec::new(),
    }
  }

  /// Generates a private key from a CSPRNG (cryptographically-secure pseudo-random number
  /// generator) entropy and returns the decimal and SHA256 representation of it.
  ///
  /// This number must be less than a constant `(n = 1.158*10^77, which is slightly less than 2^256)`,
  /// in order to be able to derive it from a ECC curve.
  ///
  /// ---
  /// Example:
  /// ```rust
  /// let wallet = Wallet::new();
  /// let private_key_generated = wallet.generate_private_key();
  /// match private_key_generated {
  ///   Ok((dec_private_key, sha256_dec_private_key)) => ,
  ///   Err(err) => panic!("{}", err),
  /// }
  /// ```
  ///
  pub fn generate_private_key(&self) -> Result<(u128, String)> {
    let maximum_private_key_value: BigInt =
      BigInt::from(1158u16) * BigInt::from(10u8).pow(74) - 1u8;

    let mut random: StdRng = SeedableRng::from_entropy();
    let random: u128 = random.gen::<u128>();
    let hexadecimal_private_key = digest(random.to_string());

    let hexa_as_bytes = hex::decode(&hexadecimal_private_key)?;
    let hexa_as_bigint = BigInt::from_bytes_be(Sign::Plus, &hexa_as_bytes);

    if hexa_as_bigint > maximum_private_key_value {
      return self.generate_private_key();
    }

    println!("Private Key (k) in decimal format: {}", random);
    println!(
      "Private Key (k) in SHA256 format: {}",
      hexadecimal_private_key
    );

    Ok((random, hexadecimal_private_key))
  }

  /// Derives a Public Key (K) from a Private Key (k) using ECC
  /// (Elliptic Curve Cryptography) using the generator parameter
  /// known as `secp256k1`.
  /// The `private_key` argument is the SHA256 representation of it.
  /// Returns a hexadecimal string representing the Public Key.
  ///
  /// ---
  /// Example:
  /// ```rust
  /// let wallet = Wallet::new();
  /// let (_dec_private_key, sha256_dec_private_key) = wallet.generate_private_key();
  /// let K = wallet.get_public_key_from_private_key(hex::decode(&sha256_dec_private_key).unwrap());
  ///
  /// // tests
  /// let k = "e1b4519c66558ec215c55392290afc35f249e113c803bfcadf3b066b4f87d2f3".to_owned();
  /// let K = wallet.get_public_key_from_private_key(hex::decode(&k).unwrap());
  /// assert_eq!(hex::encode(K), "0313e8842189afb5316c3c1acfcca696a85ec3741d17767f953bc70394b3839365".to_owned());
  /// ```
  ///
  pub fn get_public_key_from_private_key(&self, private_key: Vec<u8>) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    public_key.serialize().to_vec()
  }

  /// Generates a Bech32m address from a Public Key (K).
  /// The Public Key must not be hashed before, only in its Hex format.
  /// This function will apply the RIPEMD160(SHA256(K)) to K; get its
  /// Base32 format and then retrieve its representation in Bech32m style
  /// for the Bitcoin mainnet (bc).
  ///
  /// ---
  /// Example:
  /// ```rust
  /// let wallet = Wallet::new();
  /// let k = wallet.generate_private_key();
  /// let K = wallet.get_public_key_from_private_key(k);
  /// let bech32m_address = wallet.generate_bech32m_address_from_public_key(K);
  ///
  /// // tests
  /// let k = "e1b4519c66558ec215c55392290afc35f249e113c803bfcadf3b066b4f87d2f3".to_owned();
  /// let K = wallet.get_public_key_from_private_key(k);
  /// assert_eq!(K, "0313e8842189afb5316c3c1acfcca696a85ec3741d17767f953bc70394b3839365".to_owned());
  /// let bech32m_address = wallet.generate_bech32m_address_from_public_key(K)?;
  /// assert_eq!(Ok(bech32m_address), "bc1phq8vedlv7w3cetla7l3f3xcd8xuw0cvevn0lpw".to_owned()); // witness version 1
  /// ```
  ///
  pub fn generate_bech32m_address_from_public_key(&self, public_key: String) -> Result<String> {
    let ripemd160_hashed = get_hash160(public_key);
    println!(
      "Ripemd160(SHA256(K)), also known as HASH160: {}",
      ripemd160_hashed
    );
    let hash160_as_vec_u8 = hex::decode(&ripemd160_hashed)?;
    let hash160_as_base32 = convert_bits(8, 5, hash160_as_vec_u8);
    println!("HASH160 in Base32: {:?}", hash160_as_base32);

    // witness version
    let mut witness_version_plus_hash160 = vec![1u8];
    witness_version_plus_hash160.extend_from_slice(&hash160_as_base32);

    let bech32 = bech32::Bech32::new(
      bech32::MAIN_NET_BTC.to_owned(),
      witness_version_plus_hash160,
    );
    // Ok(bech32.encode(bech32::EncodingType::BECH32M)?)
    match bech32.encode(bech32::EncodingType::BECH32M) {
      Ok(encoded) => {
        println!("Bech32m encoded: {}", encoded);
        Ok(encoded)
      }
      Err(error) => Err(WalletError::Bech32Error(error.to_string())),
    }
  }

  /// Gets information from a Bech32 (or Bech32m) address.
  ///
  /// Example:
  /// ```rust
  ///
  /// let bech32_address = "bc1phq8vedlv7w3cetla7l3f3xcd8xuw0cvevn0lpw".to_owned();
  /// let expected = Bech32Decoded {
  /// hrp: "bc".to_owned(),
  /// payload: Payload {
  /// witness_version: "1".to_owned(),
  /// program: "b80eccb7ecf3a38caffdf7e2989b0d39b8e7e199".to_owned(),
  /// checksum: "vn0lpw".to_owned(),
  /// },
  /// };
  /// let my_wallet = wallet::Wallet::new();
  ///
  /// let result = my_wallet.get_info_from_bech32m_address(bech32_address);
  ///
  /// assert!(result.is_ok());
  /// assert_eq!(result.unwrap(), expected);
  ///
  /// ```
  ///
  pub fn get_info_from_bech32m_address(
    &self,
    bech32m_address: String,
  ) -> Result<bech32::Bech32Decoded> {
    let bech32m = bech32::Bech32::empty();
    // Ok(bech32m.decode(bech32m_address)?)
    match bech32m.decode(bech32m_address) {
      Ok(decoded) => {
        println!("Bech32m decoded: {:?}", decoded);
        Ok(decoded)
      }
      Err(error) => Err(WalletError::Bech32Error(error.to_string())),
    }
  }

  /// Gets a mnemonic from a vector of bytes (an entropy) using BIP39 rules.
  /// The entropy is anything that has size of 128 - 256 bits, as
  /// a private key, for example - which you can generate
  /// using the `generate_private_key()` method described above.
  ///
  /// ---
  /// Example:
  /// ```rust
  /// let my_wallet = Wallet::new();
  ///
  /// let entropy = [0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0x97, 0xE1, 0x4D, 0x45, 0xF1, 0x4E, 0x1A, 0x1A].to_vec();
  ///
  /// let mnemonic = match my_wallet.get_mnemonic_from_entropy(entropy) {
  ///   Ok(data) => data,
  ///   Err(err) => panic!("{}", err),
  /// };
  ///
  /// assert_eq!(mnemonic, &["army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media", "make", "crunch"].to_vec());
  /// ```
  ///
  pub fn get_mnemonic_from_entropy(&self, entropy: Vec<u8>) -> Result<Vec<String>> {
    Ok(bip39::generate_mnemonic_from_entropy(entropy)?)
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
  /// 
  /// let mnemonic: Vec<_> = vec![
  /// "army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media",
  /// "make", "crunch",
  /// ]
  /// .into_iter()
  /// .map(String::from)
  /// .collect();
  /// let my_wallet = wallet::Wallet::new();
  /// 
  /// let seed = my_wallet.seed_from_mnemonic(mnemonic, None);
  /// 
  /// assert_eq!(
  /// seed,
  /// "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570".to_owned()
  /// );
  /// 
  /// ```
  ///
  pub fn seed_from_mnemonic(&self, mnemonic: Vec<String>, passphrase: Option<String>) -> String {
    bip39::get_seed_from_mnemonic(mnemonic, passphrase)
  }

  /// Derives Master Keys from the Seed.
  /// see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  ///
  /// Child derivation from seed:
  /// ```
  /// From a CSPRNG
  ///     => generate_mnemonic_from_entropy(): Mnemonic
  ///     => get_seed_from_mnemonic: Root Seed (128, 256 or 512 bits)
  ///     => HMAC-SHA512(Root Seed)
  ///         -> Left 256 bits: Master Private Key (m) => get_public_key_from_private_key(m): Master Public Key (M) 264 bits
  ///         -> Right 256 bits: Master Chain Code  
  /// ```
  ///
  /// ---
  /// Example:
  /// ```rust
  /// let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".to_owned();
  /// my_wallet.create_master_keys_from_seed(hex::decode(&seed).unwrap());
  ///
  /// assert_eq!(my_wallet.master_keys, MasterKeys { private_key: "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e", public_key: "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7", chain_code: "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689" });
  /// ```
  ///
  pub fn create_master_keys_from_seed(&mut self, seed: Vec<u8>) -> Result<()> {
    let seed_as_sha512 = hmac_sha512_hasher(HMAC_SHA512_KEY.as_bytes().to_vec(), seed.clone());
    let master_private_key = &seed_as_sha512[..64]; // left half
    let master_private_key_bytes = hex::decode(&master_private_key)?;

    let master_public_key = self.get_public_key_from_private_key(master_private_key_bytes);

    let master_chain_code = &seed_as_sha512[64..]; // right half

    self.master_keys = MasterKeys {
      private_key: master_private_key.to_string(),
      public_key: hex::encode(master_public_key.clone()),
      chain_code: master_chain_code.to_owned(),
    };

    println!(
      "m: {}\nM: {}\nMaster chain code: {}",
      master_private_key, &self.master_keys.public_key, master_chain_code
    );

    // Extended public key
    let extended_public_key = bip32::ExtendedPublicKey {
      chain_code: hex::decode(&master_chain_code)?,
      key: master_public_key,
      depth: 0,
      parent_key_fingerprint: [0x00, 0x00, 0x00, 0x00].to_vec(), // master
      child_number: 0,
    };
    println!("zpub: {}", hex::encode(extended_public_key.encode()));

    // Extended private key
    let extended_private_key = bip32::ExtendedPrivateKey {
      chain_code: hex::decode(&master_chain_code)?,
      key: hex::decode(&master_private_key)?,
      depth: 0,
      parent_key_fingerprint: [0x00, 0x00, 0x00, 0x00].to_vec(), // master
      child_number: 0,
    };
    println!("zprv: {}", hex::encode(extended_private_key.encode()));

    Ok(())
  }

  /// Generates children keys using the derivation path.
  /// ---
  /// Example:
  ///
  /// ```rust
  /// my_wallet.create_master_keys_from_seed(hex::decode(&seed).unwrap());
  /// my_wallet.get_keys_from_derivation_path("m/84'/0'/0'/0/0");
  /// ```
  ///
  pub fn get_keys_from_derivation_path<P>(&mut self, derivation_path: P) -> Result<()>
  where
    P: Into<PathBuf>,
  {
    let mut path = derivation_path.into();

    // removes leading slash, if it exists
    if path.starts_with("/") {
      path = path.strip_prefix("/").unwrap().to_path_buf();
    }

    // verifies if path begins with either "m" or "M", otherwise
    // returns error.
    if !path.starts_with("m") && !path.starts_with("M") {
      return Err(WalletError::DerivationPathMustBeginWithEithermOrM);
    }

    // get path as string
    let path = match path.to_str() {
      Some(stringfied) => stringfied,
      None => return Err(WalletError::PathConversionToStrReturnsNone),
    };

    // get vector of string splitted by slash
    let path: Vec<&str> = path.split('/').collect();
    match path[0] {
      PUBLIC_KEY_DERIVATION_PATH => {
        self.get_child_public_keys_from_derivation_path(path[1..].to_vec())?
      }
      PRIVATE_KEY_DERIVATION_PATH => {
        self.get_child_private_keys_from_derivation_path(path[1..].to_vec())?
      }
      _ => return Err(WalletError::UnknownDerivationPath),
    }

    Ok(())
  }

  fn get_child_private_keys_from_derivation_path(
    &mut self,
    derivation_path_vector: Vec<&str>,
  ) -> Result<()> {
    let parent_private_key_bytes = hex::decode(self.master_keys.private_key.clone())?;
    let parent_public_key_bytes = hex::decode(self.master_keys.public_key.clone())?;
    let parent_chain_code_bytes = hex::decode(self.master_keys.chain_code.clone())?;

    let mut dpath_string = PathBuf::new();
    dpath_string.push(PRIVATE_KEY_DERIVATION_PATH);

    for item in &derivation_path_vector {
      let index = bip32::get_normal_or_hardened_index(item)?;
      print_derivation_path(&mut dpath_string, index);

      let mut curr_prv_key = self.current_private_key.clone();
      let mut curr_chain_code = self.current_chain_code.clone();
      let mut curr_pub_key = self.current_public_key.clone();
      // updates depth
      self.depth += 1;

      if self.depth == 1 {
        // if first level, parent keys are master keys
        curr_prv_key = parent_private_key_bytes.clone();
        curr_chain_code = parent_chain_code_bytes.clone();
        curr_pub_key = parent_public_key_bytes.clone();
      }

      let child_keys = bip32::ckd_private_parent_to_private_child_key(
        curr_prv_key,
        curr_pub_key,
        curr_chain_code,
        index,
        self.depth,
      )?;

      // updates current private key, public key and chain code
      self.current_chain_code = child_keys.child_chain_code;
      self.current_private_key = child_keys.child_private_key.clone();
      self.current_public_key = self.get_public_key_from_private_key(child_keys.child_private_key);

      println!(
        "Child Chain code: {}\nChild Prv Key: {}\nChild Pub Key: {}\nzprv: {}",
        hex::encode(&self.current_chain_code),
        hex::encode(&self.current_private_key),
        hex::encode(&self.current_public_key),
        hex::encode(child_keys.zprv.encode()),
      );

      println!(
        "Child Chain code decoded: {}\nChild Priv Key decoded: {}",
        hex::encode(child_keys.zprv.decode(child_keys.zprv.encode()).chain_code),
        hex::encode(child_keys.zprv.decode(child_keys.zprv.encode()).key),
      );
    }

    Ok(())
  }

  fn get_child_public_keys_from_derivation_path(
    &mut self,
    derivation_path_vector: Vec<&str>,
  ) -> Result<()> {
    let parent_public_key_bytes = hex::decode(self.master_keys.public_key.clone())?;
    let parent_chain_code_bytes = hex::decode(self.master_keys.chain_code.clone())?;

    let mut dpath_string = PathBuf::new();
    dpath_string.push(PUBLIC_KEY_DERIVATION_PATH);

    for item in &derivation_path_vector {
      let index = bip32::get_normal_or_hardened_index(item)?;
      print_derivation_path(&mut dpath_string, index);

      let mut curr_chain_code = self.current_chain_code.clone();
      let mut curr_pub_key = self.current_public_key.clone();

      // updates depth
      self.depth += 1;

      if self.depth == 1 {
        // if first level, parent keys are master keys
        curr_chain_code = parent_chain_code_bytes.clone();
        curr_pub_key = parent_public_key_bytes.clone();
      }

      let child_keys = bip32::ckd_public_parent_to_public_child_key(
        curr_pub_key,
        curr_chain_code,
        index,
        self.depth,
      )?;

      // updates current public key and chain code
      self.current_chain_code = child_keys.child_chain_code;
      self.current_public_key = child_keys.child_public_key;

      println!(
        "Child Chain code: {}\nChild Pub Key: {}\nzpub: {}",
        hex::encode(&self.current_chain_code),
        hex::encode(&self.current_public_key),
        hex::encode(child_keys.zpub.encode())
      );

      println!(
        "Child Chain code decoded: {}\nChild Pub Key decoded: {}",
        hex::encode(child_keys.zpub.decode(child_keys.zpub.encode()).chain_code),
        hex::encode(child_keys.zpub.decode(child_keys.zpub.encode()).key),
      );
    }

    Ok(())
  }
}
