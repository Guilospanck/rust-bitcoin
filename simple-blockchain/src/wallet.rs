use crate::bech32::{Bech32, Bech32Decoded, EncodingType, MAIN_NET_BTC};
use crate::helpers::{
  convert_bits, get_pbkdf2_sha512, hmac_sha512_hasher, read_from_a_file_to_a_vec_string,
  get_hash160,
};
use hex;
use num_bigint::{BigInt, Sign};
use rand::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha256::digest;
use std::result;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Error, Debug)]
pub enum WalletError {
  #[error("Bech32 Encoding error: `{0}`")]
  Bech32EncodingError(String),
  #[error("Bech32 Decoding error: `{0}`")]
  Bech32DecodingError(String),
  #[error("IO error: `{0}`")]
  IOError(String),
  #[error("Error: entropy out of bonds. It must be between 128 and 256.")]
  EntropyOutOfBonds,
  #[error("Error: entropy must be multiple of 32 bits.")]
  EntropyMustBe32Multiple,
  #[error("Error: initial entropy + checksum must be multiple of 11.")]
  EntropyPlusChecksumMustBe11Multiple,
}

type Result<T> = result::Result<T, WalletError>;

const MNEMONIC_STRING: &str = "mnemonic";
const HMAC_SHA512_KEY: &str = "Bitcoin seed";
const MAINNET_BTC_ZPRV: &[u8] = &[0x04, 0xb2, 0x43, 0x0c];

pub struct ExtendedPrivateKey {
  /// Current chain code
  chain_code: Vec<u8>,
  /// Private key to be extended
  key: Vec<u8>,
  /// How many derivations this key is from the master node (master is 0)
  depth: u8,
  /// Fingerprint of the parent key (0 for master)
  parents_key_fingerprint: Vec<u8>,
  /// Child number of the key used to derive from parent - index. (0 for master)
  child_number: u32
}

impl ExtendedPrivateKey {
  /// Extended private key binary encoding according to BIP 32
  /// https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs#L643
  pub fn encode(&self) -> [u8; 78] {
    let mut ret = [0; 78];

    ret[0..4].copy_from_slice(MAINNET_BTC_ZPRV); // BTC mainnet BIP 84 zprv 0x04b2430c (4 bytes)
    ret[4] = self.depth; // depth (1 byte)
    ret[5..9].copy_from_slice(&self.parents_key_fingerprint); // fingerprint of the parent's key (0x00000000 if master key) (4 bytes)
    ret[9..13].copy_from_slice(&u32::to_be_bytes(self.child_number)); // child number (0x00000000 if master key) (4 bytes)
    ret[13..45].copy_from_slice(&self.chain_code); // chain code  32 bytes
    ret[45] = 0x00; // 1 byte add because of private key
    ret[46..78].copy_from_slice(&self.key); // private key 32 bytes

    ret
  }
}

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
#[derive(Debug, Default)]
pub struct Wallet {
  /// Master keys derived from seed
  master_keys: MasterKeys,
  /// How many derivations this key is from the master node (master is 0)
  depth: u8,
}

#[derive(Debug, Default)]
pub struct MasterKeys {
  private_key: String,
  public_key: String,
  chain_code: String,
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
  pub fn new() -> Self {
    let master_keys = MasterKeys::new();
    Wallet { master_keys, depth: 0 }
  }

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
  ///
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
  ///
  pub fn generate_bech32m_address_from_public_key(&self, public_key: String) -> Result<String> {
    let ripemd160_hashed = get_hash160(public_key);
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
        return Ok(encoded);
      }
      Err(error) => {
        return Err(WalletError::Bech32EncodingError(error.to_string()));
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
  ///
  pub fn get_info_from_bech32m_address(&self, bech32m_address: String) -> Result<Bech32Decoded> {
    let bech32m = Bech32::empty();
    match bech32m.decode(bech32m_address) {
      Ok(decoded) => {
        println!("Bech32m decoded: {:?}", decoded);
        return Ok(decoded);
      }
      Err(error) => {
        return Err(WalletError::Bech32DecodingError(error.to_string()));
      }
    }
  }

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
  /// Example:
  /// ```rust
  /// let my_wallet = wallet::Wallet {};
  ///
  /// let entropy = &[0x0C, 0x1E, 0x24, 0xE5, 0x91, 0x77, 0x79, 0xD2, 0x97, 0xE1, 0x4D, 0x45, 0xF1, 0x4E, 0x1A, 0x1A].to_vec();
  ///
  /// let mnemonic = match my_wallet.generate_mnemonic_from_entropy(entropy) {
  ///   Ok(data) => data,
  ///   Err(err) => panic!("{}", err),
  /// };
  ///
  /// assert_eq!(mnemonic, &["army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media", "make", "crunch"].to_vec());
  /// ```
  ///
  pub fn generate_mnemonic_from_entropy(&self, entropy: Vec<u8>) -> Result<Vec<String>> {
    let entropy_length = entropy.len() * 8;

    if entropy_length < 128 || entropy_length > 256 {
      return Err(WalletError::EntropyOutOfBonds);
    }

    if entropy_length % 32 != 0 {
      return Err(WalletError::EntropyMustBe32Multiple);
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
      return Err(WalletError::EntropyPlusChecksumMustBe11Multiple);
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
        Err(err) => return Err(WalletError::IOError(err.to_string())),
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
  /// Example:
  /// ```rust
  /// let my_wallet = wallet::Wallet {};
  /// let mnemonic: Vec<String> = &["army", "van", "defense", "carry", "jealous", "true", "garbage", "claim", "echo", "media", "make", "crunch"].to_vec();
  ///
  /// let seed = my_wallet.get_seed_from_mnemonic(mnemonic, None);
  ///
  /// assert_eq!(seed, "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570".to_owned());
  /// ```
  pub fn get_seed_from_mnemonic(
    &self,
    mnemonic: Vec<String>,
    passphrase: Option<String>,
  ) -> String {
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

  /// see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  ///
  /// Child derivation from seed:
  /// From a CSPRNG
  ///     => `generate_mnemonic_from_entropy()`: Mnemonic
  ///     => `get_seed_from_mnemonic`: Root Seed (128, 256 or 512 bits)
  ///     => HMAC-SHA512(Root Seed)
  ///         -> Left 256 bits: Master Private Key (m) => `get_public_key_from_private_key(m)`: Master Public Key (M) 264 bits
  ///         -> Right 256 bits: Master Chain Code  
  ///
  /// Then, once you have the m, M and chain code:
  ///
  /// (*) Extending a parent private key to create a child private key:
  ///   (M || Chain Code || Index number) => HMAC-SHA512 => THEN:
  ///         -> Left 256 bits: Child Private Key Index 0 (m0) => `get_public_key_from_private_key(m || m0)`: Child Public Key (M) index 0 264 bits
  ///         -> Right 256 bits: Child Chain Code index 0
  ///
  /// Obs.: a child private key can be used to make a public key and a Bitcoin address. Then, the same child private key
  /// can be used to sign transactions to spend anything paid to that address.
  ///         
  ///    
  pub fn create_master_keys_from_seed(&mut self, seed: Vec<u8>) -> () {
    let seed_as_sha512 = hmac_sha512_hasher(HMAC_SHA512_KEY.as_bytes().to_vec(), seed);
    
    let master_private_key = &seed_as_sha512[..64]; // left half
    let master_private_key_bytes = hex::decode(&master_private_key).unwrap();

    let master_public_key = self.get_public_key_from_private_key(master_private_key_bytes);

    let master_chain_code = &seed_as_sha512[64..]; // right half

    println!(
      "m: {}\nM: {}\nMaster chain code: {}",
      master_private_key,
      hex::encode(master_public_key.clone()),
      master_chain_code
    );

    // Extended private key
    let extended_private_key = ExtendedPrivateKey {
      chain_code: hex::decode(&master_chain_code).unwrap(),
      key: hex::decode(&master_private_key).unwrap(),
      depth: self.depth,
      parents_key_fingerprint: [0x00, 0x00, 0x00, 0x00].to_vec(), // master
      child_number: 0
    };

    println!("zprv: {}", hex::encode(extended_private_key.encode()));

    self.master_keys = MasterKeys {
      private_key: master_private_key.to_string(),
      public_key: hex::encode(master_public_key),
      chain_code: master_chain_code.to_owned(),
    };
  }

  pub fn ckd_private_parent_to_private_child_key(
    &self,
    private_parent_key: Vec<u8>,
    parent_chain_code: Vec<u8>,
    index: u32,
  ) -> () {
    let base: u32 = 2;
    let mut data: Vec<u8> = Vec::new();

    if index < base.pow(31) {
      // normal keys
      let public_key = self.get_public_key_from_private_key(private_parent_key.clone());
      data.append(&mut public_key.clone());
    } else {
      // hardened keys
      data.push(0x00);
      data.append(&mut private_parent_key.clone());
    }
    data.append(&mut index.to_be_bytes().to_vec());

    let l = hmac_sha512_hasher(parent_chain_code, data);
    let left_hmac_sha512 = &l[..64]; // left half
    let left_hmac_sha512 = hex::decode(left_hmac_sha512).unwrap();
    let child_chain_code = &l[64..]; // right half

    let mut sk = secp256k1::SecretKey::from_slice(&left_hmac_sha512).unwrap();
    sk.add_assign(&private_parent_key).unwrap();
    let child_private_key = sk.display_secret().to_string();

    let extended_private_key = ExtendedPrivateKey {
      chain_code: hex::decode(&child_chain_code).unwrap(),
      key: hex::decode(&child_private_key).unwrap(),
      depth: self.depth+1, // TODO: change
      parents_key_fingerprint: self.get_fingerprint(self.master_keys.public_key.clone()),
      child_number: index
    };

    println!(
      "Child Private Key: {}\nChild Main Code: {}",
      sk.display_secret(),
      child_chain_code
    );
    
    println!("zprv: {}", hex::encode(extended_private_key.encode()));
  }

  pub fn ckd_public_parent_to_public_child_key(
    &self,
    public_parent_key: Vec<u8>,
    parent_chain_code: Vec<u8>,
    index: u32,
  ) -> () {
    let base: u32 = 2;

    if index > base.pow(31) {
      // hardened keys
      println!("Error: K -> K is not defined for hardened keys.");
      return;
    }
    let mut data: Vec<u8> = Vec::new();
    data.append(&mut public_parent_key.clone());
    data.append(&mut index.to_be_bytes().to_vec());

    let l = hmac_sha512_hasher(parent_chain_code, data);

    let child_public_key = &l[..64]; // left half
    let child_chain_code = &l[64..]; // right half
  }  

  fn get_fingerprint(&self, public_key: String) -> Vec<u8>{
    let hash160 = get_hash160(public_key);
    hex::decode(&hash160).unwrap()[..4].to_vec() // fingerprint is the first 32 bits
  }
}
