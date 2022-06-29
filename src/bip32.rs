use crate::helpers::{get_hash160, hmac_sha512_hasher};
use secp256k1::{PublicKey, Secp256k1};
use std::result;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Bip32Error {
  #[error("HexDecodeError: `{0}`")]
  HexDecodeError(String),
  #[error("Secp256k1Error: `{0}`")]
  Secp256k1Error(String),
  #[error("ParseIntError: `{0}`")]
  ParseIntError(String),
  #[error("Error: K -> K is not defined for hardened keys.")]
  PublicKeyNotDefinedForHardenedKeys,
}

impl std::convert::From<hex::FromHexError> for Bip32Error {
  fn from(error: hex::FromHexError) -> Self {
    Self::HexDecodeError(format!("{}", error))
  }
}

impl std::convert::From<secp256k1::Error> for Bip32Error {
  fn from(error: secp256k1::Error) -> Self {
    Self::Secp256k1Error(format!("{}", error))
  }
}

impl std::convert::From<std::num::ParseIntError> for Bip32Error {
  fn from(error: std::num::ParseIntError) -> Self {
    Self::ParseIntError(format!("{}", error))
  }
}

type Result<T> = result::Result<T, Bip32Error>;

/// BIP84 CONSTANTS
const MAINNET_BTC_BIP84_ZPRV: &[u8] = &[0x04, 0xb2, 0x43, 0x0c];
const MAINNET_BTC_BIP84_ZPUB: &[u8] = &[0x04, 0xb2, 0x47, 0x46];

pub struct ChildPrivateKeyChainCodeAndzprv {
  pub child_private_key: Vec<u8>,
  pub child_chain_code: Vec<u8>,
  pub zprv: ExtendedPrivateKey,
}

pub struct ChildPublicKeyChainCodeAndzpub {
  pub child_public_key: Vec<u8>,
  pub child_chain_code: Vec<u8>,
  pub zpub: ExtendedPublicKey,
}

#[derive(Debug)]
pub struct ExtendedPublicKey {
  /// Current chain code
  pub chain_code: Vec<u8>,
  /// Public key to be extended
  pub key: Vec<u8>,
  /// How many derivations this key is from the master node (master is 0)
  pub depth: u8,
  /// Fingerprint of the parent public key (0 for master)
  pub parent_key_fingerprint: Vec<u8>,
  /// Child number of the key used to derive from parent - index. (0 for master)
  pub child_number: u32,
}

impl ExtendedPublicKey {
  /// Extended public key encoding
  pub fn encode(&self) -> [u8; 78] {
    let mut ret = [0; 78];

    ret[0..4].copy_from_slice(MAINNET_BTC_BIP84_ZPUB); // BTC mainnet BIP 84 zprv 0x04b24746 (4 bytes)
    ret[4] = self.depth; // depth (1 byte)
    ret[5..9].copy_from_slice(&self.parent_key_fingerprint); // fingerprint of the parent's public key (0x00000000 if master key) (4 bytes)
    ret[9..13].copy_from_slice(&u32::to_be_bytes(self.child_number)); // child number (0x00000000 if master key) (4 bytes)
    ret[13..45].copy_from_slice(&self.chain_code); // chain code  32 bytes
    ret[45..78].copy_from_slice(&self.key); // public key 33 bytes

    ret
  }

  /// Extended public key decoding
  pub fn decode(&self, data: [u8; 78]) -> Self {
    let depth = data[4];
    let parent_key_fingerprint: Vec<u8> = data[5..9].to_vec();
    let child_number: u32 = u32::from_be_bytes(data[9..13].try_into().unwrap());
    let chain_code: Vec<u8> = data[13..45].to_vec();
    let key: Vec<u8> = data[45..78].to_vec();

    Self {
      depth,
      chain_code,
      child_number,
      key,
      parent_key_fingerprint,
    }
  }
}

#[derive(Debug)]
pub struct ExtendedPrivateKey {
  /// Current chain code
  pub chain_code: Vec<u8>,
  /// Private key to be extended
  pub key: Vec<u8>,
  /// How many derivations this key is from the master node (master is 0)
  pub depth: u8,
  /// Fingerprint of the parent public key (0 for master)
  pub parent_key_fingerprint: Vec<u8>,
  /// Child number of the key used to derive from parent - index. (0 for master)
  pub child_number: u32,
}

impl ExtendedPrivateKey {
  /// Extended private key binary encoding according to BIP 32
  /// https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs#L643
  pub fn encode(&self) -> [u8; 78] {
    let mut ret = [0; 78];

    ret[0..4].copy_from_slice(MAINNET_BTC_BIP84_ZPRV); // BTC mainnet BIP 84 zprv 0x04b2430c (4 bytes)
    ret[4] = self.depth; // depth (1 byte)
    ret[5..9].copy_from_slice(&self.parent_key_fingerprint); // fingerprint of the parent's key (0x00000000 if master key) (4 bytes)
    ret[9..13].copy_from_slice(&u32::to_be_bytes(self.child_number)); // child number (0x00000000 if master key) (4 bytes)
    ret[13..45].copy_from_slice(&self.chain_code); // chain code  32 bytes
    ret[45] = 0x00; // 1 byte add because of private key (k is 32 bytes + this 1 byte = 33 bytes)
    ret[46..78].copy_from_slice(&self.key); // private key 32 bytes

    ret
  }

  /// Extended private key decoding
  pub fn decode(&self, data: [u8; 78]) -> Self {
    let depth = data[4];
    let parent_key_fingerprint: Vec<u8> = data[5..9].to_vec();
    let child_number: u32 = u32::from_be_bytes(data[9..13].try_into().unwrap());
    let chain_code: Vec<u8> = data[13..45].to_vec();
    let key: Vec<u8> = data[46..78].to_vec();

    Self {
      depth,
      chain_code,
      child_number,
      key,
      parent_key_fingerprint,
    }
  }
}

/// Child Key Derivation (CKD): Parent Private Key to Child Private Key.
/// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
///
/// Once you have the m, M and chain code (master keys):
///```
/// If normal key (index < 2^31):
///   - key: parent chain code;
///   - data: (M || Index number)
///   => Then HMAC-SHA512(key, data)
/// If hardened keys (index >= 2^31)
///   - key: parent chain code;
///   - data: (0x00 || m || Index number)
///   => Then HMAC-SHA512(key, data)
/// THEN:
///   - Left 256 bits:
///     => Child Private Key Index 0 (m/0): (left 256 bits + m), where + is a EC group operation.
///   - Right 256 bits: Child Chain Code index 0
///```
/// `Obs.:` a child private key can be used to make a public key and a Bitcoin address. Then, the same child private key
/// can be used to sign transactions to spend anything paid to that address.
///
/// ----
/// `Example:`
///
/// ```rust
/// let master_private_key = "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e".to_owned();
/// let master_chain_code = "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689".to_owned();
/// let master_public_key = "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7".to_owned();
///
/// let master_private_key_bytes = hex::decode(&master_private_key).unwrap();
/// let master_public_key_bytes = hex::decode(&master_public_key).unwrap();
/// let master_chain_code_bytes = hex::decode(&master_chain_code).unwrap();
///
/// // Chain m/0
/// let child_keys = my_wallet.ckd_private_parent_to_private_child_key(
/// master_private_key_bytes, master_public_key_bytes,
/// master_chain_code_bytes, 0, 1);
///
/// assert_eq!(Ok(child_keys.child_private_key), hex::decode("abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e").unwrap());
/// assert_eq!(Ok(child_keys.child_chain_code), hex::decode("f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c").unwrap());
/// assert_eq!(hex::encode(Ok(child_keys.zprv.encode())), "04b2430c01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e");
/// ```
///
pub fn ckd_private_parent_to_private_child_key(
  parent_private_key: Vec<u8>,
  parent_public_key: Vec<u8>,
  parent_chain_code: Vec<u8>,
  index: u32,
  depth: u8,
) -> Result<ChildPrivateKeyChainCodeAndzprv> {
  let base: u32 = 2;
  let mut data: Vec<u8> = Vec::new();

  // gets data information
  if index < base.pow(31) {
    // normal keys
    data.append(&mut parent_public_key.clone());
  } else {
    // hardened keys
    data.push(0x00);
    data.append(&mut parent_private_key.clone());
  }
  data.append(&mut index.to_be_bytes().to_vec());

  // hmac-sha512 using parent chain code as key
  let l = hmac_sha512_hasher(parent_chain_code, data);

  // gets left and right halves of the result
  let left_hmac_sha512 = &l[..64]; // left half
  let left_hmac_sha512 = hex::decode(left_hmac_sha512)?;
  let child_chain_code = &l[64..]; // right half

  // EC group operation to get the child private key
  // child private key = left_hmac_sha512 + parent_private_key
  let mut sk =
    secp256k1::SecretKey::from_slice(&left_hmac_sha512).expect("32 bytes, within curve order");
  sk.add_assign(&parent_private_key)?;
  let child_private_key = sk.display_secret().to_string();

  // gets extended private key
  let extended_private_key = ExtendedPrivateKey {
    chain_code: hex::decode(&child_chain_code)?,
    key: hex::decode(&child_private_key)?,
    depth: depth,
    parent_key_fingerprint: get_fingerprint(hex::encode(&parent_public_key))?,
    child_number: index,
  };

  Ok(ChildPrivateKeyChainCodeAndzprv {
    child_chain_code: hex::decode(child_chain_code)?,
    child_private_key: hex::decode(&child_private_key)?,
    zprv: extended_private_key,
  })
}

/// Child Key Derivation (CKD): Parent Public Key to Child Public Key.
/// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
///
/// Once you have the m, M and chain code (master keys):
///```
/// If normal key (index < 2^31):
///   - key: parent chain code;
///   - data: (M || Index number)
///   => Then HMAC-SHA512(key, data)
/// If hardened keys (index >= 2^31)
///   - returns failure.
/// THEN:
///   - Left 256 bits:
///     => Child Public Key Index 0 (M/0): (left 256 bits + M), where + is a EC group operation.
///   - Right 256 bits: Child Chain Code index 0
///```
///
/// ----
/// `Example:`
///
/// ```rust
/// let master_public_key = "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7".to_owned();
/// let master_chain_code = "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689".to_owned();
///
/// let master_public_key_bytes = hex::decode(&master_public_key).unwrap();
/// let master_chain_code_bytes = hex::decode(&master_chain_code).unwrap();
///
/// // Chain M/0
/// let child_keys = my_wallet.ckd_public_parent_to_public_child_key(master_public_key_bytes, master_chain_code_bytes, 0, 1);
///
/// assert_eq!(hex::encode(Ok(child_keys.child_public_key)), "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea");
/// assert_eq!(hex::encode(Ok(child_keys.child_chain_code)), "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c");
/// assert_eq!(hex::encode(Ok(child_keys.zpub.encode())), "04b2474601bd16bee50000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968902fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea");
/// ```
///
pub fn ckd_public_parent_to_public_child_key(
  public_parent_key: Vec<u8>,
  parent_chain_code: Vec<u8>,
  index: u32,
  depth: u8,
) -> Result<ChildPublicKeyChainCodeAndzpub> {
  let base: u32 = 2;

  if index >= base.pow(31) {
    return Err(Bip32Error::PublicKeyNotDefinedForHardenedKeys);
  }

  // gets data
  let mut data: Vec<u8> = Vec::new();
  data.append(&mut public_parent_key.clone());
  data.append(&mut index.to_be_bytes().to_vec());

  // hmac-sha512 using parent chain code as key
  let l = hmac_sha512_hasher(parent_chain_code.clone(), data);

  let left_hmac_sha512 = &l[..64]; // left half
  let left_hmac_sha512 = hex::decode(&left_hmac_sha512)?;
  let child_chain_code = &l[64..]; // right half

  // EC group operation to get the child public key
  // child public key = left_hmac_sha512 + parent_public_key
  // Gets left 256 bits of the HMAC-SHA512 as Public Key
  let secp = Secp256k1::new();
  let sk = secp256k1::SecretKey::from_slice(&left_hmac_sha512).expect("32 bytes, within curve order");
  let mut child_public_key = PublicKey::from_secret_key(&secp, &sk);

  // Get the parent public key as Public Key (Struct from secp256k1 lib)
  let parent_public_key_as_pk = PublicKey::from_slice(&public_parent_key)?;

  // combine (+) the two public keys
  child_public_key = child_public_key.combine(&parent_public_key_as_pk)?;

  // Extended public key
  let extended_public_key = ExtendedPublicKey {
    chain_code: parent_chain_code,
    key: child_public_key.clone().serialize().to_vec(),
    depth: depth,
    parent_key_fingerprint: get_fingerprint(hex::encode(&public_parent_key))?,
    child_number: index,
  };

  Ok(ChildPublicKeyChainCodeAndzpub {
    child_chain_code: hex::decode(child_chain_code)?,
    child_public_key: child_public_key.clone().serialize().to_vec(),
    zpub: extended_public_key,
  })
}

/// Gets the index in u32 format. Remember:
/// - Normal keys: index < 2^31
/// - Hardened keys: index >= 2^31
///
/// ---
/// Example:
/// ```rust
/// let index = get_normal_or_hardened_index("84'"); // hardened
/// assert_eq!(Ok(index), 2_147_483_732u32); // 2^31 + 84
/// ```
///  
pub fn get_normal_or_hardened_index(index: &str) -> Result<u32> {
  if index.contains("'") {
    let index: Vec<&str> = index.split("'").collect();
    let u32_index = index[0].parse::<u32>()?;
    let base: u32 = 2;
    return Ok(base.pow(31) + u32_index);
  }
  Ok(index.parse::<u32>()?)
}

/// Gets the Fingerprint of the public key. It accepts a hex encoded public key.
///
/// The Fingerprint is defined as the first 32 bits of the `HASH160(public_key)` result.
///
/// ---
/// Example:
/// ```rust  ///
/// let public_key = "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7".to_owned();
/// let fingerprint = my_wallet.get_fingerprint(public_key);
///
/// assert_eq!(Ok(fingerprint), [189, 22, 190, 229]);
/// ```
///
fn get_fingerprint(public_key: String) -> Result<Vec<u8>> {
  let hash160 = get_hash160(public_key);
  let hash_bytes = hex::decode(&hash160)?;
  Ok(hash_bytes[..4].to_vec()) // fingerprint is the first 32 bits
}
