use num::bigint::{BigInt, Sign};
use rand::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha256::digest;
use hex::decode;

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
/// ```
///

pub fn generate_private_key() -> String {
  let mut random: StdRng = SeedableRng::from_entropy();
  let random: u128 = random.gen::<u128>();
  println!("Private dec: {}", random);
  let hexadecimal_private_key = digest(random.to_string());
  println!("Private hex: {}", hexadecimal_private_key);

  hexadecimal_private_key  
}

pub fn get_public_key_from_private_key(private_key: String) {
  let private_key_bytes = hex::decode(private_key).unwrap();
  let secp = Secp256k1::new();
  let secret_key =
    SecretKey::from_slice(&private_key_bytes).expect("32 bytes, within curve order");
  let public_key = PublicKey::from_secret_key(&secp, &secret_key);
  println!("Public: {}", public_key);
}
