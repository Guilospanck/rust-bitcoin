use crate::helpers;
use serde::{Deserialize, Serialize};

/// Transactions in BTC work like currency inside your wallet.
/// If you have, for example, US$ 2.00 in your wallet and you
/// want to pay for some coffee that costs US$ 2.00, you'd just
/// give away that US$ 2.00 bill.
/// But, if the cost of the coffee was US$ 1.50, you'd give your
/// 2 dollars and expect US$ 0.50 as change. You can't tear apart
/// you 2 dollar bill.
/// That's the same with transactions.
///
/// Outputs (UTXOs) are discrete and indivisible units of value, denominated in
/// integer Satoshis. An UTXO can only be consumed in its entirety by a transaction.
///
/// Fees:
/// Transactions fees are calculated based on the size of the transactions in
/// kilobytes (KB), not on the value of the transaction in BTC. The unit used generally
/// is satoshi/byte.
///
/// BTC Script Language:
/// It uses Stack in order to push, pop and evaluate expressions. And it is evaluated from
/// left to right.
/// In BTC transactions, it combines:
///       Unlocking Script + Locking Script
/// And then evaluates then. If the result is true, the transaction is valid. Otherwise, is not.
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
  version: i32,
  vins: Vec<Vin>,
  vouts: Vec<Vout>,
  locktime: u32,
}

/// Transaction Input (Vin)
/// Gathers all necessary UTXOs in order
/// to make a payment. It's describe as an array.
///
/// - txid: references the transaction in which the UTXO that it's about
///         to be spend was created.
/// - vout: which UTXO from that transaction is going to be used (index).
/// - script_sig: a script that satisfies the conditions placed on the
///         UTXO, unlocking it for spending.
/// - sequence: locktime or disabled.
///
/// Serialization:
/// - 32 bytes (little endian)           | Transaction Hash      | Pointer to the transaction containing the UTXO to be spent
/// - 4 bytes                            | Output Index          | The index number of the UTXO to be spent
/// - 1-9 bytes (VarInt)                 | Unlocking-Script Size | Unlocking-Script size length in bytes
/// - Variable                           | Unlocking-Script      | A script that fulfills the conditions of the UTXO locking script
/// - 4 bytes                            | Sequence Number       | Used for locktime or disabled (0xFFFFFFFF)
///
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Vin {
  pub txid: String,
  pub vout: u32,
  pub script_sig: String, // script sig, witness, unlocking script
  pub sequence: u32,
}

impl Vin {
  pub fn new() -> Self {
    Self {
      txid: Default::default(),
      vout: Default::default(),
      script_sig: Default::default(),
      sequence: Default::default(),
    }
  }

  pub fn serialize(&self) -> String {
    let txid_in_le_bytes_form = helpers::hex_to_le_bytes(self.txid.clone());
    let vout_4_bytes = hex::encode(self.vout.to_be_bytes());

    let script_size_bytes_no_empty_zeroes: Vec<u8> = helpers::get_even_hex_length_bytes(self.script_sig.clone());
    let script_size_hex = hex::encode(script_size_bytes_no_empty_zeroes);

    let sequence_number_4_bytes = hex::encode(self.sequence.to_be_bytes());

    format!(
      "{}{}{}{}{}",
      txid_in_le_bytes_form,
      vout_4_bytes,
      script_size_hex,
      self.script_sig,
      sequence_number_4_bytes,
    )
  }
}

/// Transacion Output (Vout)
/// It's produced in every transaction and will have
/// the amount sent to some address and the change (if any)
/// that will return to the sender. It's described as an array.
///
/// Full nodes track all UTXOs from a set. Every transaction
/// represents a change in the UTXO set.
///
/// - value: value of the UTXO in satoshis (10^-8 BTC)
/// - script_pub_key: defines the necessary conditions to spend the output
///
/// Serialization:
/// - 8 bytes (little-endian) | amount              | BTC value in satoshis
/// - 1-9 bytes (VarInt)      | Locking-Script Size | Locking-Script size in bytes
/// - Variable                | Locking-Script      | Defines the conditions needed to spend the output
///
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Vout {
  pub value: i64,             // in satoshis
  pub script_pub_key: String, // cryptographic puzzle, witness script, locking script
}

impl Vout {
  pub fn new() -> Self {
    Self {
      value: Default::default(),
      script_pub_key: Default::default(),
    }
  }

  pub fn serialize(&self) -> String {
    let amount_bytes_le = hex::encode(self.value.to_le_bytes());

    let script_size_bytes_no_empty_zeroes: Vec<u8> = helpers::get_even_hex_length_bytes(self.script_pub_key.clone());
    let script_size = hex::encode(script_size_bytes_no_empty_zeroes);

    format!("{}{}{}", amount_bytes_le, script_size, self.script_pub_key,)
  }
}
