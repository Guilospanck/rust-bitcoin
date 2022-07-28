use crate::helpers;
use serde::{Deserialize, Serialize};

// VIN constants
pub const VIN_TRANSACTION_HASH_LENGTH_HEX: usize = 64; // 32 bytes
pub const VIN_VOUT_LENGTH_IN_HEX: usize = 8; // 4 bytes
pub const VIN_SEQUENCE_NUMBER_LENGTH_IN_HEX: usize = 8; // 4 bytes

// Vout constants
pub const VOUT_AMOUNT_LENGTH_IN_HEX: usize = 16; // 8 bytes

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
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Transaction {
  pub version: i32,
  pub vins: Vec<Vin>,
  pub vouts: Vec<Vout>,
  pub locktime: u32,
}

impl Transaction {
  pub fn new() -> Self {
    Self { version: Default::default(), vins: Default::default(), vouts: Default::default(), locktime: Default::default() }
  }

  /// Serializes a transaction.
  /// 
  /// ### Example:
  /// 
  /// ```rust
  /// let mut vin = btc::transaction::Vin::new();
  /// vin.txid = "7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18".to_owned();
  /// vin.vout = 0;
  /// vin.script_sig = "483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf".to_owned();
  /// vin.sequence = 4294967295;

  /// let mut vout = btc::transaction::Vout::new();
  /// vout.value = 1_500_000; // in satoshis
  /// vout.script_pub_key = "76a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac".to_owned();

  /// let mut sec_vout = btc::transaction::Vout::new();
  /// sec_vout.value = 8_450_000; // in satoshis
  /// sec_vout.script_pub_key = "76a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac".to_owned();

  /// let mut transaction_test = btc::transaction::Transaction::new();
  /// transaction_test.version = 1i32;
  /// transaction_test.vins = vec![vin];
  /// transaction_test.vouts = vec![vout, sec_vout];
  /// transaction_test.locktime = 0u32;

  /// let serialized_tx = transaction_test.serialize();
  /// let expected_serialized_tx = "0100000001186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd734d2804fe65fa35779000000008b483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adfffffffff0260e31600000000001976a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788acd0ef8000000000001976a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac00000000".to_owned();
  /// 
  /// assert_eq!(serialized_tx, expected_serialized_tx);
  /// ```
  /// 
  /// ### Docs:
  /// |                                    Value                                   |      Meaning      |
  /// | -------------------------------------------------------------------------- | ----------------- |
  /// |                                  01000000                                  |       version     |
  /// |                                  --                                        |      --           |
  /// |                                  01                                        |   number of vins  |
  /// |   186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd734d2804fe65fa35779         |    txid           |
  /// |                                  00000000                                        |    vout index     |
  /// |                                  8b                                        |    script_sig size (hex of bytes)     |
  /// | 483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb
  ///   6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863
  ///   ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a
  ///   0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41
  ///    c04f4938de5cc17b4a10fa336a8d752adf                                        |    script_sig     |
  /// |                                  ffffffff                                        |    sequence     |
  /// |                                  --                                        |      --   |
  /// |                                  02                                        |    number of vouts     |
  /// |                                  60e3160000000000                                        |    first vout amount in hex little endian (1_500_000)     |
  /// |                                  19                                        |    script pub key size in hex = 25 bytes    |
  /// |     76a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac                                        |    script pub key     |
  /// |                                  d0ef800000000000                                        |    second vout amount in hex little endian (8_450_000)     |
  /// |                                  19                                        |    script pub key size in hex = 25 bytes    |
  /// |     76a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac                                        |    script pub key     |
  /// |                                  --                                        |      --   |
  /// |     00000000                                        |    locktime     |
  ///
  pub fn serialize(&self) -> String {
    let version_serialized = hex::encode(self.version.to_le_bytes());

    let vins_length = format!("{:02x}", self.vins.len());

    let mut vins_serialized = String::new();
    for vin in &self.vins {
      vins_serialized.push_str(&vin.serialize());
    }

    let vouts_length = format!("{:02x}", self.vouts.len());

    let mut vouts_serialized = String::new();
    for vout in &self.vouts {
      vouts_serialized.push_str(&vout.serialize());
    }

    let locktime_serialized = hex::encode(self.locktime.to_le_bytes());

    format!("{}{}{}{}{}{}",
      version_serialized,
      vins_length,
      vins_serialized,
      vouts_length,
      vouts_serialized,
      locktime_serialized,
    )
  }
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
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
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

  /// Serializes a Vin.
  ///
  /// ```rust
  /// let mut vin = btc::transaction::Vin::new();
  /// vin.txid = "7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18".to_owned();
  /// vin.vout = 0;
  /// vin.script_sig = "483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf".to_owned();
  /// vin.sequence = 4294967295;
  ///
  /// let serialized = vin.serialize();
  /// let expected = "186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd734d2804fe65fa35779000000008b483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adfffffffff".to_owned();
  /// assert_eq!(serialized, expected);
  /// ```
  ///
  pub fn serialize(&self) -> String {
    let txid_in_le_bytes_form = helpers::hex_to_reverse_bytes(self.txid.clone());
    let vout_4_bytes = hex::encode(self.vout.to_be_bytes());

    let script_size_bytes_no_empty_zeroes: Vec<u8> =
      helpers::get_even_hex_length_bytes(self.script_sig.clone());
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

  /// Deserializes a vin.
  ///
  /// ```rust
  /// let mut vin_expected = btc::transaction::Vin::new();
  /// vin_expected.txid = "7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18".to_owned();
  /// vin_expected.vout = 0;
  /// vin_expected.script_sig = "483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf".to_owned();
  /// vin_expected.sequence = 4294967295;
  ///
  /// let vin = btc::transaction::Vin::new();
  /// let serialized = "186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd734d2804fe65fa35779000000008b483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adfffffffff".to_owned();
  /// let deserialized = vin.deserialize(serialized);
  ///
  /// assert_eq!(deserialized, vin_expected);
  ///
  /// ```
  pub fn deserialize(&self, serialized_vin: String) -> Self {
    let serialized_vin_length = serialized_vin.len();
    let serialized_vin_without_sequence_number_length =
      serialized_vin_length - VIN_SEQUENCE_NUMBER_LENGTH_IN_HEX;

    let transaction =
      helpers::hex_to_reverse_bytes(serialized_vin[..VIN_TRANSACTION_HASH_LENGTH_HEX].to_owned());

    let vout: [u8; 4] = hex::decode(
      &serialized_vin[VIN_TRANSACTION_HASH_LENGTH_HEX
        ..(VIN_TRANSACTION_HASH_LENGTH_HEX + VIN_VOUT_LENGTH_IN_HEX)],
    )
    .unwrap()
    .try_into()
    .unwrap();
    let vout = u32::from_be_bytes(vout);

    let index = helpers::get_length_of_script_vin_or_vout(
      serialized_vin[..serialized_vin_without_sequence_number_length].to_owned(),
      helpers::TransactionType::Vin,
    );
    let script_sig = serialized_vin[(VIN_TRANSACTION_HASH_LENGTH_HEX
      + VIN_VOUT_LENGTH_IN_HEX
      + index)..serialized_vin_without_sequence_number_length]
      .to_owned();

    let sequence_number =
      serialized_vin[serialized_vin_without_sequence_number_length..].to_owned();
    let sequence_number: [u8; 4] = hex::decode(&sequence_number).unwrap().try_into().unwrap();
    let sequence_number: u32 = u32::from_be_bytes(sequence_number);

    Self {
      txid: transaction,
      vout,
      script_sig,
      sequence: sequence_number,
    }
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
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct Vout {
  pub value: u64,             // in satoshis
  pub script_pub_key: String, // cryptographic puzzle, witness script, locking script
}

impl Vout {
  pub fn new() -> Self {
    Self {
      value: Default::default(),
      script_pub_key: Default::default(),
    }
  }

  /// Vout serializer.
  ///
  /// Example:
  /// ```rust
  /// let mut vout = btc::transaction::Vout::new();
  /// vout.value = 1_500_000; // in satoshis
  /// vout.script_pub_key = "76a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac".to_owned();
  ///
  /// let serialized = vout.serialize();
  /// let expected = "60e31600000000001976a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac".to_owned();
  ///
  /// assert_eq!(serialized, expected);
  /// ```
  ///
  pub fn serialize(&self) -> String {
    let amount_bytes_le = hex::encode(self.value.to_le_bytes());

    let script_size_bytes_no_empty_zeroes: Vec<u8> =
      helpers::get_even_hex_length_bytes(self.script_pub_key.clone());
    let script_size = hex::encode(script_size_bytes_no_empty_zeroes);

    format!("{}{}{}", amount_bytes_le, script_size, self.script_pub_key,)
  }

  /// Vout deserializer.
  ///
  /// Example:
  /// ```rust
  /// let mut vout_expected = btc::transaction::Vout::new();
  /// vout_expected.value = 1_500_000; // in satoshis
  /// vout_expected.script_pub_key = "76a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac".to_owned();
  ///
  /// let serialized = "60e31600000000001976a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788ac".to_owned();
  /// let vout = btc::transaction::Vout::new();
  /// let deserialized = vout.deserialize(serialized);
  ///
  /// assert_eq!(deserialized, vout_expected);
  /// ```
  ///
  pub fn deserialize(&self, serialized_vout: String) -> Self {
    let amount_little_endian = serialized_vout[..VOUT_AMOUNT_LENGTH_IN_HEX].to_owned(); // first 8 bytes
    let amount_bytes: [u8; 8] = hex::decode(&amount_little_endian)
      .unwrap()
      .try_into()
      .unwrap();
    let amount = u64::from_le_bytes(amount_bytes);

    let index = helpers::get_length_of_script_vin_or_vout(
      serialized_vout.clone(),
      helpers::TransactionType::Vout,
    );

    let script_pub_key = serialized_vout[(VOUT_AMOUNT_LENGTH_IN_HEX + index)..].to_owned();

    Self {
      value: amount,
      script_pub_key,
    }
  }
}
