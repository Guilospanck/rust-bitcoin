use serde::{Deserialize, Serialize};
use sha256::digest;

const BLOCKCHAIN_DIFFICULTY: f32 = 1.00;

///
///  Bitcoin’s difficulty level is the estimated number of hashes required to mine a block.
/// 
///  Difficulty Level = Difficulty Target/Current Target.
/// 
///   => Difficulty Target = bits of block header
/// 
/// Note that the Difficulty Target is a hexadecimal notation of the target hash whose mining difficulty is 1.
/// 
/// In contrast, the current target is the target hash of the most recent block of transactions.
/// When the two values are divided, it yields a whole number which is the difficulty level of mining bitcoin

#[derive(Debug, Serialize, Deserialize)]
struct DataToMintBlock {
  previous_block_hash: String,
  transactions: Vec<Transaction>,
  timestamp: Timestamp,
}

fn mint_block(data: DataToMintBlock) -> u32 {
  let stringfied = serde_json::to_string(&data).unwrap();

  let nonce: u32 = 1;
  let hash = digest(&stringfied);

  let mut zeros_count: u32 = 0;

  // for c in stringfied.chars() {
  //   if c != '0' || zeros_count >= BLOCKCHAIN_DIFFICULTY {
  //     break
  //   }
  //   zeros_count = zeros_count+1;    
  // }

  println!("{}", hash);

  1
}

type Account = String;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Transaction {
  from: Account,
  to: Account,
  amount: f32,
}

type Timestamp = String;

#[derive(Debug, Serialize, Deserialize)]
struct Block {
  previous_block_hash: String,
  block_hash: String,
  transactions: Vec<Transaction>,
  timestamp: Timestamp,
  nonce: u32,
}

impl Block {
  fn genesis() -> Self {
    let first_transaction = Transaction {
      from: "COINBASE".to_owned(),
      to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
      amount: 50.0,
    };

    let transactions = vec![first_transaction];
    let previous_block_hash = "0".to_owned();
    let timestamp = "2022-05-31T22:32:00Z".to_owned();

    let data_to_mint = DataToMintBlock {
      previous_block_hash,
      transactions: transactions.clone(),
      timestamp,
    };

    let _minted = mint_block(data_to_mint);

    Block {
      previous_block_hash: "0".to_owned(),
      block_hash: "asdasd".to_owned(),
      transactions,
      timestamp: "2022-05-31T22:32:00Z".to_owned(),
      nonce: 0000000,
    }
  }
}

struct Blockchain {
  blocks: Vec<Block>,
}

impl Blockchain {
  fn add_to_blockchain(&mut self, block: Block) -> () {
    self.blocks.push(block);
  }

  fn get_blockchain_height(self) -> usize {
    self.blocks.len()
  }
}

fn get_genesis_block() -> Block {
  Block::genesis()
}

fn main() {
  let genesis = get_genesis_block();
  println!("\nGenesis => {:?}", genesis);
  let stringfied = serde_json::to_string(&genesis).unwrap();
  println!("\nStringfied => {:?}", stringfied);
}
