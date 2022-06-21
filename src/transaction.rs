use serde::{Deserialize, Serialize};

pub type Account = String;

/// Transactions in BTC work like currency inside your wallet.
/// If you have, for example, US$ 2.00 in your wallet and you
/// want to pay for some coffee that costs US$ 2.00, you'd just
/// give away that US$ 2.00 bill.
/// But, if the cost of the coffee was US$ 1.50, you'd give your
/// 2 dollars and expect US$ 0.50 as change. You can't tear apart 
/// you 2 dollar bill.
/// That's the same with transactions.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
  pub from: Account,
  pub to: Account,
  pub amount: f32,
}