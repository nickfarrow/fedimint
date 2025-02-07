pub mod bitcoind;
pub mod fixtures;

use async_trait::async_trait;
use bitcoin::{Address, Transaction};
use fedimint_api::Amount;
use fedimint_wallet::txoproof::TxOutProof;

#[async_trait]
pub trait BitcoinTest {
    /// Make the underlying instance act as if it was exclusively available
    /// for the existance of the returned guard.
    async fn lock_exclusive(&self) -> Box<dyn BitcoinTest>;

    /// Mines a given number of blocks
    async fn mine_blocks(&self, block_num: u64);

    /// Send some bitcoin to an address then mine a block to confirm it.
    /// Returns the proof that the transaction occurred.
    async fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction);

    /// Returns a new address.
    async fn get_new_address(&self) -> Address;

    /// Mine a block to include any pending transactions then get the amount received to an address
    async fn mine_block_and_get_received(&self, address: &Address) -> Amount;
}
