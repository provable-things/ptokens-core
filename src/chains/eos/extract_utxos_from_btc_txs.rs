use crate::{
    chains::btc::{
        btc_database_utils::get_btc_address_from_db,
        btc_types::BtcTransaction,
        btc_utils::get_pay_to_pub_key_hash_script,
        extract_utxos_from_op_return_txs::extract_utxos_from_txs,
        utxo_manager::utxo_types::BtcUtxosAndValues,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn extract_btc_utxo_from_btc_tx<D>(db: &D, signed_txs: &[BtcTransaction]) -> Result<BtcUtxosAndValues>
where
    D: DatabaseInterface,
{
    get_btc_address_from_db(db)
        .and_then(|address| get_pay_to_pub_key_hash_script(&address))
        .map(|target_script| extract_utxos_from_txs(&target_script, signed_txs))
}
