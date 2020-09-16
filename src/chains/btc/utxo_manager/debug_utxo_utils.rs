use crate::{
    types::Result,
    traits::DatabaseInterface,
    check_debug_mode::check_debug_mode,
    chains::btc::utxo_manager::utxo_database_utils::{
        get_all_utxo_db_keys,
        delete_last_utxo_key,
        delete_first_utxo_key,
        put_total_utxo_balance_in_db,
    },
};

pub fn clear_all_utxos<D>(
    db: &D,
) -> Result<String>
    where D: DatabaseInterface
{
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .map(|_| get_all_utxo_db_keys(db).to_vec())
        .and_then(|db_keys| db_keys.iter().map(|db_key| db.delete(db_key.to_vec())).collect::<Result<Vec<()>>>())
        .and_then(|_| delete_last_utxo_key(db))
        .and_then(|_| delete_first_utxo_key(db))
        .and_then(|_| put_total_utxo_balance_in_db(db, 0))
        .and_then(|_| db.end_transaction())
        .map(|_| "{clear_all_utxos_succeeded:true}".to_string())
}
