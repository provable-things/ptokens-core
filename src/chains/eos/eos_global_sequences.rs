use derive_more::{Constructor, Deref, DerefMut};
use serde_json::{json, Value as JsonValue};

use crate::{
    chains::eos::{eos_constants::PROCESSED_TX_IDS_KEY, eos_state::EosState},
    constants::MIN_DATA_SENSITIVITY_LEVEL,
    traits::DatabaseInterface,
    types::{Byte, Bytes, Result},
};

pub type GlobalSequence = u64;

#[derive(Clone, Debug, PartialEq, Eq, Constructor, Deref, DerefMut)]
pub struct GlobalSequences(Vec<GlobalSequence>);

impl GlobalSequences {
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(Self::new(serde_json::from_str::<Vec<u64>>(&s)?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Deref, DerefMut, Constructor)]
pub struct ProcessedGlobalSequences(pub Vec<GlobalSequence>);

impl ProcessedGlobalSequences {
    fn to_bytes(&self) -> Result<Bytes> {
        Ok(serde_json::to_vec(self)?)
    }

    fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn add_multi(mut self, global_sequences: &mut GlobalSequences) -> Self {
        self.append(global_sequences);
        self
    }

    pub fn to_json(&self) -> JsonValue {
        json!({"processed_global_sequences":self.0})
    }

    pub fn get_from_db<D: DatabaseInterface>(db: &D) -> Result<Self> {
        info!("✔ Getting EOS processed actions from db...");
        db.get(PROCESSED_TX_IDS_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
            .and_then(|ref bytes| Self::from_bytes(bytes))
    }

    pub fn put_in_db<D: DatabaseInterface>(&self, db: &D) -> Result<()> {
        info!("✔ Putting EOS processed tx IDs in db...");
        db.put(
            PROCESSED_TX_IDS_KEY.to_vec(),
            self.to_bytes()?,
            MIN_DATA_SENSITIVITY_LEVEL,
        )
    }

    fn remove_multi(mut self, global_sequences: &GlobalSequences) -> Self {
        global_sequences
            .iter()
            .for_each(|global_sequence| self.retain(|item| item != global_sequence));
        self
    }

    pub fn remove_global_sequences_from_list_in_db<D: DatabaseInterface>(
        db: &D,
        global_sequences: &GlobalSequences,
    ) -> Result<()> {
        info!(
            "✔ Removing global sequences: '{:?}' from `ProcessedGlobalSequences` in db...",
            global_sequences
        );
        Self::get_from_db(db)
            .map(|list| list.remove_multi(global_sequences))
            .and_then(|updated_list| updated_list.put_in_db(db))
    }

    pub fn add_global_sequences_to_list_in_db<D: DatabaseInterface>(
        db: &D,
        global_sequences: &mut GlobalSequences,
    ) -> Result<()> {
        info!(
            "✔ Adding global sequence: '{:?}' from `ProcessedGlobalSequences` in db...",
            global_sequences
        );
        Self::get_from_db(db)
            .map(|list| list.add_multi(global_sequences))
            .and_then(|updated_list| updated_list.put_in_db(db))
    }
}

pub fn maybe_add_global_sequences_to_processed_list_and_return_state<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    let mut global_sequences = state.get_global_sequences();
    match global_sequences.len() {
        0 => {
            info!("✔ No `global_sequences` to add to processed tx list!");
            Ok(state)
        },
        _ => {
            info!(
                "✔ Adding '{:?}' to `ProcessedGlobalSequences` in db...",
                global_sequences
            );
            ProcessedGlobalSequences::add_global_sequences_to_list_in_db(&state.db, &mut global_sequences)
                .and(Ok(state))
        },
    }
}

pub fn get_processed_global_sequences_and_add_to_state<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    ProcessedGlobalSequences::get_from_db(&state.db)
        .and_then(|processed_list| state.add_processed_tx_ids(processed_list))
}

#[cfg(test)]
mod teets {
    use super::*;
    use crate::test_utils::get_test_database;

    fn get_sample_processed_global_sequence_list() -> ProcessedGlobalSequences {
        ProcessedGlobalSequences::new(vec![]).add_multi(&mut GlobalSequences::new(vec![1u64, 2u64, 3u64]))
    }

    #[test]
    fn should_make_to_and_from_bytes_roundtrip() {
        let list = get_sample_processed_global_sequence_list();
        let bytes = list.to_bytes().unwrap();
        let result = ProcessedGlobalSequences::from_bytes(&bytes).unwrap();
        assert_eq!(result, list);
    }

    #[test]
    fn should_put_and_get_processed_list_to_and_from_db() {
        let db = get_test_database();
        let list = get_sample_processed_global_sequence_list();
        list.put_in_db(&db).unwrap();
        let result = ProcessedGlobalSequences::get_from_db(&db).unwrap();
        assert_eq!(result, list);
    }

    #[test]
    fn should_add_multi_glob_sequences_to_list() {
        let list = get_sample_processed_global_sequence_list();
        let global_sequence_1 = 1337u64;
        let global_sequence_2 = 1338u64;
        let mut global_sequences = GlobalSequences::new(vec![global_sequence_1, global_sequence_2]);
        let result = list.add_multi(&mut global_sequences);
        assert!(result.contains(&global_sequence_1));
        assert!(result.contains(&global_sequence_2));
    }

    #[test]
    fn should_add_multi_global_sequence_to_list_in_db() {
        let db = get_test_database();
        let list = get_sample_processed_global_sequence_list();
        let global_sequence_1 = 1337u64;
        let global_sequence_2 = 1338u64;
        assert!(!list.contains(&global_sequence_1));
        assert!(!list.contains(&global_sequence_2));
        let mut global_sequences = GlobalSequences::new(vec![global_sequence_1, global_sequence_2]);
        list.put_in_db(&db).unwrap();
        ProcessedGlobalSequences::add_global_sequences_to_list_in_db(&db, &mut global_sequences).unwrap();
        let result = ProcessedGlobalSequences::get_from_db(&db).unwrap();
        assert!(result.contains(&global_sequence_1));
        assert!(result.contains(&global_sequence_2));
    }

    #[test]
    fn should_get_global_sequences_from_json() {
        let json_str = "[1,2,3,4,5]";
        let result = GlobalSequences::from_str(json_str);
        assert!(result.is_ok());
    }

    #[test]
    fn should_remove_multi_global_sequences() {
        let list = get_sample_processed_global_sequence_list();
        let global_sequence_1 = 1u64;
        let global_sequence_2 = 2u64;
        assert!(list.contains(&global_sequence_1));
        assert!(list.contains(&global_sequence_2));
        let global_sequences = GlobalSequences::new(vec![global_sequence_1, global_sequence_2]);
        let result = list.remove_multi(&global_sequences);
        assert!(!result.contains(&global_sequence_1));
        assert!(!result.contains(&global_sequence_2));
    }

    #[test]
    fn should_remove_multi_global_sequences_from_db() {
        let db = get_test_database();
        let list = get_sample_processed_global_sequence_list();
        let global_sequence_1 = 1u64;
        let global_sequence_2 = 2u64;
        assert!(list.contains(&global_sequence_1));
        assert!(list.contains(&global_sequence_2));
        let global_sequences = GlobalSequences::new(vec![global_sequence_1, global_sequence_2]);
        list.put_in_db(&db).unwrap();
        ProcessedGlobalSequences::remove_global_sequences_from_list_in_db(&db, &global_sequences).unwrap();
        let result = ProcessedGlobalSequences::get_from_db(&db).unwrap();
        assert!(!result.contains(&global_sequence_1));
        assert!(!result.contains(&global_sequence_2));
    }
}
