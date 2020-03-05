use crate::{
    types::Result,
    traits::DatabaseInterface,
    eth::{
        eth_state::EthState,
        eth_constants::PTOKEN_CONTRACT_TOPICS,
        eth_database_utils::get_eth_smart_contract_address_from_db,
        eth_types::{
            EthLog,
            EthHash,
            EthLogs,
            EthTopics,
            EthAddress,
            EthReceipts,
            EthBlockAndReceipts
        },
    },
};

pub fn log_contains_topic(log: &EthLog, topic: &EthHash) -> bool {
    log
        .topics
        .iter()
        .filter(|log_topic| *log_topic == topic)
        .collect::<Vec<&EthHash>>()
        .len() > 0
}

pub fn logs_contain_topic(logs: &EthLogs, topic: &EthHash) -> bool {
    logs
        .iter()
        .filter(|log| log_contains_topic(log, topic) == true)
        .collect::<Vec<&EthLog>>()
        .len() > 0
}

pub fn log_contains_address(log: &EthLog, address: &EthAddress) -> bool {
    &log.address == address
}

pub fn logs_contain_address(logs: &EthLogs, address: &EthAddress) -> bool {
    logs
        .iter()
        .filter(|log| log_contains_address(log, address) == true)
        .collect::<Vec<&EthLog>>()
        .len() > 0
}

fn filter_receipts_for_address_and_topic(
    receipts: &EthReceipts,
    address: &EthAddress,
    topic: &EthHash,
) -> EthReceipts {
    receipts
        .iter()
        .filter(|receipt| logs_contain_address(&receipt.logs, address))
        .filter(|receipt| logs_contain_topic(&receipt.logs, topic))
        .cloned()
        .collect::<EthReceipts>()
}

fn filter_receipts_for_address_and_topics(
    receipts: &EthReceipts,
    address: &EthAddress,
    eth_topics: &EthTopics,
) -> EthReceipts {
    eth_topics
        .iter()
        .map(|topic|
             filter_receipts_for_address_and_topic(
                &receipts,
                &address,
                &topic,
             )
         )
        .flatten()
        .collect::<EthReceipts>()
}

fn filter_eth_block_and_receipts(
    eth_block_and_receipts: &EthBlockAndReceipts,
    address: &EthAddress,
    eth_topics: &EthTopics,
) -> Result<EthBlockAndReceipts> {
    Ok(
        EthBlockAndReceipts {
            block: eth_block_and_receipts.block.clone(),
            receipts: filter_receipts_for_address_and_topics(
                &eth_block_and_receipts.receipts,
                address,
                eth_topics,
            )
        }
    )
}

pub fn filter_irrelevant_receipts_from_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out non-pToken related receipts...");
    filter_eth_block_and_receipts(
        state.get_eth_block_and_receipts()?,
        &get_eth_smart_contract_address_from_db(&state.db)?,
        &PTOKEN_CONTRACT_TOPICS.to_vec(),
    )
        .and_then(|filtered_block_and_receipts| {
            info!(
                "✔ Receipts filtered, amount remaining: {}",
                filtered_block_and_receipts.receipts.len()
            );
            state.update_eth_block_and_receipts(filtered_block_and_receipts)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::{
        eth_constants::REDEEM_EVENT_TOPIC_HEX,
        eth_test_utils::{
            get_sample_contract_topic,
            get_sample_contract_topics,
            get_sample_contract_address,
            get_sample_log_with_desired_topic,
            get_sample_eth_block_and_receipts,
            get_sample_logs_with_desired_topic,
            get_sample_eth_block_and_receipts_n,
            get_sample_log_with_desired_address,
            get_sample_log_without_desired_topic,
            get_sample_logs_without_desired_topic,
            get_sample_log_without_desired_address,
            get_sample_receipt_with_desired_address,
            get_sample_receipt_without_desired_address
        },
    };

    #[test]
    fn should_return_true_if_log_contains_desired_topic() {
        let log = get_sample_log_with_desired_topic();
        let topic = get_sample_contract_topic();
        let result = log_contains_topic(&log, &topic);
        assert!(result);
    }

    #[test]
    fn should_return_false_if_log_does_not_contain_desired_topic() {
        let log = get_sample_log_without_desired_topic();
        let topic = get_sample_contract_topic();
        let result = log_contains_topic(&log, &topic);
        assert!(!result);
    }

    #[test]
    fn sample_logs_with_desired_topic_should_contain_topic() {
        let logs = get_sample_logs_with_desired_topic();
        let topic = get_sample_contract_topic();
        let result = logs_contain_topic(&logs, &topic);
        assert!(result);
    }

    #[test]
    fn sample_logs_without_desired_topic_should_contain_topic() {
        let logs = get_sample_logs_without_desired_topic();
        let topic = get_sample_contract_topic();
        let result = logs_contain_topic(&logs, &topic);
        assert!(!result);
    }

    #[test]
    fn sample_log_receipt_with_desired_address_should_return_true() {
        let log = get_sample_log_with_desired_address();
        let address = get_sample_contract_address();
        let result = log_contains_address(&log, &address);
        assert!(result);
    }

    #[test]
    fn sample_log_without_desired_address_should_return_false() {
        let log = get_sample_log_without_desired_address();
        let address = get_sample_contract_address();
        let result = log_contains_address(&log, &address);
        assert!(!result);
    }

    #[test]
    fn sample_receipt_with_desired_address_should_return_true() {
        let receipt = get_sample_receipt_with_desired_address();
        let address = get_sample_contract_address();
        let result = logs_contain_address(&receipt.logs, &address);
        assert!(result);
    }

    #[test]
    fn sample_receipt_without_desired_address_should_return_false() {
        let receipt = get_sample_receipt_without_desired_address();
        let address = get_sample_contract_address();
        let result = logs_contain_address(&receipt.logs, &address);
        assert!(!result);
    }

    #[test]
    fn should_filter_receipts_for_topic() {
        let receipts = get_sample_eth_block_and_receipts().receipts;
        let num_receipts_before = receipts.len();
        let topic = get_sample_contract_topic();
        let address = get_sample_contract_address();
        let result = filter_receipts_for_address_and_topic(
            &receipts,
            &address,
            &topic
        );
        let num_receipts_after = result.len();
        assert!(num_receipts_before > num_receipts_after);
        result
            .iter()
            .map(|receipt| assert!(logs_contain_topic(&receipt.logs, &topic)))
            .for_each(drop);
    }

    #[test]
    fn should_filter_eth_block_and_receipts() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        let num_receipts_before = block_and_receipts.receipts.len();
        let address = get_sample_contract_address();
        let topics = get_sample_contract_topics();
        let result = filter_eth_block_and_receipts(
            &block_and_receipts,
            &address,
            &topics,
        ).unwrap();
        let num_receipts_after = result.receipts.len();
        assert!(num_receipts_before > num_receipts_after);
        result
            .receipts
            .iter()
            .map(|receipt| {
                assert!(logs_contain_topic(&receipt.logs, &topics[0]));
                receipt
            })
            .map(|receipt|
                 assert!(logs_contain_address(&receipt.logs, &address))
             )
            .for_each(drop);
    }

    #[test]
    fn should_filter_eth_block_and_receipts_2() {
        let expected_num_receipts_after = 1;
        let block_and_receipts = get_sample_eth_block_and_receipts_n(6)
            .unwrap();
        let num_receipts_before = block_and_receipts.receipts.len();
        let address = EthAddress::from_slice(
            &hex::decode("74630cfbc4066726107a4efe73956e219bbb46ab")
                .unwrap()
        );
        let topics = vec![
            EthHash::from_slice(&hex::decode(REDEEM_EVENT_TOPIC_HEX).unwrap())
        ];
        let result = filter_eth_block_and_receipts(
            &block_and_receipts,
            &address,
            &topics,
        ).unwrap();
        let num_receipts_after = result.receipts.len();
        assert!(num_receipts_before > num_receipts_after);
        assert_eq!(num_receipts_after, expected_num_receipts_after);
        result
            .receipts
            .iter()
            .map(|receipt| {
                assert!(logs_contain_topic(&receipt.logs, &topics[0]));
                receipt
            })
            .map(|receipt|
                 assert!(logs_contain_address(&receipt.logs, &address))
             )
            .for_each(drop);
    }
}
