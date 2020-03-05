use ethereum_types::U256;
use rlp::{
    RlpStream,
    Encodable,
};
use crate::{
    types::{
        Bytes,
        Result,
    },
    eth::{
        nibble_utils::{
            Nibbles,
            get_nibbles_from_bytes,
        },
        eth_types::{
            EthLog,
            EthBlock,
            EthReceipt,
            EthReceipts,
        },
    },
};

impl Encodable for EthReceipt {
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        let rlp = rlp_stream.begin_list(4);
        match &self.status {
            true => rlp.append(&self.status),
            false => rlp.append_empty_data()
        };
        rlp
            .append(&self.cumulative_gas_used)
            .append(&self.logs_bloom)
            .append_list(&self.logs);
    }
}

impl Encodable for EthLog {
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        rlp_stream
            .begin_list(3)
            .append(&self.address)
            .append_list(&self.topics)
            .append(&self.data);
    }
}

impl Encodable for EthBlock {
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        rlp_stream
            .begin_list(15)
            .append(&self.parent_hash)
            .append(&self.sha3_uncles)
            .append(&self.miner)
            .append(&self.state_root)
            .append(&self.transactions_root)
            .append(&self.receipts_root)
            .append(&self.logs_bloom)
            .append(&self.difficulty)
            .append(&self.number)
            .append(&self.gas_limit)
            .append(&self.gas_used)
            .append(&self.timestamp)
            .append(&self.extra_data)
            .append(&self.mix_hash)
            .append(&self.nonce);
    }
}

pub fn rlp_encode_block(block: &EthBlock) -> Result<Bytes> {
    let mut rlp_stream = RlpStream::new();
    rlp_stream.append(block);
    Ok(rlp_stream.out())
}

pub fn rlp_encode_receipt(receipt: &EthReceipt) -> Result<Bytes> {
    let mut rlp_stream = RlpStream::new();
    rlp_stream.append(receipt);
    Ok(rlp_stream.out())
}

pub fn rlp_encode_transaction_index(index: &U256) -> Result<Bytes> {
    let mut rlp_stream = RlpStream::new();
    rlp_stream.append(&index.as_usize());
    Ok(rlp_stream.out())
}

pub fn get_rlp_encoded_receipt_and_encoded_key_tuple(
    receipt: &EthReceipt,
) -> Result<(Nibbles, Bytes)> {
    rlp_encode_receipt(&receipt)
        .and_then(|rlp_encoded_receipt|
            Ok(
                (
                    get_nibbles_from_bytes(
                        rlp_encode_transaction_index(&receipt.transaction_index)?
                    ),
                    rlp_encoded_receipt,
                )
            )
        )
}

pub fn get_rlp_encoded_receipts_and_nibble_tuples(
    receipts: &EthReceipts
) -> Result<Vec<(Nibbles, Bytes)>> {
    receipts
        .iter()
        .map(|receipt| get_rlp_encoded_receipt_and_encoded_key_tuple(&receipt))
        .collect::<Result<Vec<(Nibbles, Bytes)>>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::eth_test_utils::{
        get_expected_receipt,
        get_sample_eth_block_and_receipts,
    };

    fn get_expected_receipt_nibbles() -> Nibbles {
        get_nibbles_from_bytes(vec![0x02]) // NOTE: The tx index of sample receipt
    }

    fn get_logs_bloom() -> String {
           "10040060000810a000180002060000042000328000101012000204800010010000412401000100080012600209a005001200048a0c048008413ca08d8021414000000012002200004880b408400810408000040401c0005000018009804b000480020000122004003200004004080920080020058081444000080a9000a000004080000041100202000000004006040080a80001a12000100000400020340050020080040200200008000082104010040080010481020080000220000124051640075007890200000040c420000820400020800028420018000800020000208080322000000a200008a002000000800101044000000920418600200666900601".to_string()
    }

    fn get_rlp_encoded_receipt() -> Bytes {
        vec![249, 1, 167, 1, 131, 1, 56, 75, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 248, 157, 248, 155, 148, 96, 166, 64, 226, 209, 14, 2, 15, 238, 148, 33, 119, 7, 191, 169, 84, 60, 139, 89, 224, 248, 99, 160, 221, 242, 82, 173, 27, 226, 200, 155, 105, 194, 176, 104, 252, 55, 141, 170, 149, 43, 167, 241, 99, 196, 161, 22, 40, 245, 90, 77, 245, 35, 179, 239, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 37, 10, 191, 168, 188, 131, 113, 112, 159, 164, 182, 1, 216, 33, 177, 66, 22, 103, 168, 134, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, 125, 214, 137, 7, 225, 3, 195, 35, 148, 17, 218, 224, 176, 238, 249, 104, 70, 142, 242, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 137, 186, 122, 177, 116, 213, 64, 0]
    }

    fn get_rlp_encoded_block() -> Bytes {
        vec![249, 2, 26, 160, 38, 233, 147, 13, 175, 175, 7, 245, 155, 108, 143, 226, 150, 56, 25, 183, 217, 49, 154, 212, 255, 85, 108, 177, 46, 239, 186, 13, 189, 58, 243, 251, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 90, 11, 84, 213, 220, 23, 224, 170, 220, 56, 61, 45, 180, 59, 10, 13, 62, 2, 156, 76, 160, 6, 29, 1, 221, 85, 42, 53, 56, 179, 234, 223, 98, 52, 56, 42, 235, 39, 205, 128, 205, 92, 216, 139, 56, 37, 253, 105, 144, 253, 118, 40, 36, 160, 152, 144, 129, 234, 146, 19, 186, 189, 142, 130, 185, 155, 87, 155, 48, 18, 195, 211, 52, 52, 180, 32, 195, 249, 122, 240, 233, 246, 248, 184, 224, 71, 160, 147, 126, 8, 240, 51, 136, 179, 45, 124, 119, 110, 122, 2, 55, 27, 147, 13, 113, 227, 236, 9, 109, 73, 82, 48, 182, 115, 94, 127, 155, 32, 174, 185, 1, 0, 16, 4, 0, 96, 0, 8, 16, 160, 0, 24, 0, 2, 6, 0, 0, 4, 32, 0, 50, 128, 0, 16, 16, 18, 0, 2, 4, 128, 0, 16, 1, 0, 0, 65, 36, 1, 0, 1, 0, 8, 0, 18, 96, 2, 9, 160, 5, 0, 18, 0, 4, 138, 12, 4, 128, 8, 65, 60, 160, 141, 128, 33, 65, 64, 0, 0, 0, 18, 0, 34, 0, 0, 72, 128, 180, 8, 64, 8, 16, 64, 128, 0, 4, 4, 1, 192, 0, 80, 0, 1, 128, 9, 128, 75, 0, 4, 128, 2, 0, 0, 18, 32, 4, 0, 50, 0, 0, 64, 4, 8, 9, 32, 8, 0, 32, 5, 128, 129, 68, 64, 0, 8, 10, 144, 0, 160, 0, 0, 64, 128, 0, 0, 65, 16, 2, 2, 0, 0, 0, 0, 64, 6, 4, 0, 128, 168, 0, 1, 161, 32, 0, 16, 0, 0, 64, 0, 32, 52, 0, 80, 2, 0, 128, 4, 2, 0, 32, 0, 8, 0, 0, 130, 16, 64, 16, 4, 0, 128, 1, 4, 129, 2, 0, 128, 0, 2, 32, 0, 1, 36, 5, 22, 64, 7, 80, 7, 137, 2, 0, 0, 0, 64, 196, 32, 0, 8, 32, 64, 0, 32, 128, 0, 40, 66, 0, 24, 0, 8, 0, 2, 0, 0, 32, 128, 128, 50, 32, 0, 0, 10, 32, 0, 8, 160, 2, 0, 0, 0, 128, 1, 1, 4, 64, 0, 0, 9, 32, 65, 134, 0, 32, 6, 102, 144, 6, 1, 135, 8, 19, 102, 247, 231, 84, 220, 131, 129, 193, 252, 131, 122, 33, 57, 131, 121, 239, 81, 132, 93, 115, 211, 138, 153, 80, 80, 89, 69, 32, 115, 112, 97, 114, 107, 112, 111, 111, 108, 45, 101, 116, 104, 45, 99, 110, 45, 104, 122, 51, 160, 179, 161, 212, 118, 185, 99, 42, 57, 223, 46, 221, 49, 22, 105, 33, 101, 167, 188, 54, 59, 127, 86, 71, 192, 105, 245, 75, 103, 12, 213, 100, 174, 136, 159, 109, 120, 128, 5, 164, 80, 237]
    }

    #[test]
    fn should_rlp_encode_receipt() {
        let result = rlp_encode_receipt(&get_expected_receipt())
            .unwrap();
        assert!(result == get_rlp_encoded_receipt())
    }

    #[test]
    fn should_rlp_encode_block() {
        let block = get_sample_eth_block_and_receipts().block;
        let result = rlp_encode_block(&block)
            .unwrap();
        let expected_result = get_rlp_encoded_block();
        assert!(get_logs_bloom() == hex::encode(block.logs_bloom));
        assert!(result == expected_result);
    }

    #[test]
    fn should_get_encoded_receipt_and_hash_tuple() {
        let result = get_rlp_encoded_receipt_and_encoded_key_tuple(
            &get_expected_receipt()
        ).unwrap();
        assert!(result.0 == get_expected_receipt_nibbles());
        assert!(result.1 == get_rlp_encoded_receipt());
    }

    #[test]
    fn should_get_encoded_receipts_and_hash_tuples() {
        let receipts = vec![
            get_expected_receipt(),
            get_expected_receipt(),
        ];
        let results = get_rlp_encoded_receipts_and_nibble_tuples(&receipts)
            .unwrap();
        results
            .iter()
            .map(|result| {
                assert!(result.0 == get_expected_receipt_nibbles());
                assert!(result.1 == get_rlp_encoded_receipt());
            })
            .for_each(drop);
    }

    #[test]
    fn should_encode_tx_receipt() {
        let index_u256 = U256::from_dec_str("3").unwrap();
        let result = rlp_encode_transaction_index(&index_u256).unwrap();
        let expected_result = vec![0x03];
        assert!(result == expected_result);
    }

    #[test]
    fn should_encode_tx_receipt_of_0() {
        let index_u256 = U256::from_dec_str("0").unwrap();
        let result = rlp_encode_transaction_index(&index_u256).unwrap();
        let expected_result = vec![0x80];
        assert!(result == expected_result);
    }
}
