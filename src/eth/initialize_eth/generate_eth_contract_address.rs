use rlp::RlpStream;
use tiny_keccak::keccak256;
use ethereum_types::Address as EthAddress;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    eth::{
        eth_state::EthState,
        eth_constants::ETH_SMART_CONTRACT_ADDRESS_KEY,
        eth_database_utils::get_public_eth_address_from_db,
    },
};

const INITIAL_NONCE: usize = 0;

fn calculate_contract_address(
    eth_address: EthAddress,
    nonce: usize
) -> EthAddress {
    let mut rlp_stream = RlpStream::new();
    rlp_stream.begin_list(2);
    rlp_stream.append(&eth_address);
    rlp_stream.append(&nonce);
    let encoded = rlp_stream.out();
    let hashed = keccak256(&encoded);
    EthAddress::from_slice(&hashed[12..])
}

fn get_eth_contract_address<D>(db: &D) -> Result<EthAddress>
    where D: DatabaseInterface
{
    get_public_eth_address_from_db(db)
        .and_then(|eth_address| {
            info!("✔ Calculating pBTC contract address...");
            Ok(calculate_contract_address(eth_address, INITIAL_NONCE))
        })
}

pub fn generate_and_store_eth_contract_address<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Calculating pToken contract address...");
    get_eth_contract_address(&state.db)
        .map(|smart_contract_address| {
            info!("✔ Storing pToken contract address in db...");
            &state.db.put(
                ETH_SMART_CONTRACT_ADDRESS_KEY.to_vec(),
                smart_contract_address.as_bytes().to_vec(),
                None,
            );
            state
        })
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::eth::eth_test_utils::get_sample_eth_address;

    #[test]
    fn should_calculate_contract_address() {
        let nonce = 2;
        let eth_address = get_sample_eth_address();
        // NOTE: The actual contract deployed @ this nonce by this test address:
        // https://rinkeby.etherscan.io/address/0xc63b099efb18c8db573981fb64564f1564af4f30
        let expected_result = EthAddress::from_slice(
            &hex::decode("c63b099efB18c8db573981fB64564f1564af4f30").unwrap()
        );
        let result = calculate_contract_address(eth_address, nonce);
        assert!(result == expected_result);
    }
}
