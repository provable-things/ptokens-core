use rlp::RlpStream;
use tiny_keccak::keccak256;
use ethereum_types::Address as EthAddress;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::{
        eth_state::EthState,
        eth_database_utils::{
            get_public_eth_address_from_db,
            put_btc_on_eth_smart_contract_address_in_db,
            put_erc20_on_eos_smart_contract_address_in_db,
        },
    },
};

const INITIAL_NONCE: usize = 0;

fn calculate_contract_address(eth_address: EthAddress, nonce: usize) -> EthAddress {
    let mut rlp_stream = RlpStream::new();
    rlp_stream.begin_list(2);
    rlp_stream.append(&eth_address);
    rlp_stream.append(&nonce);
    let encoded = rlp_stream.out();
    let hashed = keccak256(&encoded);
    EthAddress::from_slice(&hashed[12..])
}

fn get_eth_contract_address<D>(db: &D) -> Result<EthAddress> where D: DatabaseInterface {
    get_public_eth_address_from_db(db)
        .map(|eth_address| {
            info!("✔ Calculating pBTC contract address...");
            calculate_contract_address(eth_address, INITIAL_NONCE)
        })
}

pub fn generate_and_store_btc_on_eth_contract_address<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Calculating `pBTC-on-ETH` contract address...");
    get_eth_contract_address(&state.db)
        .and_then(|ref smart_contract_address| {
            info!("✔ Storing `pBTC-on-ETH` contract address in db...");
            put_btc_on_eth_smart_contract_address_in_db(&state.db, smart_contract_address)
        })
        .and(Ok(state))
}

pub fn generate_and_store_erc20_on_eos_contract_address<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Calculating `pERC20-on-EOS` contract address...");
    get_eth_contract_address(&state.db)
        .and_then(|ref smart_contract_address| {
            info!("✔ Storing `pERC20-on-EOS` contract address in db...");
            put_erc20_on_eos_smart_contract_address_in_db(&state.db, smart_contract_address)
        })
        .and(Ok(state))
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::btc_on_eth::eth::eth_test_utils::get_sample_eth_address;

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
        assert_eq!(result, expected_result);
    }
}
