use ethereum_types::{
    U256,
    H256 as EthHash,
    Address as EthAddress,
};
use derive_more::{
    Deref,
    Constructor,
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::{
        eos::{
            eos_utils::remove_symbol_from_eos_asset,
            eos_erc20_dictionary::EosErc20Dictionary,
        },
        eth::{
            eth_state::EthState,
            eth_database_utils::get_eth_canon_block_from_db,
        },
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erc20OnEosPegInInfo {
    pub token_amount: U256,
    pub eos_address: String,
    pub eos_token_address: String,
    pub eos_asset_amount: String,
    pub token_sender: EthAddress,
    pub eth_token_address: EthAddress,
    pub originating_tx_hash: EthHash,
}

impl Erc20OnEosPegInInfo {
    pub fn new(
        token_amount: U256,
        token_sender: EthAddress,
        eth_token_address: EthAddress,
        eos_address: String,
        originating_tx_hash: EthHash,
        eos_token_address: String,
        eos_asset_amount: String,
    ) -> Erc20OnEosPegInInfo {
        Erc20OnEosPegInInfo {
            token_amount,
            eth_token_address,
            eos_address,
            originating_tx_hash,
            token_sender,
            eos_token_address,
            eos_asset_amount,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Constructor, Deref)]
pub struct Erc20OnEosPegInInfos(pub Vec<Erc20OnEosPegInInfo>);

impl Erc20OnEosPegInInfos {
    pub fn sum(&self) -> U256 {
        self.0.iter().fold(U256::zero(), |acc, params| acc + params.token_amount)
    }

    pub fn filter_out_zero_eos_values(&self) -> Result<Self> {
        Ok(Self::new(
            self
                .iter()
                .filter(|peg_in_info|
                    match remove_symbol_from_eos_asset(&peg_in_info.eos_asset_amount).parse::<f64>() != Ok(0.0) {
                        true => true,
                        false => {
                            info!("✘ Filtering out peg in info due to zero EOS asset amount: {:?}", peg_in_info);
                            false
                        }
                    }
                )
                .cloned()
                .collect::<Vec<Erc20OnEosPegInInfo>>()
        ))
    }
}

pub fn maybe_parse_peg_in_info_from_canon_block_and_add_to_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe parsing `erc20-on-eos` peg-in infos...");
    get_eth_canon_block_from_db(&state.db)
        .and_then(|submission_material| {
            match submission_material.receipts.is_empty() {
                true => {
                    info!("✔ No receipts in canon block ∴ no info to parse!");
                    Ok(state)
                }
                false => {
                    info!("✔ {} receipts in canon block ∴ parsing info...", submission_material.receipts.len());
                    EosErc20Dictionary::get_from_db(&state.db)
                        .and_then(|account_names| submission_material.get_erc20_on_eos_peg_in_infos(&account_names))
                        .and_then(|peg_in_infos| state.add_erc20_on_eos_peg_in_infos(peg_in_infos))
                }
            }
        })
}

pub fn maybe_filter_peg_in_info_in_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe filtering `erc20-on-eos` peg-in infos...");
    debug!("✔ Num peg-in infos before: {}", state.erc20_on_eos_peg_in_infos.len());
    state
        .erc20_on_eos_peg_in_infos
        .filter_out_zero_eos_values()
        .and_then(|filtered_peg_ins| {
            debug!("✔ Num peg-in infos after: {}", filtered_peg_ins.len());
            state.replace_erc20_on_eos_peg_in_infos(filtered_peg_ins)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_sample_zero_eos_asset_peg_in_info() -> Erc20OnEosPegInInfo {
        Erc20OnEosPegInInfo::new(
            U256::from_dec_str("1337").unwrap(),
            EthAddress::from_slice(&hex::decode("edB86cd455ef3ca43f0e227e00469C3bDFA40628").unwrap()),
            EthAddress::from_slice(&hex::decode("d879D3C8782aB95a43C69Fa73d8DCC50C8815d5e").unwrap()),
            "aneosaddress".to_string(),
            EthHash::from_slice(&hex::decode("7b7f73183fe4d1d6e23c494ba0b579718c7dd6e1c62426fd5411a6a21b3203aa").unwrap()),
            "aneosaccount".to_string(),
            "0.000000000 SAM".to_string(),
        )
    }

    #[test]
    fn should_filter_out_zero_eos_asset_peg_ins() {
        let expected_num_peg_ins_before = 1;
        let expected_num_peg_ins_after = 0;
        let peg_ins = Erc20OnEosPegInInfos::new(vec![get_sample_zero_eos_asset_peg_in_info()]);
        assert_eq!(peg_ins.len(), expected_num_peg_ins_before);
        let result = peg_ins.filter_out_zero_eos_values().unwrap();
        assert_eq!(result.len(), expected_num_peg_ins_after);
    }
}
