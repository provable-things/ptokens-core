use crate::chains::eth::eth_types::EthSignature;

pub fn set_eth_signature_recovery_param(signature: &mut EthSignature) {
    signature[64] = if signature[64] == 1 { 0x1c } else { 0x1b };
}
