use std::str::FromStr;
use eos_primitives::{
    ActionName,
    AccountName,
    PermissionLevel,
    PermissionLevels,
    Action as EosAction,
};
use crate::{
    types::{Bytes, Result},
    btc_on_eos::eos::eos_types::{
        EosActionJson,
        AuthorizationJson,
    },
};

fn parse_authorization_json(
    authorization_json: &AuthorizationJson
) -> Result<PermissionLevel> {
    Ok(
        PermissionLevel::from_str(
            authorization_json.actor.clone(),
            authorization_json.permission.clone(),
        )?
    )
}

fn parse_authorization_jsons(
    authorization_jsons: &[AuthorizationJson]
) -> Result<PermissionLevels> {
    authorization_jsons
        .iter()
        .map(parse_authorization_json)
        .collect::<Result<PermissionLevels>>()
}

fn deserialize_action_data(
    maybe_hex_data: &Option<String>,
) -> Result<Bytes> {
    match maybe_hex_data {
        Some(string) => Ok(hex::decode(string)?),
        None => Err("✘ Failed to decode hex_data field of action!".into())
    }
}

pub fn parse_eos_action_json(action_json: &EosActionJson) -> Result<EosAction> {
    Ok(
        EosAction {
            name: ActionName::from_str(
                &action_json.name
            )?,
            account: AccountName::from_str(
                &action_json.account
            )?,
            data: deserialize_action_data(
                &action_json.hex_data,
            )?,
            authorization: parse_authorization_jsons(
                &action_json.authorization
            )?,
        }
    )
}
