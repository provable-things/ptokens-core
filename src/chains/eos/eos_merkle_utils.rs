use bitcoin::hashes::{sha256, Hash};
use eos_chain::Checksum256;
use serde::{Deserialize, Serialize};

use crate::{
    chains::eos::eos_utils::convert_hex_to_checksum256,
    errors::AppError,
    types::{Byte, Bytes, NoneError, Result},
};

pub type CanonicalLeft = Bytes;
pub type CanonicalRight = Bytes;
pub type Sha256Hash = bitcoin::hashes::sha256::Hash;
pub type CanonicalPair = (CanonicalLeft, CanonicalRight);

fn set_first_bit_of_byte_to_zero(mut byte: Byte) -> Byte {
    byte &= 0b0111_1111;
    byte
}

fn set_first_bit_of_byte_to_one(mut byte: Byte) -> Byte {
    byte |= 0b1000_0000;
    byte
}

fn set_first_bit_of_hash_to_one(hash: &[Byte]) -> Bytes {
    let mut new_hash = hash.to_vec();
    new_hash[0] = set_first_bit_of_byte_to_one(hash[0]);
    new_hash
}

fn set_first_bit_of_hash_to_zero(hash: &[Byte]) -> Bytes {
    let mut new_hash = hash.to_vec();
    new_hash[0] = set_first_bit_of_byte_to_zero(hash[0]);
    new_hash
}

fn make_canonical_left(hash: &[Byte]) -> CanonicalLeft {
    set_first_bit_of_hash_to_zero(hash)
}

fn make_canonical_right(hash: &[Byte]) -> CanonicalRight {
    set_first_bit_of_hash_to_one(hash)
}

fn is_canonical_left(hash: &[Byte]) -> bool {
    hash[0] & 0b1000_0000 == 0
}

fn is_canonical_right(hash: &[Byte]) -> bool {
    !is_canonical_left(hash)
}

fn make_canonical_pair(l: &[Byte], r: &[Byte]) -> CanonicalPair {
    (make_canonical_left(l), make_canonical_right(r))
}

fn concatenate_canonical_pair(mut pair: CanonicalPair) -> Bytes {
    pair.0.append(&mut pair.1);
    pair.0
}

fn hash_canonical_pair(pair: CanonicalPair) -> Sha256Hash {
    sha256::Hash::hash(&concatenate_canonical_pair(pair))
}

fn make_and_hash_canonical_pair(l: &[Byte], r: &[Byte]) -> Bytes {
    hash_canonical_pair(make_canonical_pair(l, r)).to_vec()
}

pub fn verify_merkle_proof(merkle_proof: &[String]) -> Result<bool> {
    let mut node = hex::decode(merkle_proof[0].clone())?;
    let leaves = merkle_proof[..merkle_proof.len() - 1]
        .iter()
        .map(|hex| Ok(hex::decode(hex)?))
        .collect::<Result<Vec<Bytes>>>()?;
    for leaf in leaves.iter().skip(1) {
        match is_canonical_right(leaf) {
            true => {
                node = make_and_hash_canonical_pair(&node, leaf);
            },
            false => {
                node = make_and_hash_canonical_pair(leaf, &node);
            },
        }
    }
    Ok(node == hex::decode(merkle_proof.last().ok_or(NoneError("Could not unwrap merkle proof!"))?)?)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncremerkleJson {
    node_count: u64,
    active_nodes: Vec<String>,
}

impl IncremerkleJson {
    pub fn from_incremerkle(incremerkle: &Incremerkle) -> Self {
        IncremerkleJson {
            node_count: incremerkle.node_count,
            active_nodes: incremerkle
                .active_nodes
                .iter()
                .map(|checksum| checksum.to_string())
                .collect::<Vec<String>>(),
        }
    }

    pub fn to_incremerkle(&self) -> Result<Incremerkle> {
        Ok(Incremerkle {
            node_count: self.node_count,
            active_nodes: self
                .active_nodes
                .iter()
                .map(convert_hex_to_checksum256)
                .collect::<Result<Vec<Checksum256>>>()?,
        })
    }
}

// NOTE: Courtesy of: https://github.com/bifrost-codes/rust-eos/
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Incremerkle {
    node_count: u64,
    active_nodes: Vec<Checksum256>,
}

// NOTE: Ibid
impl Incremerkle {
    pub fn to_json(&self) -> IncremerkleJson {
        IncremerkleJson::from_incremerkle(self)
    }

    pub fn default() -> Self {
        Incremerkle {
            node_count: 0,
            active_nodes: vec![],
        }
    }

    fn make_canonical_left(val: &Checksum256) -> Checksum256 {
        let mut canonical_l: Checksum256 = *val;
        canonical_l.set_hash0(canonical_l.hash0() & 0xFFFF_FFFF_FFFF_FF7F_u64);
        canonical_l
    }

    fn make_canonical_right(val: &Checksum256) -> Checksum256 {
        let mut canonical_r: Checksum256 = *val;
        canonical_r.set_hash0(canonical_r.hash0() | 0x0000_0000_0000_0080_u64);
        canonical_r
    }

    pub fn make_canonical_pair(l: &Checksum256, r: &Checksum256) -> (Checksum256, Checksum256) {
        (Self::make_canonical_left(l), Self::make_canonical_right(r))
    }

    fn next_power_of_2(mut value: u64) -> u64 {
        value -= 1;
        value |= value >> 1;
        value |= value >> 2;
        value |= value >> 4;
        value |= value >> 8;
        value |= value >> 16;
        value |= value >> 32;
        value += 1;
        value
    }

    fn clz_power_2(value: u64) -> usize {
        let mut lz: usize = 64;

        if value != 0 {
            lz -= 1;
        }
        if (value & 0x0000_0000_FFFF_FFFF_u64) != 0 {
            lz -= 32;
        }
        if (value & 0x0000_FFFF_0000_FFFF_u64) != 0 {
            lz -= 16;
        }
        if (value & 0x00FF_00FF_00FF_00FF_u64) != 0 {
            lz -= 8;
        }
        if (value & 0x0F0F_0F0F_0F0F_0F0F_u64) != 0 {
            lz -= 4;
        }
        if (value & 0x3333_3333_3333_3333_u64) != 0 {
            lz -= 2;
        }
        if (value & 0x5555_5555_5555_5555_u64) != 0 {
            lz -= 1;
        }

        lz
    }

    fn calculate_max_depth(node_count: u64) -> usize {
        if node_count == 0 {
            return 0;
        }
        let implied_count = Self::next_power_of_2(node_count);
        Self::clz_power_2(implied_count) + 1
    }

    pub fn new(node_count: u64, active_nodes: Vec<Checksum256>) -> Self {
        Incremerkle {
            node_count,
            active_nodes,
        }
    }

    pub fn append(&mut self, digest: Checksum256) -> Result<Checksum256> {
        let mut partial = false;
        let max_depth = Self::calculate_max_depth(self.node_count + 1);
        let mut current_depth = max_depth - 1;
        let mut index = self.node_count;
        let mut top = digest;
        let mut active_iter = self.active_nodes.iter();
        let mut updated_active_nodes: Vec<Checksum256> = Vec::with_capacity(max_depth);

        while current_depth > 0 {
            if (index & 0x1) == 0 {
                if !partial {
                    updated_active_nodes.push(top);
                }

                top = Checksum256::hash(Self::make_canonical_pair(&top, &top))?;
                partial = true;
            } else {
                let left_value = active_iter
                    .next()
                    .ok_or_else(|| AppError::Custom("✘ Incremerkle error!".into()))?;

                if partial {
                    updated_active_nodes.push(*left_value);
                }

                top = Checksum256::hash(Self::make_canonical_pair(left_value, &top))?;
            }

            current_depth -= 1;
            index >>= 1;
        }

        updated_active_nodes.push(top);

        self.active_nodes = updated_active_nodes;

        self.node_count += 1;

        Ok(self.active_nodes[self.active_nodes.len() - 1])
    }

    pub fn get_root(&self) -> Checksum256 {
        if self.node_count > 0 {
            self.active_nodes[self.active_nodes.len() - 1]
        } else {
            Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_range_loop)]
    use std::str::FromStr;

    use eos_chain::{AccountName, Action, ActionName, PermissionLevel, PermissionName, SerializeData};

    use super::*;
    use crate::chains::eos::{
        eos_action_receipt::{AuthSequence, EosActionReceipt},
        eos_test_utils::{get_sample_action_digests, get_sample_eos_submission_material_n},
    };

    fn get_expected_digest_1() -> &'static str {
        "9b9babebfbdff48ce4002b5f3c7f999c0ee74707b6d121c47ef5db68c6be7262"
    }

    fn get_expected_digest_2() -> &'static str {
        "122cd09d66ca7df007a35bd9c9be5484833f1a69ad0c8527c3e2a56b6955e761"
    }

    fn get_expected_digest_bytes_1() -> Bytes {
        hex::decode(get_expected_digest_1()).unwrap()
    }

    fn get_expected_digest_bytes_2() -> Bytes {
        hex::decode(get_expected_digest_2()).unwrap()
    }

    fn get_expected_first_byte_1() -> Byte {
        0b0001_1011
    }

    fn get_expected_first_byte_2() -> Byte {
        0b1001_0010
    }

    fn get_sample_canonical_pair() -> CanonicalPair {
        make_canonical_pair(&get_expected_digest_bytes_1(), &get_expected_digest_bytes_2())
    }

    pub fn get_merkle_digest(mut leaves: Vec<Bytes>) -> Bytes {
        if leaves.is_empty() {
            return vec![0x00];
        }
        while leaves.len() > 1 {
            if leaves.len() % 2 != 0 {
                let last = leaves[leaves.len() - 1].clone();
                leaves.push(last);
            }
            for i in 0..(leaves.len() / 2) {
                leaves[i] = hash_canonical_pair(make_canonical_pair(&leaves[2 * i], &leaves[(2 * i) + 1])).to_vec();
            }
            leaves.resize(leaves.len() / 2, vec![0x00]);
        }
        leaves[0].clone()
    }

    #[test]
    fn should_set_first_bit_of_byte_to_zero() {
        let byte = 0b1011_1011;
        let expected_result = 0b0011_1011;
        let result = set_first_bit_of_byte_to_zero(byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_set_first_bit_of_byte_to_one() {
        let byte = 0b0011_0011;
        let expected_result = 0b1011_0011;
        let result = set_first_bit_of_byte_to_one(byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_set_first_bit_of_hash_to_one() {
        let hash = get_expected_digest_bytes_2();
        let result = set_first_bit_of_hash_to_one(&hash);
        for i in 0..hash.len() {
            if i == 0 {
                assert_eq!(result[i], get_expected_first_byte_2());
            } else {
                assert_eq!(result[i], hash[i]);
            }
        }
    }

    #[test]
    fn should_set_first_bit_of_hash_to_zero() {
        let hash = get_expected_digest_bytes_1();
        let result = set_first_bit_of_hash_to_zero(&hash);
        for i in 0..hash.len() {
            if i == 0 {
                assert_eq!(result[i], get_expected_first_byte_1());
            } else {
                assert_eq!(result[i], hash[i]);
            }
        }
    }

    #[test]
    fn should_make_hash_canonical_right() {
        let hash = get_expected_digest_bytes_2();
        let result = make_canonical_right(&hash);
        for i in 0..hash.len() {
            if i == 0 {
                assert_eq!(result[i], get_expected_first_byte_2());
            } else {
                assert_eq!(result[i], hash[i]);
            }
        }
    }

    #[test]
    fn should_make_hash_canonical_left() {
        let hash = get_expected_digest_bytes_1();
        let result = make_canonical_left(&hash);
        for i in 0..hash.len() {
            if i == 0 {
                assert_eq!(result[i], get_expected_first_byte_1());
            } else {
                assert_eq!(result[i], hash[i]);
            }
        }
    }

    #[test]
    fn canonical_left_hash_should_be_canonical_left() {
        let hash = get_expected_digest_bytes_1();
        let canonical_left_hash = make_canonical_left(&hash);
        let is_left = is_canonical_left(&canonical_left_hash);
        let is_right = is_canonical_right(&canonical_left_hash);
        assert!(is_left);
        assert!(!is_right);
    }

    #[test]
    fn canonical_right_hash_should_be_canonical_right() {
        let hash = get_expected_digest_bytes_2();
        let canonical_right_hash = make_canonical_right(&hash);
        let is_left = is_canonical_left(&canonical_right_hash);
        let is_right = is_canonical_right(&canonical_right_hash);
        assert!(!is_left);
        assert!(is_right);
    }

    #[test]
    fn should_get_correct_action_digest() {
        let account_name = AccountName::from_str("provabletokn").unwrap();
        let action_name = ActionName::from_str("event").unwrap();
        let actor = AccountName::from_str("provabletokn").unwrap();
        let permission = PermissionName::from_str("active").unwrap();
        let permission_level = PermissionLevel { actor, permission };
        let authorization = vec![permission_level];
        let data = hex::decode(
            "e0d2b86b1a3962343021cd2a1eb3e9ad672b00000000000004454f53000000002a3078303236644336413433353631444138413641373735353338623139324133653933366330463239422301000000000000"
            ).unwrap();
        let action = Action {
            account: account_name,
            name: action_name,
            authorization,
            data,
        };
        let serialized_action = action.to_serialize_data().unwrap();
        let result = sha256::Hash::hash(&serialized_action).to_string();
        assert_eq!(result, get_expected_digest_1());
    }

    #[test]
    fn should_make_canonical_pair() {
        let digest_1 = get_expected_digest_bytes_1();
        let digest_2 = get_expected_digest_bytes_2();
        let result = make_canonical_pair(&digest_1, &digest_2);
        for i in 0..result.0.len() {
            if i == 0 {
                assert_eq!(result.0[i], get_expected_first_byte_1());
            } else {
                assert_eq!(result.0[i], digest_1[i]);
            }
        }
        for i in 0..result.1.len() {
            if i == 0 {
                assert_eq!(result.1[i], get_expected_first_byte_2());
            } else {
                assert_eq!(result.1[i], digest_2[i]);
            }
        }
    }

    #[test]
    fn should_hash_canonical_pair() {
        let expected_result = "a26284468e89fe4a5cce763ca3b3d3d37d5fcb35f289c63f0558487ec57ace28";
        let canonical_pair = get_sample_canonical_pair();
        let result = hash_canonical_pair(canonical_pair);
        assert_eq!(result.to_string(), expected_result);
    }

    #[test]
    fn should_serialize_a_simple_action_receipt_correctly() {
        let expected_result = "6cd473b189a292bd520cac3430cc7934273da81cc3417376194a5d757b4abdc8".to_string();
        let result = EosActionReceipt::new(
            "eosio",
            "a6a370c6569034a4cc41935dd88f83d1c64e0414580872f29d87f69fe7a5d769",
            60725518,
            12,
            498637597,
            10,
            vec![AuthSequence::new("eosio", 59191700).unwrap()],
        )
        .unwrap()
        .to_digest()
        .unwrap();
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_get_merkle_root_for_an_even_number_of_action_receipts() {
        // NOTE: Test vector = https://jungle.bloks.io/block/58316764
        let expected_result = "2f013d3ed57c89f1824772d18a4a74c043574bad47e9c6f088136e7595511810";
        let action_digest_1 = EosActionReceipt::new(
            "eosio",
            "8e3e721a497dbae5e5fde0bb43e9086628809efaf102b763a3e9820adce9ce8f",
            62815613,
            12,
            503056735,
            10,
            vec![AuthSequence::new("eosio", 61275209).unwrap()],
        )
        .unwrap()
        .to_digest()
        .unwrap();
        let action_digest_2 = EosActionReceipt::new(
            "provabletokn",
            "4b991cebb3e6667b242aca3fb011623cd8ce2be2e8c24958da551c7b3ba68903",
            2884,
            48,
            503056736,
            80,
            vec![AuthSequence::new("provabletokn", 3090).unwrap()],
        )
        .unwrap()
        .to_digest()
        .unwrap();
        let result = get_merkle_digest(vec![action_digest_1, action_digest_2]);
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_get_merkle_root_for_an_odd_number_of_action_receipts_gt_one() {
        // NOTE: Test vector = https://jungle.bloks.io/block/58319528
        let expected_result = "593f54cbc0b877b30cec5e510838b2b16ca00aca43e21d204d21eb8e8f947aa0";
        let action_digest_1 = EosActionReceipt::new(
            "eosio",
            "23ab74b930cceea6061e1c4580ec988bf483a77e225cfca254d832928b4d1b36",
            62818486,
            12,
            503062766,
            10,
            vec![AuthSequence::new("eosio", 61277973).unwrap()],
        )
        .unwrap()
        .to_digest()
        .unwrap();
        let action_digest_2 = EosActionReceipt::new(
            "eosebetbullj",
            "b9243d8513e25705e89d7ccd0491f4a57d07b9866fd89d3446887af852cfed15",
            1440226,
            215,
            503062767,
            215,
            vec![AuthSequence::new("eosebetbullj", 1440687).unwrap()],
        )
        .unwrap()
        .to_digest()
        .unwrap();
        let action_digest_3 = EosActionReceipt::new(
            "dvmh1tbb1him",
            "4bd1d3e987cd13e3d108a9a0cd185bf022cb1a826f69f163fcd109db54ba799f",
            804629,
            2,
            503062768,
            1,
            vec![AuthSequence::new("dvmh1tbb1him", 804649).unwrap()],
        )
        .unwrap()
        .to_digest()
        .unwrap();
        let result = get_merkle_digest(vec![action_digest_1, action_digest_2, action_digest_3]);
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_get_action_mroot_when_action_has_gt_one_auth_sequence() {
        // NOTE: Test vector = https://jungle.bloks.io/block/58345436
        let expected_result = "f93a91688d12170c24807d4bd507cf52dcde962ae4a41a86fe55231dee4df348";
        let action_receipt_1 = EosActionReceipt::new(
            "eosio",
            "2d5371b958af052629f3fb62ede1bfcd94703675bc734535bf87fb615284dba3",
            62844592,
            12,
            503124645,
            10,
            vec![AuthSequence::new("eosio", 61303891).unwrap()],
        )
        .unwrap()
        .to_digest()
        .unwrap();
        let action_receipt_2 = EosActionReceipt::new(
            "authsequence",
            "ae341469a7b3936c70e9684a42ef8fc1975f1bb2fe1f3b0b1105eda7d3a6276a",
            10,
            1,
            503124646,
            1,
            vec![
                AuthSequence::new("othrsequence", 14).unwrap(),
                AuthSequence::new("rick11111111", 268).unwrap(),
            ],
        )
        .unwrap()
        .to_digest()
        .unwrap();
        let result = get_merkle_digest(vec![action_receipt_1, action_receipt_2]);
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_get_action_mroot_for_four_actions_correctly() {
        let digests = get_sample_action_digests().unwrap();
        let expected_result = "8b4e5e5d3e7587065896d0076d65c72e03c11a9159d414eb3a2363b59108116a";
        let result = get_merkle_digest(digests);
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_verify_merkle_proofs() {
        let num_proofs = 4;
        vec![0, num_proofs - 1]
            .iter()
            .enumerate()
            .map(|(_, i)| get_sample_eos_submission_material_n(i + 1))
            .map(|submission_material| submission_material.action_proofs[0].action_proof.clone())
            .for_each(|merkle_proof| assert!(verify_merkle_proof(&merkle_proof).unwrap()));
    }

    #[test]
    fn should_get_incremerkle_root_from_interim_block_idss() {
        let expected_incremerkle_root = "1894edef851c070852f55a4dc8fc50ea8f2eafc67d8daad767e4f985dfe54071";
        let submission_material = get_sample_eos_submission_material_n(5);
        let active_nodes = submission_material.interim_block_ids.clone();
        let node_count: u64 = submission_material.block_header.block_num().into();
        let incremerkle = Incremerkle::new(node_count, active_nodes);
        let incremerkle_root = hex::encode(&incremerkle.get_root().to_bytes());
        assert_eq!(incremerkle_root, expected_incremerkle_root);
    }

    #[test]
    fn should_convert_from_incremerkle_to_json_and_back() {
        let expected_incremerkle_root = "1894edef851c070852f55a4dc8fc50ea8f2eafc67d8daad767e4f985dfe54071";
        let submission_material = get_sample_eos_submission_material_n(5);
        let active_nodes = submission_material.interim_block_ids.clone();
        let node_count: u64 = submission_material.block_header.block_num().into();
        let incremerkle = Incremerkle::new(node_count, active_nodes);
        let json = IncremerkleJson::from_incremerkle(&incremerkle);
        assert_eq!(json.node_count, incremerkle.node_count);
        assert_eq!(json.active_nodes.len(), incremerkle.active_nodes.len());
        let result = json.to_incremerkle().unwrap();
        assert_eq!(result.node_count, incremerkle.node_count);
        assert_eq!(result.active_nodes.len(), incremerkle.active_nodes.len());
        let result_root = hex::encode(&incremerkle.get_root().to_bytes());
        assert_eq!(result_root, expected_incremerkle_root);
    }
}
