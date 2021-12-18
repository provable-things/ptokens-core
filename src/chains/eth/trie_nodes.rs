use ethereum_types::H256;
use rlp::{Rlp, RlpStream};

use crate::{
    chains::eth::{
        eth_constants::{BRANCH_NODE_STRING, EMPTY_NIBBLES, EXTENSION_NODE_STRING, LEAF_NODE_STRING},
        eth_types::{ChildNodes, TrieHashMap},
        get_trie_hash_map::get_thing_from_trie_hash_map,
        nibble_utils::Nibbles,
        path_codec::{
            decode_path_to_nibbles_and_node_type,
            encode_extension_path_from_nibbles,
            encode_leaf_path_from_nibbles,
        },
    },
    crypto_utils::keccak_hash_bytes,
    types::{Bytes, Result},
};

static NO_NODE_IN_STRUCT_ERR: &str = "✘ No node present in struct to rlp-encode!";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Node {
    pub leaf: Option<LeafNode>,
    pub branch: Option<BranchNode>,
    pub extension: Option<ExtensionNode>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LeafNode {
    pub raw: Bytes,
    pub value: Bytes,
    pub encoded_path: Bytes,
    pub path_nibbles: Nibbles,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExtensionNode {
    pub raw: Bytes,
    pub value: Bytes,
    pub encoded_path: Bytes,
    pub path_nibbles: Nibbles,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BranchNode {
    pub value: Option<Bytes>,
    pub branches: ChildNodes,
}

impl Node {
    pub fn new_leaf(path_nibbles: Nibbles, value: Bytes) -> Result<Node> {
        let encoded_path = encode_leaf_path_from_nibbles(path_nibbles.clone())?;
        let mut raw = encoded_path.clone();
        raw.append(&mut value.clone());
        Ok(Node {
            branch: None,
            extension: None,
            leaf: Some(LeafNode {
                raw,
                value,
                encoded_path,
                path_nibbles,
            }),
        })
    }

    pub fn new_extension(path_nibbles: Nibbles, value: Bytes) -> Result<Node> {
        let encoded_path = encode_extension_path_from_nibbles(path_nibbles.clone())?;
        let mut raw = encoded_path.clone();
        raw.append(&mut value.clone());
        Ok(Node {
            leaf: None,
            branch: None,
            extension: Some(ExtensionNode {
                raw,
                value,
                encoded_path,
                path_nibbles,
            }),
        })
    }

    pub fn new_branch(value: Option<Bytes>) -> Result<Node> {
        Ok(Node {
            leaf: None,
            extension: None,
            branch: Some(BranchNode {
                value,
                branches: get_empty_child_nodes(),
            }),
        })
    }

    pub fn update_branch_at_index(self, new_value: Option<Bytes>, index: usize) -> Result<Self> {
        if let Some(branch) = self.branch {
            Ok(Node {
                leaf: None,
                extension: None,
                branch: Some(BranchNode {
                    value: branch.value,
                    branches: update_child_nodes(branch.branches, new_value, index),
                }),
            })
        } else {
            Err("✘ Cannot update branches - not a branch node!".into())
        }
    }

    pub fn get_rlp_encoding(&self) -> Result<Bytes> {
        let mut rlp_stream = RlpStream::new();
        if let Some(leaf) = &self.leaf {
            rlp_stream.begin_list(2);
            rlp_stream.append(&leaf.encoded_path);
            rlp_stream.append(&leaf.value);
            Ok(rlp_stream.out().to_vec())
        } else if let Some(extension) = &self.extension {
            rlp_stream.begin_list(2);
            rlp_stream.append(&extension.encoded_path);
            rlp_stream.append(&extension.value);
            Ok(rlp_stream.out().to_vec())
        } else if let Some(branch) = &self.branch {
            rlp_stream.begin_list(17);
            for i in 0..branch.branches.len() {
                match &branch.branches[i] {
                    None => rlp_stream.append_empty_data(),
                    Some(thing) => rlp_stream.append(&thing.clone()),
                };
            }
            match &branch.value {
                None => rlp_stream.append_empty_data(),
                Some(value) => rlp_stream.append(&value.clone()),
            };
            Ok(rlp_stream.out().to_vec())
        } else {
            Err(NO_NODE_IN_STRUCT_ERR.into())
        }
    }

    pub fn get_hash(&self) -> Result<H256> {
        self.get_rlp_encoding().map(|bytes| keccak_hash_bytes(&bytes))
    }

    pub fn get_key(&self) -> Nibbles {
        if let Some(leaf_node) = &self.leaf {
            leaf_node.path_nibbles.clone()
        } else if let Some(extension_node) = &self.extension {
            // NOTE: Could be inline node, but we've not implemented them.
            extension_node.path_nibbles.clone()
        } else {
            EMPTY_NIBBLES
        }
    }

    pub fn get_key_length(&self) -> usize {
        if let Some(leaf_node) = &self.leaf {
            leaf_node.path_nibbles.len()
        } else if let Some(extension_node) = &self.extension {
            // NOTE: Could be inline node, but we've not implemented them.
            extension_node.path_nibbles.len()
        } else if self.branch.is_some() {
            1
        } else {
            0
        }
    }

    pub fn get_value(&self) -> Option<Bytes> {
        if let Some(leaf_node) = &self.leaf {
            Some(leaf_node.value.clone())
        } else if let Some(extension_node) = &self.extension {
            Some(extension_node.value.clone())
        } else if let Some(branch_node) = &self.branch {
            branch_node.value.clone()
        } else {
            None
        }
    }

    pub fn get_type(&self) -> &'static str {
        if self.leaf.is_some() {
            LEAF_NODE_STRING
        } else if self.branch.is_some() {
            BRANCH_NODE_STRING
        } else {
            EXTENSION_NODE_STRING
        }
    }
}

pub fn rlp_decode_node(rlp_data: Bytes) -> Result<Node> {
    match Rlp::new(&rlp_data).as_list() {
        Err(err) => Err(err.into()),
        Ok(list) => match list.len() {
            2 => {
                let path: &Bytes = &list[0];
                let value = &list[1];
                let (path_nibbles, node_type) = decode_path_to_nibbles_and_node_type(path.clone())?;
                match node_type == LEAF_NODE_STRING {
                    true => Node::new_leaf(path_nibbles, value.to_vec()),
                    false => Node::new_extension(path_nibbles, value.to_vec()),
                }
            },
            17 => {
                let value = &list[16];
                let mut branches = get_empty_child_nodes();
                for i in 0..16 {
                    if !list[i].is_empty() {
                        let value = &list[i];
                        branches[i] = Some(value.to_vec())
                    }
                }
                Ok(Node {
                    leaf: None,
                    extension: None,
                    branch: Some(BranchNode {
                        branches,
                        value: if !value.is_empty() { Some(value.to_vec()) } else { None },
                    }),
                })
            },
            _ => Err("✘ Cannot decode node from rlp data!".into()),
        },
    }
}

fn get_empty_child_nodes() -> ChildNodes {
    [
        None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    ]
}

fn update_child_nodes(mut child_nodes: ChildNodes, new_value: Option<Bytes>, index: usize) -> ChildNodes {
    child_nodes[index] = new_value;
    child_nodes
}

pub fn get_node_from_trie_hash_map(trie_hash_map: &TrieHashMap, key: &H256) -> Result<Option<Node>> {
    match get_thing_from_trie_hash_map(trie_hash_map, key) {
        None => Ok(None),
        Some(encoded_node) => Ok(Some(rlp_decode_node(encoded_node)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::eth::{
            eth_test_utils::{get_sample_branch_node, get_sample_extension_node, get_sample_leaf_node},
            eth_utils::convert_hex_to_h256,
            get_trie_hash_map::{get_new_trie_hash_map, put_thing_in_trie_hash_map},
            nibble_utils::{get_length_in_nibbles, get_nibbles_from_bytes},
        },
        errors::AppError,
    };

    fn get_sample_leaf_node_expected_encoding() -> Bytes {
        hex::decode("c9842012345683c0ffee").unwrap()
    }

    fn get_sample_extension_node_expected_encoding() -> Bytes {
        hex::decode("e68400c0ffeea01d237c84432c78d82886cb7d6549c179ca51ebf3b324d2a3fa01af6a563a9377").unwrap()
    }

    fn get_sample_branch_node_expected_encoding() -> Bytes {
        hex::decode("f85180a04f81663d4c7aeb115e49625430e3fa114445dc0a9ed73a7598a31cd60808a758a0d55a192f93e0576f46019553e2b4c0ff4b8de57cd73020f751aed18958e9ecdb8080808080808080808080808080")
            .unwrap()
    }

    fn get_sample_leaf_node_expected_hash() -> H256 {
        let hex = "c9161ce49c6a3362f5d20db4b6e36c259c9624eac5f99e64a052f45035d14c5d";
        convert_hex_to_h256(hex).unwrap()
    }

    fn get_sample_extension_node_expected_hash() -> H256 {
        let hex = "d1425391446456311990cdf61e1dbe92b14cb53caad0539a15564b9efac0f733";
        convert_hex_to_h256(hex).unwrap()
    }

    fn get_sample_branch_node_expected_hash() -> H256 {
        let hex = "9b88bb3372fcfde94cfbfd784ffcf64490a75bb2adedc128e67c887ce3d78535";
        convert_hex_to_h256(hex).unwrap()
    }

    #[test]
    fn should_get_new_leaf_node_correctly() {
        let panic_str = "Node should be a leaf node";
        let path_bytes = vec![0x12, 0x34, 0x56];
        let expected_nibble_length = path_bytes.len() * 2;
        let path_nibbles = get_nibbles_from_bytes(path_bytes);
        let value = hex::decode("c0ffee").unwrap();
        let expected_encoded_path = encode_leaf_path_from_nibbles(path_nibbles.clone()).unwrap();
        let mut expected_raw = expected_encoded_path.clone();
        expected_raw.append(&mut value.clone());
        let result = Node::new_leaf(path_nibbles.clone(), value.clone()).unwrap();
        let node_type = result.get_type();
        assert_eq!(node_type, LEAF_NODE_STRING);
        if result.extension.is_some() || result.branch.is_some() {
            panic!("{}", panic_str)
        }
        match result.leaf {
            None => panic!("{}", panic_str),
            Some(leaf) => {
                let nibble_length = get_length_in_nibbles(&leaf.path_nibbles);
                assert_eq!(leaf.value, value);
                assert_eq!(leaf.raw, expected_raw);
                assert_eq!(leaf.path_nibbles, path_nibbles);
                assert_eq!(leaf.encoded_path, expected_encoded_path);
                assert_eq!(nibble_length, expected_nibble_length)
            },
        }
    }

    #[test]
    fn should_rlp_encode_leaf_node_correctly() {
        let leaf_node = get_sample_leaf_node();
        let expected_result = get_sample_leaf_node_expected_encoding();
        let result = leaf_node.get_rlp_encoding().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_leaf_node_hash_correctly() {
        let leaf_node = get_sample_leaf_node();
        let expected_result = get_sample_leaf_node_expected_hash();
        let result = leaf_node.get_hash().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_extension_node_correctly() {
        let panic_str = "Node should be an extension node";
        let path_bytes = vec![0xc0, 0xff, 0xee];
        let expected_nibble_length = path_bytes.len() * 2;
        let path_nibbles = get_nibbles_from_bytes(path_bytes);
        let value =
            hex::decode("4aad98246efabf243441508dc0f328d80e83e9522e43709abab1c0c9cf4416dc".to_string()).unwrap();
        let expected_encoded_path = encode_extension_path_from_nibbles(path_nibbles.clone()).unwrap();
        let result = Node::new_extension(path_nibbles.clone(), value.clone()).unwrap();
        let node_type = result.get_type();
        assert_eq!(node_type, EXTENSION_NODE_STRING);
        let mut expected_raw = expected_encoded_path.clone();
        expected_raw.append(&mut value.clone());
        if result.leaf.is_some() || result.branch.is_some() {
            panic!("{}", panic_str)
        }
        match result.extension {
            None => panic!("{}", panic_str),
            Some(extension) => {
                let nibble_length = get_length_in_nibbles(&extension.path_nibbles);
                assert_eq!(extension.value, value);
                assert_eq!(extension.raw, expected_raw);
                assert_eq!(extension.path_nibbles, path_nibbles);
                assert_eq!(extension.encoded_path, expected_encoded_path);
                assert_eq!(nibble_length, expected_nibble_length)
            },
        }
    }

    #[test]
    fn should_rlp_encode_extension_node_correctly() {
        let extension_node = get_sample_extension_node();
        let expected_result = get_sample_extension_node_expected_encoding();
        let result = extension_node.get_rlp_encoding().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_extension_node_hash_correctly() {
        let extension_node = get_sample_extension_node();
        let expected_result = get_sample_extension_node_expected_hash();
        let result = extension_node.get_hash().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_new_branch_with_no_value_correctly() {
        let panic_str = "Node should be a branch node";
        let result = Node::new_branch(None).unwrap();
        if result.extension.is_some() || result.leaf.is_some() {
            panic!("{}", panic_str)
        }
        let node_type = result.get_type();
        assert_eq!(node_type, BRANCH_NODE_STRING);
        match result.branch {
            None => panic!("{}", panic_str),
            Some(branch) => {
                if branch.value.is_some() {
                    panic!("Branch should not have a value!")
                };
                assert_eq!(branch.branches, get_empty_child_nodes());
            },
        }
    }

    #[test]
    fn should_get_new_branch_with_value_correctly() {
        let panic_str = "Node should be a branch node";
        let value = hex::decode("c0ffee").unwrap();
        let result = Node::new_branch(Some(value.clone())).unwrap();
        if result.extension.is_some() || result.leaf.is_some() {
            panic!("{}", panic_str)
        }
        let node_type = result.get_type();
        assert_eq!(node_type, "branch");
        match result.branch {
            None => panic!("{}", panic_str),
            Some(branch) => {
                match branch.value {
                    Some(_value) => assert_eq!(_value, value),
                    None => panic!("Branch should have a value!"),
                }
                assert_eq!(branch.branches, get_empty_child_nodes());
            },
        }
    }

    #[test]
    fn should_update_branch_at_index_correctly() {
        let index = 5;
        let value = None;
        let branch_value = hex::decode("c0ffee").unwrap();
        let branch_node = Node::new_branch(value).unwrap();
        assert_eq!(branch_node.clone().branch.unwrap().branches[index], None);
        let result = branch_node
            .update_branch_at_index(Some(branch_value.clone()), index)
            .unwrap();
        assert_eq!(result.branch.unwrap().branches[index], Some(branch_value));
    }

    #[test]
    fn should_fail_to_update_branch_of_non_branch_node_correctly() {
        let expected_error = "✘ Cannot update branches - not a branch node!";
        let non_branch_node = get_sample_leaf_node();
        match non_branch_node.update_branch_at_index(None, 4) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            _ => panic!("Did not receive expected error!"),
        }
    }

    #[test]
    fn should_rlp_encode_branch_node_correctly() {
        let branch_node = get_sample_branch_node();
        let expected_result = get_sample_branch_node_expected_encoding();
        let result = branch_node.get_rlp_encoding().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_branch_node_hash_correctly() {
        let branch_node = get_sample_branch_node();
        let expected_result = get_sample_branch_node_expected_hash();
        let result = branch_node.get_hash().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_key_from_leaf_node() {
        let path_bytes = vec![0x12, 0x34, 0x56];
        let expected_result = get_nibbles_from_bytes(path_bytes);
        let node = get_sample_leaf_node();
        let result = node.get_key();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_key_from_extension_node() {
        let node = get_sample_extension_node();
        let path_bytes = vec![0xc0, 0xff, 0xee];
        let expected_result = get_nibbles_from_bytes(path_bytes);
        let result = node.get_key();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_no_key_from_branch_node() {
        let node = get_sample_branch_node();
        let result = node.get_key();
        assert_eq!(result, EMPTY_NIBBLES);
    }

    #[test]
    fn should_get_value_from_leaf_node() {
        let expected_result = hex::decode("c0ffee".to_string()).unwrap();
        let node = get_sample_leaf_node();
        let result = node.get_value();
        assert_eq!(result, Some(expected_result));
    }

    #[test]
    fn should_get_value_from_extension_node() {
        let node = get_sample_extension_node();
        let expected_result =
            hex::decode("1d237c84432c78d82886cb7d6549c179ca51ebf3b324d2a3fa01af6a563a9377".to_string()).unwrap();
        let result = node.get_value();
        assert_eq!(result, Some(expected_result));
    }

    #[test]
    fn should_get_value_from_branch_node() {
        let node = get_sample_branch_node();
        let expected_result = None;
        let result = node.get_value();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_rlp_decode_leaf_node() {
        let node = get_sample_leaf_node();
        let rlp_encoded_node = node.get_rlp_encoding().unwrap();
        let result = rlp_decode_node(rlp_encoded_node).unwrap();
        assert_eq!(result, node);
    }

    #[test]
    fn should_rlp_decode_extension_node() {
        let node = get_sample_extension_node();
        let rlp_encoded_node = node.get_rlp_encoding().unwrap();
        let result = rlp_decode_node(rlp_encoded_node).unwrap();
        assert_eq!(result, node);
    }

    #[test]
    fn should_rlp_decode_branch_node() {
        let node = get_sample_branch_node();
        let rlp_encoded_node = node.get_rlp_encoding().unwrap();
        let result = rlp_decode_node(rlp_encoded_node).unwrap();
        assert_eq!(result, node);
    }

    #[test]
    fn should_get_leaf_node_from_trie_hash_map() {
        let trie_hash_map = get_new_trie_hash_map().unwrap();
        let node = get_sample_leaf_node();
        let key = node.get_hash().unwrap();
        let rlp_encoded_node = node.get_rlp_encoding().unwrap();
        let updated_trie_hash_map = put_thing_in_trie_hash_map(trie_hash_map, key, rlp_encoded_node).unwrap();
        let result = get_node_from_trie_hash_map(&updated_trie_hash_map, &key).unwrap();
        assert_eq!(result, Some(node));
    }

    #[test]
    fn should_get_branch_node_from_trie_hash_map() {
        let trie_hash_map = get_new_trie_hash_map().unwrap();
        let node = get_sample_branch_node();
        let key = node.get_hash().unwrap();
        let rlp_encoded_node = node.get_rlp_encoding().unwrap();
        let updated_trie_hash_map = put_thing_in_trie_hash_map(trie_hash_map, key, rlp_encoded_node).unwrap();
        let result = get_node_from_trie_hash_map(&updated_trie_hash_map, &key).unwrap();
        assert_eq!(result, Some(node));
    }

    #[test]
    fn should_get_extension_node_from_trie_hash_map() {
        let trie_hash_map = get_new_trie_hash_map().unwrap();
        let node = get_sample_branch_node();
        let key = node.get_hash().unwrap();
        let rlp_encoded_node = node.get_rlp_encoding().unwrap();
        let updated_trie_hash_map = put_thing_in_trie_hash_map(trie_hash_map, key, rlp_encoded_node).unwrap();
        let result = get_node_from_trie_hash_map(&updated_trie_hash_map, &key).unwrap();
        assert_eq!(result, Some(node));
    }

    #[test]
    fn should_fail_to_get_non_existing_node_from_db() {
        let trie_hash_map = get_new_trie_hash_map().unwrap();
        let node = get_sample_branch_node();
        let dummy_key = node.get_hash().unwrap();
        let result = get_node_from_trie_hash_map(&trie_hash_map, &dummy_key).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn should_get_key_length_of_leaf_node() {
        let node = get_sample_leaf_node();
        let expected_result = 6; // Note: "123456" length.
        let result = node.get_key_length();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_key_length_of_extension_node() {
        let node = get_sample_extension_node();
        let expected_result = 6; // Note: "c0ffee" length.
        let result = node.get_key_length();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_key_length_of_branch_node() {
        let node = get_sample_branch_node();
        let expected_result = 1;
        let result = node.get_key_length();
        assert_eq!(result, expected_result);
    }
}
