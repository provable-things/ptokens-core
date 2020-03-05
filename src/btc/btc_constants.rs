#[cfg(not(test))]
pub const PTOKEN_P2SH_SCRIPT_BYTES: usize = 101;

#[cfg(test)] // NOTE Because of real BTC tx test-vectors
pub const PTOKEN_P2SH_SCRIPT_BYTES: usize = 0;

pub const BTC_TAIL_LENGTH: u64 = 10;
// NOTE: Following is used as placeholder for bad address parsing in ETH params!
pub const DEFAULT_BTC_ADDRESS: &'static str =
    "msTgHeQgPZ11LRcUdtfzagEfiZyKF57DhR";

pub const DEFAULT_BTC_SEQUENCE: u32 = 4294967295; // NOTE: 0xFFFFFFFF
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-difficulty').slice(2), 'hex')
// )
// 0ed532c16cd0bcc543cdcd01132c38349fd25e85b2d7f4609b66943bc8500a7c
pub static BTC_DIFFICULTY_THRESHOLD: [u8; 32] = [
  14, 213, 50, 193, 108, 208, 188, 197,
  67, 205, 205, 1, 19, 44, 56, 52,
  159, 210, 94, 133, 178, 215, 244, 96,
  155, 102, 148, 59, 200, 80, 10, 124
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-address').slice(2), 'hex')
// )
// bdf6e75595f2a65ce048e0416b8c2a8462288116db886b551b2891adceb0a53a
pub static BTC_ADDRESS_KEY: [u8; 32] = [
  189, 246, 231, 85, 149, 242, 166, 92,
  224, 72, 224, 65, 107, 140, 42, 132,
  98, 40, 129, 22, 219, 136, 107, 85,
  27, 40, 145, 173, 206, 176, 165, 58
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-canon-block').slice(2), 'hex')
// )
// ed228247ba940027aa9406ef39c2aa07f650bfa53f0b8478f2d90836615912b8
pub static BTC_CANON_BLOCK_HASH_KEY: [u8; 32] = [
  237, 34, 130, 71, 186, 148, 0, 39,
  170, 148, 6, 239, 57, 194, 170, 7,
  246, 80, 191, 165, 63, 11, 132, 120,
  242, 217, 8, 54, 97, 89, 18, 184
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-latest-block').slice(2), 'hex')
// )
// 22f781fdf51ac53605f603b9abeaddd618d29eb7ebed285a919abf128379a0a2
pub static BTC_LATEST_BLOCK_HASH_KEY: [u8; 32] = [
  34, 247, 129, 253, 245, 26, 197, 54,
  5, 246, 3, 185, 171, 234, 221, 214, 24,
  210, 158, 183, 235, 237, 40, 90, 145,
  154, 191, 18, 131, 121, 160, 162
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-linker-hash').slice(2), 'hex')
// )
// 98e63aa8f93943b3bfea2ee4d0e063942415618cfc0cd51828de4de7b4698039
pub static BTC_LINKER_HASH_KEY: [u8; 32] = [
  152, 230, 58, 168, 249, 57, 67, 179,
  191, 234, 46, 228, 208, 224, 99, 148,
  36, 21, 97, 140, 252, 12, 213, 24,
  40, 222, 77, 231, 180, 105, 128, 57
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-anchor-block').slice(2), 'hex')
// )
// bb005e5d49d23fc16c62b7971672f0f44043866cf19e4aa2d77db7f9632d0d83
pub static BTC_ANCHOR_BLOCK_HASH_KEY: [u8; 32] = [
  187, 0, 94, 93, 73, 210, 63, 193,
  108, 98, 183, 151, 22, 114, 240, 244,
  64, 67, 134, 108, 241, 158, 74, 162,
  215, 125, 183, 249, 99, 45, 13, 131
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-private-key').slice(2), 'hex')
// )
// d8c4da823c79e9245163a8db18b7e9d6107f7487e624a4db9bdc3acb788902de
pub static BTC_PRIVATE_KEY_DB_KEY: [u8; 32] = [
  216, 196, 218, 130, 60, 121, 233, 36,
  81, 99, 168, 219, 24, 183, 233, 214,
  16, 127, 116, 135, 230, 36, 164, 219,
  155, 220, 58, 203, 120, 137, 2, 222
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-canon-to-tip-length').slice(2), 'hex')
// )
// 2d9b6327983926c2dd9636f3c8bc13b811af80858c08fe1b9d019ebdcf73049c
pub static BTC_CANON_TO_TIP_LENGTH_KEY: [u8; 32] = [
  45, 155, 99, 39, 152, 57, 38, 194,
  221, 150, 54, 243, 200, 188, 19, 184,
  17, 175, 128, 133, 140, 8, 254, 27,
  157, 1, 158, 189, 207, 115, 4, 156
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('provable-ptoken').slice(2), 'hex')
// )
// 7eb2e65416dd107602495454d1ed094ae475cff2f3bfb2e2ae68a1c52bc0d66f
pub static PTOKEN_GENESIS_HASH: [u8; 32] = [
  126, 178, 230, 84, 22, 221, 16, 118,
  2, 73, 84, 84, 209, 237, 9, 74,
  228, 117, 207, 242, 243, 191, 178, 226,
  174, 104, 161, 197, 43, 192, 214, 111
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-network-key').slice(2), 'hex')
// )
// 'f2321e29a0792487edd90debfc9a85fcb39856a5343801e794c5c915aa341ee8'
pub static BTC_NETWORK_KEY: [u8; 32] = [
  242, 50, 30, 41, 160, 121, 36, 135,
  237, 217, 13, 235, 252, 154, 133, 252,
  179, 152, 86, 165, 52, 56, 1, 231,
  148, 197, 201, 21, 170, 52, 30, 232
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-fee-key').slice(2), 'hex')
// )
// 6ded8f6cf1097edaf81e815dec1810946dd32327ecdc9de506ca7d1535c34801
pub static BTC_FEE_KEY: [u8; 32] = [
  109, 237, 143, 108, 241, 9, 126, 218,
  248, 30, 129, 93, 236, 24, 16, 148,
  109, 211, 35, 39, 236, 220, 157, 229,
  6, 202, 125, 21, 53, 195, 72, 1
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-account-nonce-key').slice(2), 'hex')
// )
// 48236d034b7d7fac3b4550bdbe5682eb012d1717bb345c39c5add04be5139880
pub static BTC_ACCOUNT_NONCE_KEY: [u8; 32] = [
  72, 35, 109, 3, 75, 125, 127, 172,
  59, 69, 80, 189, 190, 86, 130, 235,
  1, 45, 23, 23, 187, 52, 92, 57,
  197, 173, 208, 75, 229, 19, 152, 128
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('btc-tail-block-hash-key').slice(2), 'hex')
// )
// 0x26ab99d609131225d7ecf087632b5b6771468931273d0f6c16b09c9bbe316f71
pub static BTC_TAIL_BLOCK_HASH_KEY: [u8; 32] = [
  38, 171, 153, 214, 9, 19, 18, 37,
  215, 236, 240, 135, 99, 43, 91, 103,
  113, 70, 137, 49, 39, 61, 15, 108,
  22, 176, 156, 155, 190, 49, 111, 113
];
