// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('utxo-first').slice(2), 'hex')
// )
// 2674b2e116a8fe42de73cd7e81f67c7e42c788c2da9711f2e5f628a001368b22
pub static UTXO_FIRST: [u8; 32] = [
  38, 116, 178, 225, 22, 168, 254, 66,
  222, 115, 205, 126, 129, 246, 124, 126,
  66, 199, 136, 194, 218, 151, 17, 242,
  229, 246, 40, 160, 1, 54, 139, 34
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('utxo-last').slice(2), 'hex')
// )
// 2dc0848af1e571dec07f281eb7203914e09c0075440ce765bfcce0e7ff2efb01
pub static UTXO_LAST: [u8; 32] = [
  45, 192, 132, 138, 241, 229, 113, 222,
  192, 127, 40, 30, 183, 32, 57, 20,
  224, 156, 0, 117, 68, 12, 231, 101,
  191, 204, 224, 231, 255, 46, 251, 1
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('utxo-balance').slice(2), 'hex')
// )
// 42bb26f284ec4151fbaa7c3180177dbbea7ad6efd175a6fe5a26b677ef9ee910
pub static UTXO_BALANCE: [u8; 32] = [
  66, 187, 38, 242, 132, 236, 65, 81,
  251, 170, 124, 49, 128, 23, 125, 187,
  234, 122, 214, 239, 209, 117, 166, 254,
  90, 38, 182, 119, 239, 158, 233, 16
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('utxo-nonce').slice(2), 'hex')
// )
// 6657849370667d5ff108ecc3ad36d76500c0ebf95aa4602ddabd9552023b187a
pub static UTXO_NONCE: [u8; 32] = [
  102, 87, 132, 147, 112, 102, 125,
  95, 241, 8, 236, 195, 173, 54, 215,
  101, 0, 192, 235, 249, 90, 164, 96,
  45, 218, 189, 149, 82, 2, 59, 24, 122
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('total-num-utxos').slice(2), 'hex')
// )
// 7651d70711827379e018a45253f680f104f3c978ed059940e7364f6676da1754
pub static TOTAL_NUM_UTXOS: [u8; 32] = [
  118, 81, 215, 7, 17, 130, 115, 121,
  224, 24, 164, 82, 83, 246, 128, 241,
  4, 243, 201, 120, 237, 5, 153, 64,
  231, 54, 79, 102, 118, 218, 23, 84
];
