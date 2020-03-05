# :closed_lock_with_key: pTokens Core

The Provable __pTokens__ core which manages the cross-chain conversions between a host and a native blockchain.

&nbsp;

***

&nbsp;

## :earth_africa: Core Overview

The __pToken__ core is a library implementing light-clients for various block-chains. The initial release involves __ETH__ as the host chain on which the __pTokens__ are manifest, and uses __BTC__ as the native chain and underlying asset.

The core library has zero network connectivity and makes no network requests. It is a push-only model, requiring external tools to gather & feed it the blocks from the chains with which the core is to interact.

In order to initialize the light-clients inside the core, an initial block from each desired chain is required. These will be the only trusted blocks in the system. Thereafter, subsequent blocks pushed to the core will undergo all the usual validation checks w/r/t to that block's veracity before appending it to the small piece of chain the light client holds.

The length of these small pieces of chain held by the core is governed by its __`canon-to-tip`__ length, which length can also be thought of as the number of __`confirmations + 1`__ required before the core will sign a transaction.

Once a block reaches __`canon-to-tip`__ number of blocks away from the tip of the chain, it becomes the __`canon-block`__. At this point, it is searched for any relevant deposit or redemption events and any required transactions are then signed and returned from the core in __`JSON`__ format.

In order to keep the light-clients thin, blocks behind the __`canon-block`__  are removed. In order to do that whilst retaining the integrity of the chain, the block to be removed is first _linked_ to the initial trusted block (the __`anchor-block`__) by hashing it together with the so-called __`linker-hash`__ (where an arbitrary constant is used for the first linkage) and the block to be removed. This way the small piece of chain inside then core can always be proven to have originated from the original trusted block.

And so thusly the core remains synced with the each blockchain, writing relevant transactions as it does so.

## :lock_with_ink_pen: Security:

The library herein is designed to be imported by an application that leverages an HSM in order to implement a secure database that adheres to the interface as defined in __`./src/traits.rs`__.

This library itself implements no such protections, except those afforded by the protected runtime of an __SGX__ environment if an __`app`__ were to leverage such technology.

Note the library can be built in __`debug`__ mode via setting the feature flag when building thusly: __`cargo build --release --features=debug`__.  If built in __`debug`__ mode, all security of the app/core combination are waived entirely, the database is entirely accessible including the private keys!

#### :warning: The core should NOT be used in `debug` mode in production! :warning:

&nbsp;

***

&nbsp;


## :point_right: API:

### submit_eth_block_to_enclave

```

pub fn submit_eth_block_to_enclave<D>(
    db: D,
    block_json_string: String
) -> Result<String>

```

❍ Submit an ETH block (& its receipts) to the enclave.  NOTE: The enclave must first have been initialized!

➔ `blockJson` Format:

A valid JSON string of an object containing the fields:

`Block`    ➔ The block header itself.

`Receipts` ➔ An array containing the block's receipts.

***

### submit_btc_block_to_enclave

```

pub fn submit_btc_block_to_enclave<D>(
    db: D,
    block_json_string: String
) -> Result<String>

```

__Action:__

Submit a BTC block to the core.  The submission material must also include an array of deposit information for `p2sh` addresses.  NOTE: The core must first have been initialized!

➔ `block_json_string` Format:

A valid `JSON` string of an object containing the fields:

`block`        ➔ The BTC block in `JSON` format.

`transactions` ➔ The transactions in HEX format.

`deposit_address_list` ➔ An array of objects:

```

  {
    `nonce`: An integer nonce.
    `eth_address`: The destination ETH address in hex.
    `btc_deposit_address`: The `p2sh` BTC deposit address.
    `eth_address_and_nonce_hash`: The `sha256d` of `eth_address + nonce`
  }

```

***

### maybe_initialize_eth_enclave

```

pub fn maybe_initialize_eth_enclave<D>(
    db: D,
    block_json_string: String,
    chain_id: u8,
    gas_price: u64,
    canon_to_tip_length: u64,
) -> Result<String>

```

__Action:__

Initializes the core with the first trusted ETH block. Ensure the block has NO transactions relevant to the pToken in it, because they'll be ignored by the core. Transactions are not verified so you may omit them and include an empty array in their place if needs be. The core will initialize its ETH-related database from this trusted block, create the ETH private-key and seal it into the database. This command will return a signed transaction to broadcast, which transaction will deploy the pToken contract to the ETH network. The core's ETH address will first need to be funded with ETH before broadcasting the deployment transaction.

➔ blocksJson Format:

A valid `JSON` string of an object containing the fields:

`block_json_string` ➔ A valid `JSON` string of and ETH block & receipts. See `submit_eth_block_to_enclave` for `JSON` format.

***

### maybe_initialize_btc_enclave

```

pub fn maybe_initialize_btc_enclave<D>(
    db: D,
    block_json_string: String,
    fee: u64,
    difficulty: u64,
    network: String,
    canon_to_tip_length: u64,
) -> Result<String>

```

__Action:__

Initializes the core with the first trusted BTC block. Ensure the block has NO transactions relevant to the pToken in it, because they'll be ignored by the core. Transactions are not verified so you may omit them and include an empty array in their place. The core will initialize its BTC related database from this trusted block, create the BTC private-key and seal it into the database.

➔ blocksJson Format:

A valid `JSON` string of an object containing the fields:

`block_json_string` ➔ A valid `JSON` string of the BTC block & transactions. See `submit_btc_block_to_enclave` for `JSON` format.

***

### get_enclave_state

```

pub fn get_enclave_state<D>(db: D) -> Result<String> where D: DatabaseInterface

```

Returns the current state of the core as pulled from the database, omitting sensitive fields such as private-keys etc.

***


### debug_get_all_utxos

```

pub fn debug_get_all_utxos<D>(db: D) -> Result<String>

```

Returns `JSON` formatted report of all the `UTXO`s currently held in the database. This function can only be called if the core is build in `debug` mode.

***

### debug_get_key_from_db

```

pub fn debug_get_key_from_db<D>(db: D, key: String) -> Result<String>

```

Get a given <key> from the database. This function can only be called if the core is built in `debug` mode.

***

### debug_get_key_from_db

```

pub fn get_latest_block_numbers<D>(db: D) -> Result<String>

```

Returns the current latest ETH & BTC block numbers seen by the core.

***

### debug_set_key_in_db_to_value

```

pub fn debug_set_key_in_db_to_value<D>(db: D, key: String, value: String) -> Result<String>

```

Set a given <key> in the database to a given <value>. This function can only be called if the core is build in `debug` mode. Note there there are __NO__ checks on the what is passed in to the database. Use at own risk!

&nbsp;

***

&nbsp;

### :wrench: Build


You need to ensure you have both __`clang`__ & __`llvm`__ (or later versions) installed on your system. Then enter the __`./app`__ directory and run:

__`❍ cargo build --release`__

#### Versions

 - __`llvm:`__ version 6.0.0 or later.
 - __`clang:`__ version 6.0.0-1ubuntu2 or later.
 - __`rustc & cargo:`__ version 1.42.0-nightly or later.

&nbsp;

***

&nbsp;

### :floppy_disk: Database Interface

The `core` implements a generic database whose interface follows:

```
pub trait DatabaseInterface {
    fn end_transaction(&self) -> Result<()>;
    fn start_transaction(&self) -> Result<()>;
    fn delete(&self, key: Bytes) -> Result<()>;
    fn get(&self, key: Bytes, data_sensitivity: Option<u8>) -> Result<Bytes>;
    fn put(&self, key: Bytes, value: Bytes, data_sensitivity: Option<u8>) -> Result<()>;
}

```

The `start_transaction` and `end_transaction` are used by the core algorithms to signal when databasing actions begin and end, allowing a consumer of the `core` to implement atomic databasing however they wish.

Further, the `sensitivity` parameter provides a way for the `core` to signal to the consumer how sensitive the data being transmitted is, giving flexibility for the `core` consumer to handle different levels of sensitive data in different ways, where `0` signifies the _least_ sensitive data, and `255` the _most_.

&nbsp;

***

&nbsp;

### :black_nib: Notes

- The eth ptoken smart-contract bytecode needs to be in the root of the directory of the binary when you run the ETH initialization step, as a file called: __`ptoken-erc777-bytecode`__.
-
- The maximum __`confs`__ possible during initialization is 255.

- There are hardcoded "safe" __ETH__ & __BTC__ addresses which are used as destinations for transactions whose actual destinations are absent or malformed when being parsed from their originating transactions.

- When initializing the core, the merkle-roots inside the __ETH__ and __BTC__ blocks are __NOT__ verified - only the block headers are checked. For smaller initialiazation material, feel free to provide empty arrays for the transactions. Ensure not relevant transactions took place in the blocks used to initialize the core.

- The light __BTC__ client implemented herein currently accepts only _two_ deposit types:

1) `p2sh` deposits made to addresses generated via the __`deposit-address-generator`__ run with the private-key emitted by the core upon BTC initialization.
2) `OP_RETURN` deposits that include in the transaction a UTXO to the `p2pkh` of the aforementioned private-key.

:warning: Neither `p2pk` nor `segwit` transactions are currently supported. Deposits made via such transactions will result in lost funds! :warning:

&nbsp;

***

&nbsp;

### :mag: Features

When importing this core library into your app, enable features in your __`Cargo.toml`__ like so:

__`pbtc_core = { version = "0.1.0", features = ["btc-on-eth"] }`__.

Currently supported features include:

 - __`debug`__ To enable debug mode.

 - __`btc-on-eth`__ For the pBTC, BTC on ETH implementation.


&nbsp;

***

&nbsp;

### :guardsman: Tests

To run the tests simply run:

__`❍ cargo +nightly test --features='<chosen-feature>'`__

&nbsp;

***

&nbsp;

### :black_nib: To Do:

- [ ] Use enum for trie node types.
- [ ] Needs method to adjust difficulty in future.
- [ ] Pass in path of bytecode as arg to the initter.
