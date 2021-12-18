//! # The pToken error enum.
quick_error! {
    #[derive(Debug)]
    pub enum AppError {
        Custom(err: String) {
            from()
            from(err: &str) -> (err.into())
            display("✘ Program Error!\n{}", err)
        }
        IoError(err: std::io::Error) {
            from()
            display("✘ I/O Error!\n✘ {}", err)
        }
        HexError(err: hex::FromHexError) {
            from()
            display("✘ Hex Error!\n✘ {}", err)
        }
        CryptoError(err: secp256k1::Error) {
            from()
            display("✘ Crypto Error!\n✘ {}", err)
        }
        BitcoinCryptoError(err: bitcoin::secp256k1::Error) {
            from()
            display("✘ Bitcoin Crypto Error!\n✘ {}", err)
        }
        Base58Error(err: bitcoin::util::base58::Error) {
            from()
            display("✘ Base58 Error!\n✘ {}", err)
        }
        SerdeJsonError(err: serde_json::Error) {
            from()
            display("✘ Serde-Json Error!\n✘ {}", err)
        }
        FromUtf8Error(err: std::str::Utf8Error) {
            from()
            display("✘ From utf8 error!\n✘ {}", err)
        }
        SetLoggerError(err: log::SetLoggerError) {
            from(log::SetLoggerError)
            display("✘ Error setting up logger!\n✘ {}", err)
        }
        ParseIntError(err: std::num::ParseIntError) {
            from()
            display("✘ Parse Int Error!\n✘ {}", err)
        }
        ChronoError(err: chrono::ParseError) {
            from()
            display("✘ Chrono Error!\n✘ {}", err)
        }
        EosPrimitivesError(err: eos_chain::Error) {
            from()
            display("✘ EOS Chain Error!\n✘ {:?}", err)
        }
        BitcoinHexError(err: bitcoin::hashes::hex::Error) {
            from()
            display("✘ Bitcoin Hex Error!\n✘ {}", err)
        }
        SystemTimeError(err: std::time::SystemTimeError) {
            from()
            display("✘ System Time Error!\n✘ {}", err)
        }
        FromSliceError(err: std::array::TryFromSliceError) {
            from(std::array::TryFromSliceError)
            display("✘ From slice Error!\n✘ {}", err)
        }
        BitcoinHashError(err: bitcoin::hashes::Error) {
            from()
            display("✘ Bitcoin Hash Error!\n✘ {}", err)
        }
        BitcoinError(err: bitcoin::consensus::encode::Error) {
            from()
            display("✘ Bitcoin Error!\n✘ {}", err)
        }
        BitcoinAddressError(err: bitcoin::util::address::Error) {
            from()
            display("✘ Bitcoin Address Error!\n✘ {}", err)
        }
        BitcoinScriptError(err: bitcoin::blockdata::script::Error) {
            from()
            display("✘ Bitcoin Script Error!\n✘ {}", err)
        }
        BitcoinKeyError(err: bitcoin::util::key::Error) {
            from()
            display("✘ Bitcoin Key Error!\n✘ {}", err)
        }        EosPrimitivesNamesError(err: eos_chain::ParseNameError) {
            from()
            display("✘ EOS Chain Names Error!\n✘ {}", err)
        }
        EthAbiError(err: ethabi::Error) {
            from()
            display("✘ ETH ABI Error!\n✘ {}", err)
        }
        RlpDecoderError(err: rlp::DecoderError) {
            from()
            display("✘ RLP Decoder Error!\n✘ {}", err)
        }
        FromDecStrErr(err: ethereum_types::FromDecStrErr) {
            from()
            display("✘ Ethereum types `from_dec_str` err: {}", err)
        }
        EosParseAssetErr(err: eos_chain::ParseAssetError) {
            from()
            display("✘ EOS parse asset error: {:?}", err)
        }
        EosWriteError(err: eos_chain::WriteError) {
            from()
            display("✘ EOS write error: {:?}", err)
        }
        TryFromError(err: std::num::TryFromIntError) {
            from()
            display("✘ `TryFrom` error: {:?}", err)
        }
        TryFromSliceError(err: std::array::TryFromSliceError) {
            from()
            display("✘ `TryFromSlice` error: {:?}", err)
        }
        NoneError(err: &'static str) {
            display("✘ None Error!\n✘ {}", err)
        }
    }
}
