quick_error! {
    #[derive(Debug)]
    pub enum AppError {
        Custom(err: String) {
            from()
            from(err: &str) -> (err.into())
            display("✘ Program Error!\n{}", err)
        }
        IOError(err: std::io::Error) {
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
        Base58Error(err: crate::base58::Error) {
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
        EosPrimitivesError(err: eos_primitives::Error) {
            from()
            display("✘ Eos Primitives Error!\n✘ {:?}", err)
        }
        BitcoinHexError(err: bitcoin_hashes::hex::Error) {
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
        BitcoinHashError(err: bitcoin_hashes::Error) {
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
        EosPrimitivesNamesError(err: eos_primitives::ParseNameError) {
            from()
            display("✘ Eos Primitives Names Error!\n✘ {}", err)
        }
        EthAbiError(err: ethabi::Error) {
            from()
            display("✘ Eth ABI  Error!\n✘ {}", err)
        }
        RlpDecoderError(err: rlp::DecoderError) {
            from()
            display("✘ RLP Decoder Error!\n✘ {}", err)
        }
        NoneError(err: &'static str) {
            display("✘ None Error!\n✘ {}", err)
        }
    }
}
