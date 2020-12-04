use serde::{
    de::{self, Deserializer, Visitor},
    ser::Serializer,
};
use std::fmt;

pub mod data {
    use super::*;
    use crate::types::{Byte, Bytes};

    pub fn serialize<S>(value: &[Byte], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(value)))
    }

    struct DataVisitor;

    impl<'de> Visitor<'de> for DataVisitor {
        type Value = Bytes;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a hex string - \"0x...\"")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            hex::decode(&value[2..]).map_err(de::Error::custom)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DataVisitor)
    }
}

pub mod compensation {
    use super::*;

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    struct CompensationVisitor;

    impl<'de> Visitor<'de> for CompensationVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an integer between 0 and 2^63 - 1 as a string - stringified base 10")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value.parse().map_err(de::Error::custom)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CompensationVisitor)
    }
}
