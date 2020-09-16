#![cfg(test)]

pub fn get_sample_message_to_sign() -> &'static str {
    "Provable pToken!"
}

pub fn get_sample_message_to_sign_bytes() -> &'static [u8] {
    get_sample_message_to_sign()
        .as_bytes()
}
