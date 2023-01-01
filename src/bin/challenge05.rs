use std::error::Error;
use indoc::indoc;

const CLEARTEXT: &str = indoc! {"
    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal
"};

const KEY: &[u8] = "ICE".as_bytes();

const EXPECTED_CIPHERTEXT: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

fn main() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        hex::decode(EXPECTED_CIPHERTEXT)?,
        repeating_key_xor(CLEARTEXT.as_bytes(), KEY)
    );

    Ok(())
}

fn repeating_key_xor(cleartext: &[u8], key: &[u8]) -> Vec<u8> {
    cleartext
        .iter()
        .zip(key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}
