extern crate core;

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        hex::decode("746865206b696420646f6e277420706c6179")?,
        xor(
            hex::decode("1c0111001f010100061a024b53535009181c")?.as_slice(),
            hex::decode("686974207468652062756c6c277320657965")?.as_slice(),
        )?
    );

    Ok(())
}

fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if a.len() != b.len() {
        Err("Mismatched buffer lengths")
    } else {
        Ok(a.iter()
            .zip(b.iter())
            .map(|(a, b)| a ^ b)
            .collect())
    }
}
