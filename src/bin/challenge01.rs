use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let decoded_hex = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?;

    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        radix64::STD.encode(decoded_hex.as_slice())
    );

    Ok(())
}
