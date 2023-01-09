pub fn pkcs7_pad<const N: usize>(bytes: &[u8]) -> [u8; N] {
    assert!(bytes.len() <= N);

    let mut block = [(N - bytes.len()) as u8; N];
    block[..bytes.len()].clone_from_slice(bytes);

    block
}

pub fn pkcs7_strip(bytes: &[u8]) -> Vec<u8> {
    if let Ok(stripped) = try_pkcs7_strip(bytes) {
        stripped
    } else {
        Vec::from(bytes)
    }
}

pub fn try_pkcs7_strip(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    if bytes.is_empty() {
        Ok(vec![])
    } else {
        let last_byte = bytes[bytes.len() - 1];

        if (last_byte as usize) < bytes.len()
            && bytes[bytes.len() - last_byte as usize..].iter().all(|&b| b == last_byte) {

            Ok(Vec::from(&bytes[..bytes.len() - last_byte as usize]))
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::pkcs7::{pkcs7_pad, pkcs7_strip};

    #[test]
    fn test_pkcs7_strip() {
        assert_eq!(
            "This should not be modified".as_bytes(),
            pkcs7_strip("This should not be modified".as_bytes())
        );

        let padded: [u8; 16] = pkcs7_pad("admin".as_bytes());

        assert_eq!(
            "admin".as_bytes(),
            pkcs7_strip(&padded)
        );
    }
}
