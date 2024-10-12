
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use rsa::Pkcs1v15Encrypt;
use rand::rngs::OsRng;
use std::io;

pub fn read_rsa_key(pem: &str) -> Result<RsaPublicKey, io::Error> {
    match RsaPublicKey::from_pkcs1_pem(pem) {
        Ok(public_key) => Ok(public_key),
        Err(e) => {
            eprintln!("Error reading RSA key: {}", e);
            Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid RSA Key"))
        }
    }
}



pub fn rsa_encrypt_buffer(buffer: &[u8], pub_key: &RsaPublicKey) -> Result<Vec<u8>, io::Error> {
    let mut rng = OsRng;

    match pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, buffer) {
        Ok(enc_data) => Ok(enc_data),
        Err(e) => {
            eprintln!("Error in enc_buffer: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, "Encryption failed"))
        }
    }
}
