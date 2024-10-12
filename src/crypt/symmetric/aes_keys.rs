use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize};

/*  
    struct keys hold two value it's by default genrate 32 byte (256 bit) key
    for encryption but you can use diff fn for generating diff length of key
    ...
    ...
    ...

*/

// This struct will be zeroized on drop
pub struct Keys {
    pub key: [u8; 32],
    pub iv: [u8; 16],
}

impl Zeroize for Keys {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Keys {
    pub fn new() -> Self {
        Self {
            key : Self::generate_key32(),
            iv: Self::generate_iv(),
        }
    }

    fn generate_key32() -> [u8; 32] { // 256-bit key
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    fn generate_iv() -> [u8; 16] { // 128-bit IV
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        iv
    }
}