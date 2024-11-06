use rsa::{RsaPrivateKey, RsaPublicKey};

#[derive(Clone)]
pub struct RsaKey {
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

impl RsaKey {
    pub fn new() -> Option<Self> {
        let mut rng = rand::thread_rng();

        let bits = 2048;

        match RsaPrivateKey::new(&mut rng, bits) {
            Ok(private_key) => {
                let public_key = RsaPublicKey::from(&private_key);
                Some(Self {
                    public_key,
                    private_key,
                })
            }
            _ => None,
        }
    }
}
