use std::collections::HashMap;
use std::io;

use anyhow::Result;
use hmac::{Hmac, Mac, NewMac};
use scrypt;
use sha2::Sha512;
use sha3::Sha3_512;

pub enum PasswordGeneratorAlgo {
    Sha512,
    Sha3,
}

enum PasswordGeneratorHmac {
    HmacSha512(Hmac<Sha512>),
    HmacSha3(Hmac<Sha3_512>),
}

pub struct PasswordGenerator {
    hmac: PasswordGeneratorHmac,
    pub templates: HashMap<String, Vec<char>>,
}

impl PasswordGeneratorHmac {
    fn new(algo: PasswordGeneratorAlgo, key: &str) -> Result<Self> {
        // Create master key for Hmac
        let mut master_key: [u8; 64] = [0; 64];
        let (log_n, r, p) = (15, 8, 2);
        let params = scrypt::Params::new(log_n, r, p)?;
        scrypt::scrypt(key.as_bytes(), b"", &params, &mut master_key)?;

        // Create desired Hmac from master key
        match algo {
            PasswordGeneratorAlgo::Sha512 => Ok(Self::HmacSha512(
                Hmac::<Sha512>::new_from_slice(&master_key).expect("HMAC accepts any key length"),
            )),
            PasswordGeneratorAlgo::Sha3 => Ok(Self::HmacSha3(
                Hmac::<Sha3_512>::new_from_slice(&master_key).expect("HMAC accepts any key length"),
            )),
        }
    }
}

impl PasswordGenerator {
    pub fn new(algo: PasswordGeneratorAlgo, key: &str) -> Result<Self> {
        // Create hmac object (must be mutable for updates)
        let hmac = PasswordGeneratorHmac::new(algo, key)?;
        // Create all the password templates
        let templates: HashMap<String, Vec<char>> = [
            (
                "All".to_string(),
                "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()[]{}<>"
                    .chars()
                    .collect(),
            ),
            (
                "Alphanumeric".to_string(),
                "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789"
                    .chars()
                    .collect(),
            ),
        ]
        .iter()
        .cloned()
        .collect();

        Ok(Self { hmac, templates })
    }

    pub fn create_site_password(&mut self, seed: &str, options: &str) -> Result<String> {
        // Define pattern matching macro
        macro_rules! match_hmac {
            ($value:expr, $pattern:pat => $result:expr) => {
                match $value {
                    PasswordGeneratorHmac::HmacSha512($pattern) => $result,
                    PasswordGeneratorHmac::HmacSha3($pattern) => $result,
                }
            };
        }

        // Create key using site as the seed
        let site_key: Vec<u8> = match_hmac!(&mut self.hmac, hmac => {
            hmac.update(seed.as_bytes());
            hmac.finalize_reset().into_bytes().to_vec()
        });

        // Create the password, using the byte array to index into the valid password characters
        let mut password = String::new();
        let pass_chars = self.templates.get(options).ok_or(io::Error::new(
            io::ErrorKind::NotFound,
            "Password type not found.",
        ))?;
        for i in site_key {
            password.push(pass_chars[i as usize % pass_chars.len()]);
        }

        Ok(password)
    }
}