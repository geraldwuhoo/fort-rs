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

pub enum PasswordGeneratorHmac {
    HmacSha512(Hmac<Sha512>),
    HmacSha3(Hmac<Sha3_512>),
}

pub struct PasswordGenerator {
    hmac: PasswordGeneratorHmac,
    templates: HashMap<String, Vec<char>>,
}

impl PasswordGeneratorHmac {
    pub fn new(algo: PasswordGeneratorAlgo, key: &str) -> Result<Self> {
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

fn main() -> Result<()> {
    // Get master passphrase from user.
    println!("Enter master passphrase:");
    let mut key = String::new();
    io::stdin()
        .read_line(&mut key)
        .expect("Failed to read line");

    let mut password_generator = PasswordGenerator::new(PasswordGeneratorAlgo::Sha512, &key)?;

    loop {
        // Get site name from user.
        println!("Enter site name:");
        let mut site_name = String::new();
        io::stdin()
            .read_line(&mut site_name)
            .expect("Failed to read line");
        let site_name = site_name.trim();
        let seed = format!("{}{}", site_name.len(), site_name);

        // Get the password type from user.
        println!("Enter password type {:?}:", password_generator.templates.keys());
        let mut password_type = String::new();
        io::stdin()
            .read_line(&mut password_type)
            .expect("Failed to read line");
        let password_type = password_type.trim();

        let password = match password_generator.create_site_password(&seed, &password_type) {
            Ok(password) => password,
            Err(error) => {
                println!("{}", error);
                continue;
            }
        };

        println!("{}", password);
    }
}
