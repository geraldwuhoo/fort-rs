use anyhow::Result;
use hmac::{Hmac, Mac, NewMac};
use scrypt;
use sha2::Sha512;
use sha3::Sha3_512;
use std::io;

pub enum PasswordGeneratorAlgo {
    Sha512,
    Sha3,
}

pub enum PasswordGenerator {
    HmacSha512(Hmac<Sha512>),
    HmacSha3(Hmac<Sha3_512>),
}

impl PasswordGenerator {
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

    pub fn create_site_password(&mut self, seed: &str, pass_chars: &Vec<char>) -> String {
        // Define pattern matching macro
        macro_rules! match_hmac {
            ($value:expr, $pattern:pat => $result:expr) => {
                match $value {
                    Self::HmacSha512($pattern) => $result,
                    Self::HmacSha3($pattern) => $result,
                }
            };
        }

        // Create key using site as the seed
        let site_key: Vec<u8> = match_hmac!(self, hmac => {
            hmac.update(seed.as_bytes());
            hmac.finalize_reset().into_bytes().to_vec()
        });

        // Create the password, using the byte array to index into the valid password characters
        let mut password = String::new();
        for i in site_key {
            password.push(pass_chars[i as usize % pass_chars.len()]);
        }

        password
    }
}

fn main() -> Result<()> {
    // Valid password characters
    let pass_chars: Vec<char> =
        "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()"
            .chars()
            .collect();

    // Get master passphrase from user.
    println!("Enter master passphrase:");
    let mut key = String::new();
    io::stdin()
        .read_line(&mut key)
        .expect("Failed to read line");

    let mut password_generator = PasswordGenerator::new(PasswordGeneratorAlgo::Sha3, &key)?;

    loop {
        // Get site name from user.
        println!("Enter site name:");
        let mut site_name = String::new();
        io::stdin()
            .read_line(&mut site_name)
            .expect("Failed to read line");

        // Create the site key using the hmac generator and the site name as seed.
        let seed = format!("{}{}", site_name.len(), site_name);
        let password = password_generator.create_site_password(&seed, &pass_chars);

        println!("{}", password);
    }
}
