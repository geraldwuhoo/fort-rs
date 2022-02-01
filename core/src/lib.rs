use std::collections::HashMap;
use std::io;

use anyhow::Result;
use hmac::{Hmac, Mac, NewMac};
use scrypt;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Site {
    counter: u32,
    template_name: String,
    length: u32,
}

impl Default for Site {
    fn default() -> Self {
        Self {
            counter: 0,
            template_name: "All".to_string(),
            length: 64,
        }
    }
}

pub struct PasswordGenerator {
    hmac: PasswordGeneratorHmac,
    pub templates: HashMap<String, Vec<char>>,
    sites_settings: Option<HashMap<String, Site>>,
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

    pub fn create_site_password(
        &mut self,
        site_name: &str,
        counter: u32,
        pass_chars: &Vec<char>,
        length: u32,
    ) -> Result<String> {
        // Define pattern matching macro
        macro_rules! match_hmac {
            ($value:expr, $pattern:pat => $result:expr) => {
                match $value {
                    PasswordGeneratorHmac::HmacSha512($pattern) => $result,
                    PasswordGeneratorHmac::HmacSha3($pattern) => $result,
                }
            };
        }
        // Create key using seed
        let seed = format!("{}{}{}", site_name.len(), site_name, counter);
        let site_key: Vec<u8> = match_hmac!(self, hmac => {
            hmac.update(seed.as_bytes());
            hmac.finalize_reset().into_bytes().to_vec()
        });

        // Create the password, using the byte array to index into the valid password characters
        let mut password = String::new();
        for i in site_key {
            password.push(pass_chars[i as usize % pass_chars.len()]);
        }

        Ok(password[..length as usize].to_string())
    }
}

impl PasswordGenerator {
    pub fn new(
        algo: PasswordGeneratorAlgo,
        key: &str,
        site_settings: Option<HashMap<String, Site>>,
    ) -> Result<Self> {
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

        Ok(Self {
            hmac,
            templates,
            sites_settings: site_settings,
        })
    }

    pub fn create_site_password(&mut self, site_name: &str) -> Result<String> {
        // Get the password settings for this site
        let default_settings = Site {
            ..Default::default()
        };
        let default_sites_settings: HashMap<String, Site> = HashMap::new();
        let site_settings = self
            .sites_settings
            .as_ref()
            .unwrap_or(&default_sites_settings)
            .get(site_name)
            .unwrap_or(&default_settings);

        // Get the password template from the templates map
        let pass_chars = self
            .templates
            .get(&site_settings.template_name)
            .ok_or(io::Error::new(
                io::ErrorKind::NotFound,
                "Password template not found.",
            ))?;

        self.hmac.create_site_password(
            site_name,
            site_settings.counter,
            pass_chars,
            site_settings.length,
        )
    }

    pub fn create_site_password_raw(
        &mut self,
        site_name: &str,
        counter: u32,
        template_name: &str,
        length: u32,
    ) -> Result<String> {
        // Get the password template from the templates map
        let pass_chars = self.templates.get(template_name).ok_or(io::Error::new(
            io::ErrorKind::NotFound,
            "Password template not found.",
        ))?;

        self.hmac
            .create_site_password(site_name, counter, pass_chars, length)
    }
}
