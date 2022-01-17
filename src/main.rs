use anyhow::Result;
use hmac::{Hmac, Mac, NewMac};
use scrypt;
use sha2::Sha512;
use std::io;
use log::debug;

fn main() -> Result<()> {
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

    // Create master key bytearray from passphrase using scrypt.
    let master_key = create_master_key(&key)?;
    debug!("master_key: {:?}", &master_key);

    // Create hmac generator object from the master key.
    let mut mac = create_hmac(&master_key)?;

    loop {
        // Get site name from user.
        println!("Enter site name:");
        let mut site_name = String::new();
        io::stdin()
            .read_line(&mut site_name)
            .expect("Failed to read line");

        // Create the site key using the hmac generator and the site name as seed.
        let seed = format!("{}{}", site_name.len(), site_name);
        let site_key = create_site_key(&mut mac, &seed);
        debug!("site_key: {:?}", &site_key);

        // Create the password, using the byte array to index into the valid password characters
        let mut password = String::new();
        for i in site_key {
            password.push(pass_chars[i as usize % pass_chars.len()]);
        }

        println!("{}", password);
    }
}

fn create_master_key(key: &str) -> Result<[u8; 64]> {
    let mut master_key: [u8; 64] = [0; 64];
    let params = scrypt::Params::new(15, 8, 2)?;

    scrypt::scrypt(key.as_bytes(), b"", &params, &mut master_key)?;

    Ok(master_key)
}

fn create_hmac(key: &[u8]) -> Result<Hmac<Sha512>> {
    let mac = Hmac::<Sha512>::new_from_slice(&key)?;
    Ok(mac)
}

fn create_site_key(mac: &mut Hmac<Sha512>, seed: &str) -> Vec<u8> {
    mac.update(seed.as_bytes());
    mac.finalize_reset().into_bytes().to_vec()
}
