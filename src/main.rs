use std::io;

use fort_rs::{PasswordGenerator, PasswordGeneratorAlgo};

fn main() {
    // Get master passphrase from user.
    println!("Enter master passphrase:");
    let mut key = String::new();
    io::stdin()
        .read_line(&mut key)
        .expect("Failed to read line");

    let mut password_generator = PasswordGenerator::new(PasswordGeneratorAlgo::Sha512, &key)
        .expect("Failed to create password generator.");

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
        println!(
            "Enter password type {:?}:",
            password_generator.templates.keys()
        );
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
