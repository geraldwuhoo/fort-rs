use anyhow::Result;
use clap::Parser;
use fort_rs::{PasswordGenerator, PasswordGeneratorAlgo, Site};
use std::{collections::HashMap, fs::File, io};

#[derive(Parser, Debug)]
#[clap(author, version)]
struct Args {
    // Path to sites settings.json
    #[clap(short, long)]
    filepath: Option<String>,
}

fn main() -> Result<()> {
    // Attempt to open state json file from command line args
    let args = Args::parse();
    let sites: Option<HashMap<String, Site>> = match args.filepath {
        Some(filepath) => {
            let f = File::open(filepath)?;
            Some(serde_json::from_reader(f)?)
        }
        None => None,
    };

    // Get master passphrase from user.
    println!("Enter master password:");
    let mut master_password = String::new();
    io::stdin()
        .read_line(&mut master_password)
        .expect("Failed to read line");
    let master_password = master_password.trim();

    let mut password_generator =
        PasswordGenerator::new(PasswordGeneratorAlgo::Sha512, &master_password, sites)
            .expect("Failed to create password generator.");

    loop {
        // Get site name from user.
        println!("Enter site name:");
        let mut site_name = String::new();
        io::stdin()
            .read_line(&mut site_name)
            .expect("Failed to read line");
        let site_name = site_name.trim();

        // Generate password using user settings
        let password = match password_generator.create_site_password(site_name) {
            Ok(password) => password,
            Err(error) => {
                println!("{}", error);
                continue;
            }
        };

        println!("{}", password);
    }
}
