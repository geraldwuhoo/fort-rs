use wasm_bindgen::prelude::*;

use fort_rs::{PasswordGenerator, PasswordGeneratorAlgo};

#[wasm_bindgen]
pub struct PasswordGeneratorJs {
    password_generator: PasswordGenerator,
    template_names: Vec<JsValue>,
}

#[wasm_bindgen]
impl PasswordGeneratorJs {
    pub fn new(algo: &str, key: &str) -> Result<PasswordGeneratorJs, JsError> {
        // Convert string to respective algorithm enum
        let algo_enum = match algo {
            "Sha512" => PasswordGeneratorAlgo::Sha512,
            "Sha3" => PasswordGeneratorAlgo::Sha3,
            _ => return Err(JsError::new("Invalid hash algorithm!")),
        };

        // Create password generator and list of template names
        let password_generator = match PasswordGenerator::new(algo_enum, key) {
            Ok(gen) => gen,
            Err(_) => return Err(JsError::new("Failed to create password generator")),
        };
        let template_names: Vec<JsValue> = password_generator
            .templates
            .keys()
            .map(|key| JsValue::from(key.clone()))
            .collect();

        Ok(Self {
            password_generator,
            template_names,
        })
    }

    pub fn create_site_password(&mut self, seed: &str, options: &str) -> Result<String, JsError> {
        match self.password_generator.create_site_password(seed, options) {
            Ok(s) => Ok(s),
            Err(_) => Err(JsError::new("Unable to create site password")),
        }
    }

    pub fn get_template_names(&self) -> Vec<JsValue> {
        self.template_names.clone()
    }
}
