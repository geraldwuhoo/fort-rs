import init, { PasswordGeneratorJs } from "./pkg/fort_rs_wasm.js";

init().then(() => {
  try {
    const password_generator = PasswordGeneratorJs.new("Sha512", "password");
    const template_names = password_generator.get_template_names();
    console.log(password_generator.create_site_password("example.com", template_names[0]));
    console.log(password_generator.create_site_password("example.com", template_names[1]));
  } catch (err) {
    console.log(err);
  }
});
