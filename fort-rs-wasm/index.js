import init, { PasswordGeneratorJs } from "./pkg/fort_rs_wasm.js";

init().then(() => {
  let password_generator;
  let password;
  const password_output = document.getElementById("password");

  // Create the password generator. This is only run once at the beginning of the program.
  const initialize_password_generator = () => {
    // Get the master password supplied by user and attempt to create a password generator.
    const master_password = document.getElementById("master").value;
    try {
      password_generator = PasswordGeneratorJs.new("Sha512", master_password);
    } catch (err) {
      console.log(err);
      return;
    }
    const template_names = password_generator.get_template_names();

    // Show the site generation fields.
    document.getElementById("site").hidden = false;
    document.getElementById("length").hidden = false;
    document.getElementById("lengthValue").textContent = document.getElementById("length").value;

    // Generate radio buttons for all password template options.
    template_names.forEach((value, i) => {
      let label = document.createElement("label");
      label.textContent = value;
      let input = document.createElement("input");
      input.type = "radio";
      input.name = "option";
      input.value = value;
      if (i === 0) {
        input.checked = true;
      }
      input.onclick = create_site_password;
      document.getElementById("options").appendChild(input);
      document.getElementById("options").appendChild(label);
    });

    // Hide the initial password generator creator.
    document.getElementById("master").hidden = true;
    document.getElementById("initialize").hidden = true;
  };

  // Create password for particular site. This expects the password generator to already be created, and only runs upon site update or password template update.
  const create_site_password = () => {
    const site = document.getElementById("site").value;
    const template = document.querySelector('input[name="option"]:checked').value;
    const length = document.getElementById("length").value;
    document.getElementById("lengthValue").textContent = length;

    if (site === "") {
      // Set password to empty if no site is given
      password = "";
      password_output.textContent = "";
    } else {
      // Generate a password with the specified length and site
      try {
        password = password_generator.create_site_password(site, template);
        password_output.textContent = password.slice(0, length);
      } catch (err) {
        console.log(err);
      }
    }
  };

  // Adjust the length of the password whenever the slider is moved. This avoids recomputation.
  const adjust_length = () => {
    const length = document.getElementById("length").value;
    document.getElementById("lengthValue").textContent = length;

    if (document.getElementById("site").value !== "") {
      password_output.textContent = password.slice(0, length);
    }
  }

  document.getElementById("initialize").addEventListener("click", initialize_password_generator);
  document.getElementById("master").addEventListener("keyup", e => {
    if (e.key === 'Enter') {
      initialize_password_generator();
    }
  });
  document.getElementById("site").addEventListener("keyup", create_site_password);
  document.getElementById("length").addEventListener("input", adjust_length);
});
