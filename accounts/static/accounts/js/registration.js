// registration.js
(function(){
  const form = document.getElementById("regForm");
  const emailEl = document.getElementById("email");
  const passEl = document.getElementById("password");
  const confirmEl = document.getElementById("confirm_password");
  const terms = document.getElementById("terms");
  const captchaEl = document.getElementById("captcha");

  const gmailRegex = /^[A-Za-z0-9._%+-]+@gmail\.com$/;
  const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#\$%\^&\*]).{8,}$/;

  form.addEventListener("submit", function(e){
    let ok = true;
    // email
    if(!gmailRegex.test(emailEl.value.trim())){
      emailEl.classList.add("is-invalid");
      document.getElementById("emailError").innerText = "Use a valid Gmail address";
      ok = false;
    } else { emailEl.classList.remove("is-invalid"); }

    // password
    if(!passRegex.test(passEl.value)){
      passEl.classList.add("is-invalid");
      document.getElementById("passError").innerText = "Weak password - must include uppercase, lowercase, digit and special char.";
      ok = false;
    } else { passEl.classList.remove("is-invalid"); }

    // confirm
    if(passEl.value !== confirmEl.value){
      confirmEl.classList.add("is-invalid");
      document.getElementById("confirmError").innerText = "Passwords do not match.";
      ok = false;
    } else { confirmEl.classList.remove("is-invalid"); }

    // terms
    if(!terms.checked){
      terms.classList.add("is-invalid");
      ok = false;
    } else { terms.classList.remove("is-invalid"); }

    // captcha basic non-empty check (server will verify correctness)
    if(captchaEl.value.trim() === ""){
      captchaEl.classList.add("is-invalid");
      document.getElementById("captchaError").innerText = "Solve the captcha.";
      ok = false;
    } else { captchaEl.classList.remove("is-invalid"); }

    if(!ok){
      e.preventDefault();
    }
  });
})();