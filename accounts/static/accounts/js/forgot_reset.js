// accounts/static/accounts/js/forgot_reset.js
(function(){
  // Email regex for gmail or general? Using general here:
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#\$%\^&\*]).{8,}$/;

  // Forgot form
  const forgotForm = document.getElementById("forgotForm");
  if(forgotForm){
    forgotForm.addEventListener("submit", function(e){
      let ok = true;
      const email = document.getElementById("email");
      const captcha = document.getElementById("captcha");

      if(!emailRegex.test(email.value.trim())){
        ok = false;
        email.classList.add("is-invalid");
        document.getElementById("emailError").innerText = "Enter a valid email.";
      } else { email.classList.remove("is-invalid"); }

      if(captcha.value.trim() === ""){
        ok = false;
        captcha.classList.add("is-invalid");
        document.getElementById("captchaError").innerText = "Solve the captcha.";
      } else { captcha.classList.remove("is-invalid"); }

      if(!ok) e.preventDefault();
    });
  }

  // Reset form
  const resetForm = document.getElementById("resetForm");
  if(resetForm){
    resetForm.addEventListener("submit", function(e){
      let ok = true;
      const pass = document.getElementById("password");
      const conf = document.getElementById("confirm_password");

      if(!passRegex.test(pass.value)){
        ok = false;
        pass.classList.add("is-invalid");
        document.getElementById("passError").innerText = "Weak password - include uppercase, lowercase, digit, special char.";
      } else { pass.classList.remove("is-invalid"); }

      if(pass.value !== conf.value){
        ok = false;
        conf.classList.add("is-invalid");
        document.getElementById("confirmError").innerText = "Passwords do not match.";
      } else { conf.classList.remove("is-invalid"); }

      if(!ok) e.preventDefault();
    });
  }
})();