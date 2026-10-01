(function () {
  "use strict";
  var EMAIL = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
  var PW = {
    len: function (v) { return v.length >= 8; },
    upper: function (v) { return /[A-Z]/.test(v); },
    lower: function (v) { return /[a-z]/.test(v); },
    num: function (v) { return /\d/.test(v); },
    sym: function (v) { return /[^A-Za-z0-9]/.test(v); }
  };

  function message(input, form) {
    var v = input.value, rules = (input.dataset.rules || "").split(" "), label = (input.labels[0] || {}).textContent || "This field";
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      if (r === "required" && !v.trim()) return label + " is required.";
      if (r === "email" && v && !EMAIL.test(v.trim())) return "Enter a valid email address.";
      if (r === "password" && v && Object.keys(PW).some(function (k) { return !PW[k](v); })) return "Password doesn't meet all requirements.";
      if (r.indexOf("match:") === 0 && v !== form.elements[r.slice(6)].value) return "Passwords do not match.";
    }
    return "";
  }

  function show(input, msg) {
    var box = input.closest(".field");
    box.classList.toggle("invalid", !!msg);
    box.querySelector(".field-error").textContent = msg;
    input.setAttribute("aria-invalid", msg ? "true" : "false");
  }

  document.querySelectorAll("form[data-validate]").forEach(function (form) {
    var inputs = form.querySelectorAll("[data-rules]");
    inputs.forEach(function (input) {
      input.addEventListener("blur", function () { if (input.value) show(input, message(input, form)); });
      input.addEventListener("input", function () {
        if (input.closest(".field").classList.contains("invalid")) show(input, message(input, form));
        if (input.id === "password") updateReqs(input.value);
      });
    });

    form.addEventListener("submit", function (e) {
      if (form.dataset.submitting) { e.preventDefault(); return; } // block double submits
      var first = null;
      inputs.forEach(function (input) {
        var m = message(input, form);
        show(input, m);
        if (m && !first) first = input;
      });
      if (first) { e.preventDefault(); first.focus(); return; }
      form.dataset.submitting = "1";
      var btn = form.querySelector("[data-loading]");
      if (btn) {
        btn.classList.add("is-loading");
        btn.setAttribute("aria-busy", "true");
        btn.querySelector(".btn-label").textContent = btn.dataset.loading;
        btn.querySelector(".spinner-border").classList.remove("d-none");
      }
    });
  });

  // Show / hide password
  document.querySelectorAll(".toggle-pw").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.toggle), show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
      btn.querySelector("i").className = "bi " + (show ? "bi-eye-slash" : "bi-eye");
      input.focus();
    });
  });

  function updateReqs(v) {
    document.querySelectorAll("#pw-reqs li").forEach(function (li) {
      var ok = PW[li.dataset.req](v);
      li.classList.toggle("met", ok);
      li.querySelector("i").className = "bi " + (ok ? "bi-check-circle-fill" : "bi-circle");
    });
  }

  // Copy-to-clipboard buttons
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.dataset.copy;
      var done = function () {
        btn.classList.add("copied"); btn.querySelector("i").className = "bi bi-check2";
        setTimeout(function () { btn.classList.remove("copied"); btn.querySelector("i").className = "bi bi-clipboard"; }, 1800);
      };
      if (navigator.clipboard) { navigator.clipboard.writeText(text).then(done); }
      else { var t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select(); document.execCommand("copy"); t.remove(); done(); }
    });
  });

  // Re-enable the form if the user navigates back (bfcache)
  window.addEventListener("pageshow", function (e) {
    if (e.persisted) location.reload();
  });
})();
