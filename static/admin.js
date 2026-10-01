(function () {
  "use strict";
  var modal = document.getElementById("empModal");
  if (!modal) return;
  var form = modal.querySelector("form"), title = modal.querySelector(".modal-title"), E = form.elements;
  var pwLabel = document.getElementById("pwLabel"), pwHint = document.getElementById("pwHint");
  var ADD_HINT = pwHint.textContent;

  function mode(editing) {
    E.employee_code.readOnly = editing;
    E.password.required = !editing;
    pwLabel.textContent = editing ? "New password (optional)" : "Temporary password";
    pwHint.textContent = editing ? "Leave blank to keep the current password. Entering one resets it and unlocks the account." : ADD_HINT;
    title.textContent = editing ? "Edit Employee" : "Add Employee";
    E.password.value = ""; E.password.type = "password";
  }

  document.querySelectorAll(".add-emp").forEach(function (b) {
    b.addEventListener("click", function () {
      form.reset(); mode(false);
      E.emp_id.value = ""; E.employee_code.value = b.dataset.next || "";
    });
  });

  document.querySelectorAll(".edit-emp").forEach(function (b) {
    b.addEventListener("click", function () {
      form.reset(); mode(true);
      E.emp_id.value = b.dataset.id; E.employee_code.value = b.dataset.code; E.full_name.value = b.dataset.name;
      E.email.value = b.dataset.email; E.department.value = b.dataset.dept; E.designation.value = b.dataset.desig;
      bootstrap.Modal.getOrCreateInstance(modal).show();
    });
  });

  // Show / hide and generate a compliant password
  document.getElementById("pwShow").addEventListener("click", function () {
    var show = E.password.type === "password";
    E.password.type = show ? "text" : "password";
    this.querySelector("i").className = "bi " + (show ? "bi-eye-slash" : "bi-eye");
  });
  document.getElementById("pwGen").addEventListener("click", function () {
    var sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "@#$%&*!?"], all = sets.join(""), out = [], rnd = new Uint32Array(14);
    crypto.getRandomValues(rnd);
    sets.forEach(function (s, i) { out.push(s[rnd[i] % s.length]); });
    for (var i = sets.length; i < 12; i++) out.push(all[rnd[i] % all.length]);
    for (var j = out.length - 1; j > 0; j--) { var k = rnd[12 + (j % 2)] % (j + 1); var t = out[j]; out[j] = out[k]; out[k] = t; }
    E.password.value = out.join(""); E.password.type = "text";
    document.getElementById("pwShow").querySelector("i").className = "bi bi-eye-slash";
  });

  document.querySelectorAll(".toggle-form").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
})();

// ---------- Admin attendance: edit-times modal + date picker ----------
(function () {
  "use strict";
  // Open the native picker when the date label is clicked
  document.querySelectorAll(".month-pick input").forEach(function (i) {
    i.addEventListener("click", function () { if (i.showPicker) { try { i.showPicker(); } catch (e) {} } });
  });
  var m = document.getElementById("attModal");
  if (!m) return;
  var E = m.querySelector("form").elements, name = m.querySelector(".att-name");
  document.querySelectorAll(".edit-att").forEach(function (b) {
    b.addEventListener("click", function () {
      E.user_id.value = b.dataset.id; E.check_in.value = b.dataset["in"]; E.check_out.value = b.dataset.out;
      name.textContent = b.dataset.name;
      bootstrap.Modal.getOrCreateInstance(m).show();
    });
  });
})();

// ---------- Admin tasks: create / edit modal ----------
(function () {
  "use strict";
  var m = document.getElementById("taskModal");
  if (!m) return;
  var form = m.querySelector("form"), E = form.elements, title = m.querySelector(".modal-title");
  var wrap = document.getElementById("statusWrap"), hint = document.getElementById("taskHint");
  var today = E.due_date.value;

  document.querySelectorAll(".add-task").forEach(function (b) {
    b.addEventListener("click", function () {
      form.reset(); E.task_id.value = ""; E.due_date.value = today; E.due_date.min = today;
      title.textContent = "Create Task"; wrap.hidden = true;
      hint.textContent = "The employee gets a notification as soon as the task is assigned.";
    });
  });
  document.querySelectorAll(".edit-task").forEach(function (b) {
    b.addEventListener("click", function () {
      form.reset(); E.task_id.value = b.dataset.id; E.title.value = b.dataset.title; E.project.value = b.dataset.project;
      E.assignee.value = b.dataset.user; E.priority.value = b.dataset.priority; E.status.value = b.dataset.status;
      E.due_date.removeAttribute("min"); E.due_date.value = b.dataset.due;
      title.textContent = "Edit Task"; wrap.hidden = false;
      hint.textContent = "Changing the assignee or due date notifies the employee.";
      bootstrap.Modal.getOrCreateInstance(m).show();
    });
  });
  document.querySelectorAll(".delete-task-form").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
})();

// ---------- Admin timesheets: bulk select + approve / reject ----------
(function () {
  "use strict";
  var bar = document.getElementById("bulkForm");
  if (!bar) return;
  var all = document.getElementById("selAll"), count = document.getElementById("selCount");
  var rows = Array.prototype.slice.call(document.querySelectorAll(".row-sel"));

  function checked() { return rows.filter(function (r) { return r.checked; }).length; }
  function refresh() {
    var n = checked();
    rows.forEach(function (r) { r.closest("tr").classList.toggle("is-selected", r.checked); });
    count.textContent = n; bar.hidden = n === 0;
    if (all) { all.checked = n > 0 && n === rows.length; all.indeterminate = n > 0 && n < rows.length; }
  }
  rows.forEach(function (r) { r.addEventListener("change", refresh); });
  if (all) all.addEventListener("change", function () { rows.forEach(function (r) { r.checked = all.checked; }); refresh(); });
  document.getElementById("selClear").addEventListener("click", function () { rows.forEach(function (r) { r.checked = false; }); refresh(); });

  bar.addEventListener("submit", function (e) {
    var n = checked();
    if (!n) { e.preventDefault(); return; }
    var reject = e.submitter && e.submitter.value === "reject";
    var what = n + " selected entr" + (n === 1 ? "y" : "ies");
    if (!confirm(reject ? "Reject " + what + "? Employees will be notified and can edit and resubmit." : "Approve " + what + "? Employees will be notified.")) e.preventDefault();
  });
  document.querySelectorAll(".review-form").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
  refresh();
})();

// ---------- Admin leaves: reject / revoke modal ----------
(function () {
  "use strict";
  var m = document.getElementById("leaveModal");
  if (!m) return;
  var form = m.querySelector("form"), E = form.elements, title = m.querySelector(".modal-title");
  var who = m.querySelector(".lv-who"), when = m.querySelector(".lv-when"), btn = m.querySelector(".lv-btn"), hint = document.getElementById("leaveHint");
  document.querySelectorAll(".reject-leave").forEach(function (b) {
    b.addEventListener("click", function () {
      var revoke = b.dataset.revoke === "1";
      form.reset(); E.leave_id.value = b.dataset.id; E.decision.value = "reject";
      who.textContent = b.dataset.name; when.textContent = b.dataset.period;
      title.textContent = revoke ? "Revoke approved leave" : "Reject leave request";
      btn.textContent = revoke ? "Revoke" : "Reject";
      hint.textContent = revoke ? "The employee is notified that this approved leave was cancelled." : "The employee is notified and can apply again.";
      bootstrap.Modal.getOrCreateInstance(m).show();
    });
  });
  m.addEventListener("shown.bs.modal", function () { E.note.focus(); });
})();

// ---------- Admin payroll: salary dialog, bulk "mark paid", confirmations ----------
(function () {
  "use strict";
  function inr(n) {
    n = Math.round(n * 100) / 100;
    var s = (Math.abs(n) % 1 === 0 ? Math.abs(n).toFixed(0) : Math.abs(n).toFixed(2)).split("."), w = s[0], head = w.slice(0, -3), tail = w.slice(-3), g = [];
    while (head.length > 2) { g.unshift(head.slice(-2)); head = head.slice(0, -2); }
    if (head) g.unshift(head);
    return (n < 0 ? "-" : "") + "\u20B9" + g.concat([tail]).join(",") + (s[1] ? "." + s[1] : "");
  }
  document.querySelectorAll(".pay-confirm").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  var modal = document.getElementById("salaryModal");
  if (modal) {
    var E = modal.querySelector("form").elements, who = modal.querySelector(".sal-who"), out = modal.querySelector(".sal-net");
    function preview() {
      var b = parseFloat(E.basic.value) || 0, a = parseFloat(E.allowances.value) || 0, d = parseFloat(E.deductions.value) || 0;
      out.textContent = inr(b + a - d);
    }
    ["basic", "allowances", "deductions"].forEach(function (n) { E[n].addEventListener("input", preview); });
    document.querySelectorAll(".edit-salary").forEach(function (btn) {
      btn.addEventListener("click", function () {
        E.user_id.value = btn.dataset.id; who.textContent = btn.dataset.name;
        E.basic.value = btn.dataset.basic; E.allowances.value = btn.dataset.allow || "0"; E.deductions.value = btn.dataset.ded || "0";
        preview(); bootstrap.Modal.getOrCreateInstance(modal).show();
      });
    });
  }

  var table = document.getElementById("payTable");
  if (table) {
    var bar = document.getElementById("payBulk"), count = document.getElementById("payCount"), all = document.getElementById("paySelAll");
    var boxes = function () { return Array.prototype.slice.call(table.querySelectorAll(".pay-row-chk")); };
    var update = function () {
      var n = boxes().filter(function (b) { return b.checked; }).length;
      bar.hidden = n === 0; count.textContent = n;
      if (all) all.checked = n > 0 && n === boxes().length;
    };
    if (all) all.addEventListener("change", function () { boxes().forEach(function (b) { b.checked = all.checked; }); update(); });
    boxes().forEach(function (b) { b.addEventListener("change", update); });
  }
})();

// ---------- Admin projects: add / edit dialog ----------
(function () {
  "use strict";
  document.querySelectorAll(".proj-confirm").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
  var m = document.getElementById("projectModal");
  if (!m) return;
  var form = m.querySelector("form"), E = form.elements, title = m.querySelector(".modal-title"), hint = document.getElementById("projHint");
  function sync() { E.end_date.min = E.start_date.value || ""; }
  E.start_date.addEventListener("input", sync);
  document.querySelectorAll(".add-project").forEach(function (b) {
    b.addEventListener("click", function () {
      form.reset(); E.project_id.value = ""; E.status.value = "Active"; sync();
      title.textContent = "Add Project"; hint.textContent = "Projects group tasks. Assign tasks to a project from the Tasks page.";
    });
  });
  document.querySelectorAll(".edit-project").forEach(function (b) {
    b.addEventListener("click", function () {
      form.reset(); E.project_id.value = b.dataset.id; E.name.value = b.dataset.name; E.client.value = b.dataset.client;
      E.description.value = b.dataset.desc; E.start_date.value = b.dataset.start; E.end_date.value = b.dataset.end;
      E.status.value = b.dataset.status; sync();
      title.textContent = "Edit Project"; hint.textContent = "Renaming a project also updates the project name on all of its tasks.";
      bootstrap.Modal.getOrCreateInstance(m).show();
    });
  });
})();

// ---------- Admin notifications: announcement dialog + confirmations ----------
(function () {
  "use strict";
  document.querySelectorAll(".nt-confirm").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
  var m = document.getElementById("announceModal");
  if (!m) return;
  var form = m.querySelector("form"), E = form.elements;
  var dept = document.getElementById("aud_dept"), emps = document.getElementById("aud_emps");
  var filter = document.getElementById("empFilter"), sel = document.getElementById("empSel"), cnt = document.getElementById("msgCount");
  var boxes = function () { return Array.prototype.slice.call(emps.querySelectorAll("input[type=checkbox]")); };
  function audience() { return form.querySelector("input[name=audience]:checked").value; }
  function sync() {
    var a = audience();
    dept.hidden = a !== "department"; emps.hidden = a !== "employees";
    dept.disabled = a !== "department";
    sel.textContent = boxes().filter(function (b) { return b.checked; }).length;
    cnt.textContent = E.message.value.length + "/255";
  }
  form.addEventListener("input", sync); form.addEventListener("change", sync);
  filter.addEventListener("input", function () {
    var q = filter.value.trim().toLowerCase();
    emps.querySelectorAll("label[data-name]").forEach(function (l) { l.hidden = q && l.dataset.name.indexOf(q) === -1; });
  });
  form.addEventListener("submit", function (e) {
    if (audience() === "employees" && !boxes().some(function (b) { return b.checked; })) {
      e.preventDefault(); alert("Select at least one employee."); 
    }
  });
  m.addEventListener("show.bs.modal", function () { form.reset(); filter.dispatchEvent(new Event("input")); sync(); });
  m.addEventListener("shown.bs.modal", function () { E.title.focus(); });
  sync();
})();

// ---------- Admin settings: confirmations, password rules, show/hide ----------
(function () {
  "use strict";
  document.querySelectorAll(".set-confirm").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
  var pw = document.getElementById("pw_new");
  if (!pw) return;
  var tests = { len: /^.{8,}$/, upper: /[A-Z]/, lower: /[a-z]/, num: /\d/, sym: /[^A-Za-z0-9]/ };
  var items = document.querySelectorAll("#pwRules li");
  function check() {
    items.forEach(function (li) { li.classList.toggle("ok", tests[li.dataset.rule].test(pw.value)); });
  }
  pw.addEventListener("input", check);
  document.getElementById("showPw").addEventListener("change", function (e) {
    document.querySelectorAll(".pw-field").forEach(function (i) { i.type = e.target.checked ? "text" : "password"; });
  });
  check();
})();