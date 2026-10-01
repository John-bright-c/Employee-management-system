(function () {
  "use strict";
  var csrf = document.querySelector('meta[name="csrf-token"]').content;

  // Mobile sidebar
  var sb = document.getElementById("sidebar"), scrim = document.getElementById("scrim");
  function toggle(open) { sb.classList.toggle("open", open); scrim.classList.toggle("show", open); }
  var menu = document.getElementById("menuBtn");
  if (menu) menu.addEventListener("click", function () { toggle(true); });
  scrim.addEventListener("click", function () { toggle(false); });

  // Placeholder links for pages that aren't built yet
  document.querySelectorAll("a[href='#']").forEach(function (a) { a.addEventListener("click", function (e) { e.preventDefault(); }); });

  // Live working-hours counter while checked in
  var w = document.getElementById("worked");
  if (w && w.dataset.running === "1" && w.dataset.start) {
    var start = new Date(w.dataset.start);
    var tick = function () {
      var m = Math.max(0, Math.floor((Date.now() - start.getTime()) / 60000));
      w.textContent = Math.floor(m / 60) + "h " + String(m % 60).padStart(2, "0") + "m";
    };
    tick(); setInterval(tick, 30000);
  }

  // Tick a task complete / incomplete
  document.querySelectorAll(".task-check").forEach(function (box) {
    box.addEventListener("change", function () {
      var row = box.closest(".task");
      box.disabled = true;
      fetch("/employee/tasks/" + box.dataset.id + "/toggle", { method: "POST", headers: { "X-CSRFToken": csrf } })
        .then(function (r) { if (!r.ok) throw new Error(); location.reload(); })
        .catch(function () { box.checked = !box.checked; box.disabled = false; row.classList.add("shake"); });
    });
  });

  // Change a task's status from the My Tasks table
  document.querySelectorAll(".status-select").forEach(function (sel) {
    sel.addEventListener("change", function () {
      sel.disabled = true;
      var body = new URLSearchParams({ status: sel.value });
      fetch("/employee/tasks/" + sel.dataset.id + "/status", { method: "POST", headers: { "X-CSRFToken": csrf }, body: body })
        .then(function (r) { if (!r.ok) throw new Error(); location.reload(); })
        .catch(function () { alert("Couldn't update the task. Please try again."); location.reload(); });
    });
  });

  // Auto-submit filter dropdowns
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { el.form.submit(); });
  });

  // Timesheet page: add / edit modal and delete confirmation
  var em = document.getElementById("entryModal");
  if (em && em.querySelector("[name=entry_id]")) {
    var ef = em.querySelector("form"), et = em.querySelector(".modal-title");
    document.querySelectorAll(".edit-entry").forEach(function (b) {
      b.addEventListener("click", function () {
        ef.entry_id.value = b.dataset.id; ef.work_date.value = b.dataset.date; ef.task.value = b.dataset.task;
        ef.start_time.value = b.dataset.start; ef.end_time.value = b.dataset.end;
        et.textContent = "Edit Timesheet Entry"; dur();
        bootstrap.Modal.getOrCreateInstance(em).show();
      });
    });
    document.querySelectorAll(".add-entry").forEach(function (b) {
      b.addEventListener("click", function () {
        ef.entry_id.value = ""; ef.task.value = ""; ef.start_time.value = ""; ef.end_time.value = "";
        ef.work_date.value = ef.work_date.dataset.today; et.textContent = "Add Timesheet Entry"; dur();
      });
    });
  }
  document.querySelectorAll(".delete-form").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm("Delete this timesheet entry?")) e.preventDefault(); });
  });

  // Leave form: live working-day count
  var lf = document.getElementById("l_from"), lt = document.getElementById("l_to"), ld = document.getElementById("l_days");
  function wdays(a, b) {
    var n = 0, d = new Date(a + "T00:00:00"), e = new Date(b + "T00:00:00");
    while (d <= e) { var w = d.getDay(); if (w !== 0 && w !== 6) n++; d.setDate(d.getDate() + 1); }
    return n;
  }
  function leaveHint() {
    if (!lf.value || !lt.value) { ld.textContent = ""; return; }
    if (lt.value < lf.value) { ld.textContent = "The to date can't be before the from date."; ld.style.color = "#dc2f3c"; return; }
    var n = wdays(lf.value, lt.value);
    ld.textContent = n ? n + " working day" + (n === 1 ? "" : "s") + " (weekends excluded)" : "These dates fall only on weekends.";
    ld.style.color = n ? "" : "#dc2f3c";
  }
  if (lf && lt && ld) {
    lf.addEventListener("input", function () { lt.min = lf.value; if (!lt.value || lt.value < lf.value) lt.value = lf.value; leaveHint(); });
    lt.addEventListener("input", leaveHint);
  }
  document.querySelectorAll(".cancel-form").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm("Cancel this leave request?")) e.preventDefault(); });
  });

  // Notifications: click a row to mark it read and open its page
  document.querySelectorAll(".notif").forEach(function (item) {
    function open() {
      var link = item.dataset.link, unread = item.classList.contains("unread");
      if (!link && !unread) return;
      var go = function () { if (link) location.href = link; else location.reload(); };
      if (unread) fetch("/employee/notifications/" + item.dataset.id + "/read", { method: "POST", headers: { "X-CSRFToken": csrf } }).then(go, go);
      else go();
    }
    item.addEventListener("click", function (e) { if (!e.target.closest("form,button,a")) open(); });
    item.addEventListener("keydown", function (e) { if (e.key === "Enter" && e.target === item) open(); });
  });

  // Prevent double submits
  document.querySelectorAll("form").forEach(function (f) {
    f.addEventListener("submit", function () {
      f.querySelectorAll("[data-once]").forEach(function (b) { setTimeout(function () { b.disabled = true; }, 0); });
    });
  });

  // Live duration hint in the entry modal
  var s = document.getElementById("start_time"), e = document.getElementById("end_time"), d = document.getElementById("dur");
  function dur() {
    if (!s.value || !e.value) { d.textContent = ""; return; }
    var a = s.value.split(":"), b = e.value.split(":");
    var m = (+b[0] * 60 + +b[1]) - (+a[0] * 60 + +a[1]);
    d.textContent = m > 0 ? "Duration: " + Math.floor(m / 60) + "h " + String(m % 60).padStart(2, "0") + "m" : "End time must be after start time.";
    d.style.color = m > 0 ? "" : "#dc2f3c";
  }
  if (s && e) { s.addEventListener("input", dur); e.addEventListener("input", dur); }
})();