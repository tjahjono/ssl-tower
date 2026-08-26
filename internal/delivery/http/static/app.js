// Progressive enhancement only: every page works without this file, htmx does
// the heavy lifting. Delegated listeners survive htmx swaps, so nothing needs
// to be re-bound after a fragment is replaced.
(function () {
  "use strict";

  // Plain tab switching for the certificate vault's generate/upload panels —
  // no framework, just toggling a couple of utility classes and [hidden].
  var TAB_ACTIVE = ["ring-1", "ring-inset", "ring-sky-500/25", "bg-sky-500/10", "text-hue-sky"];
  var TAB_INACTIVE = ["text-ink-4"];

  document.addEventListener("click", function (event) {
    var tabButton = event.target.closest("[data-tab-button]");
    if (tabButton) {
      var group = tabButton.closest("[data-tabs]");
      if (!group) return;
      var name = tabButton.getAttribute("data-tab-button");
      group.querySelectorAll("[data-tab-button]").forEach(function (btn) {
        var active = btn === tabButton;
        btn.setAttribute("aria-selected", active ? "true" : "false");
        TAB_ACTIVE.forEach(function (cls) { btn.classList.toggle(cls, active); });
        TAB_INACTIVE.forEach(function (cls) { btn.classList.toggle(cls, !active); });
      });
      group.querySelectorAll("[data-tab-panel]").forEach(function (panel) {
        panel.classList.toggle("hidden", panel.getAttribute("data-tab-panel") !== name);
      });
      return;
    }

    // Generic show/hide toggle — e.g. the Certificates page's "Add a
    // certificate" button revealing its intake tabs. A button carries
    // data-toggle-target="<id>"; clicking it flips [hidden] on that id and
    // updates the button's own label from data-toggle-label-open/closed if
    // present.
    var toggle = event.target.closest("[data-toggle-target]");
    if (toggle) {
      var panel = document.getElementById(toggle.getAttribute("data-toggle-target"));
      if (!panel) return;
      var isHidden = panel.classList.toggle("hidden");
      var label = toggle.querySelector("[data-toggle-label]");
      if (label) {
        label.textContent = isHidden
          ? toggle.getAttribute("data-toggle-label-closed")
          : toggle.getAttribute("data-toggle-label-open");
      }
      if (!isHidden) panel.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    var dismiss = event.target.closest("[data-dismiss]");
    if (dismiss) {
      var banner = dismiss.closest("[data-autodismiss], [role=status]");
      if (banner) banner.remove();
      return;
    }

    var copy = event.target.closest("[data-copy]");
    if (copy) {
      var source = document.querySelector(copy.getAttribute("data-copy"));
      if (!source) return;
      var text = source.innerText || source.value || "";
      var done = function () {
        var original = copy.getAttribute("data-label") || copy.textContent;
        copy.setAttribute("data-label", original);
        copy.textContent = "Copied";
        setTimeout(function () {
          copy.textContent = copy.getAttribute("data-label");
        }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () {});
      } else {
        var area = document.createElement("textarea");
        area.value = text;
        document.body.appendChild(area);
        area.select();
        try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
        area.remove();
      }
    }
  });

  // Auto-dismiss flash banners once they have been read.
  function armBanners(root) {
    (root.querySelectorAll ? root.querySelectorAll("[data-autodismiss]") : []).forEach(function (el) {
      if (el.dataset.armed) return;
      el.dataset.armed = "1";
      setTimeout(function () {
        el.style.transition = "opacity .3s";
        el.style.opacity = "0";
        setTimeout(function () { el.remove(); }, 320);
      }, parseInt(el.getAttribute("data-autodismiss"), 10) || 8000);
    });
  }

  document.addEventListener("DOMContentLoaded", function () { armBanners(document); });
  document.body.addEventListener("htmx:afterSwap", function (event) { armBanners(event.target); });
  document.body.addEventListener("htmx:oobAfterSwap", function (event) { armBanners(event.target); });

  // Clear forms marked data-reset once their htmx request succeeds.
  document.body.addEventListener("htmx:afterRequest", function (event) {
    if (!event.detail || !event.detail.successful) return;
    var form = event.target.closest ? event.target.closest("form[data-reset]") : null;
    if (form) form.reset();
  });

  // Toggle the key-size / curve selects to match the chosen algorithm.
  document.addEventListener("change", function (event) {
    if (event.target.name !== "key_algorithm") return;
    var form = event.target.form;
    if (!form) return;
    var rsa = form.querySelector("[data-key-rsa]");
    var ec = form.querySelector("[data-key-ecdsa]");
    if (!rsa || !ec) return;
    var isEC = event.target.value === "ecdsa";
    rsa.classList.toggle("hidden", isEC);
    ec.classList.toggle("hidden", !isEC);
  });

  // Generic conditional field visibility. An element carrying
  // data-show-when="fieldName:value" is shown only while the nearest form's
  // fieldName (a radio group or a select) currently holds that value —
  // e.g. the certificate request form uses this to show the PO number only
  // for an external trust class, and to swap between "new certificate"
  // fields and the renewal picker depending on request type.
  function applyShowWhen(root) {
    if (!root.querySelectorAll) return;
    root.querySelectorAll("[data-show-when]").forEach(function (el) {
      var form = el.closest("form");
      if (!form) return;
      var parts = el.getAttribute("data-show-when").split(":");
      var field = parts[0], want = parts[1];
      var checked = form.querySelector('[name="' + field + '"]:checked');
      var current = checked ? checked.value : (function () {
        var input = form.querySelector('[name="' + field + '"]');
        return input ? input.value : null;
      })();
      el.classList.toggle("hidden", current !== want);
    });
  }

  document.addEventListener("DOMContentLoaded", function () { applyShowWhen(document); });
  document.body.addEventListener("htmx:afterSwap", function (event) { applyShowWhen(event.target); });

  document.addEventListener("change", function (event) {
    var form = event.target.form;
    if (form && form.querySelector("[data-show-when]")) applyShowWhen(form);
  });
})();
