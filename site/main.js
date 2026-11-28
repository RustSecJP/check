// Picks the right download for the visitor's OS, and wires up tabs and copy buttons.
(function () {
  "use strict";

  // ---- OS detection -------------------------------------------------------
  function detect() {
    var uaData = navigator.userAgentData;
    var ua = navigator.userAgent || "";
    var platform = (uaData && uaData.platform) || navigator.platform || "";
    var p = (platform + " " + ua).toLowerCase();
    if (/iphone|ipad|ipod|android/.test(p)) return Promise.resolve(null);
    var os = /win/.test(platform.toLowerCase()) || /windows/.test(p) ? "windows"
      : /mac/.test(p) ? "macos"
      : /linux|x11|cros/.test(p) ? "linux" : null;
    if (!os) return Promise.resolve(null);
    var guess = { os: os, arch: os === "macos" ? "aarch64" : "x86_64" };
    if (os === "linux" && /aarch64|arm64|armv8/.test(p)) guess.arch = "aarch64";
    if (uaData && uaData.getHighEntropyValues) {
      return uaData.getHighEntropyValues(["architecture"]).then(function (v) {
        if (v.architecture === "arm") guess.arch = "aarch64";
        else if (v.architecture === "x86" && os !== "windows") guess.arch = "x86_64";
        if (os === "windows") guess.arch = "x86_64"; // only x86_64 is published
        return guess;
      }, function () { return guess; });
    }
    return Promise.resolve(guess);
  }

  var LABEL = { windows: "Windows", macos: "macOS", linux: "Linux" };
  var ARCH = { x86_64: "x86_64", aarch64: "arm64" };

  var btn = document.getElementById("download-btn");
  if (btn) {
    detect().then(function (g) {
      if (!g) return; // keep the generic "Download" that scrolls to the table
      var name = btn.dataset.prefix + "-" + g.os + "-" + g.arch + (g.os === "windows" ? ".zip" : ".tar.gz");
      btn.href = btn.dataset.base + name;
      var label = btn.querySelector(".label");
      var archText = g.os === "macos" ? (g.arch === "aarch64" ? "Apple silicon" : "Intel") : ARCH[g.arch];
      label.textContent = "Download for " + LABEL[g.os];
      btn.setAttribute("aria-label", "Download " + name);
      var note = document.getElementById("download-note");
      if (note) note.querySelector(".detected").textContent = LABEL[g.os] + " · " + archText;
      var row = document.querySelector('[data-asset="' + name + '"]');
      if (row) row.classList.add("mine");
    });
  }

  // ---- Tabs ---------------------------------------------------------------
  document.querySelectorAll("[data-tabs]").forEach(function (box) {
    var tabs = box.querySelectorAll('[role="tab"]');
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        tabs.forEach(function (t) {
          var on = t === tab;
          t.setAttribute("aria-selected", on ? "true" : "false");
          t.tabIndex = on ? 0 : -1;
          document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
        });
      });
      tab.addEventListener("keydown", function (e) {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        var list = Array.prototype.slice.call(tabs);
        var i = list.indexOf(tab) + (e.key === "ArrowRight" ? 1 : -1);
        var next = list[(i + list.length) % list.length];
        next.focus();
        next.click();
      });
    });
  });

  // ---- Copy buttons -------------------------------------------------------
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy") ? resolve() : reject(); } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }
  document.querySelectorAll(".code").forEach(function (box) {
    var b = box.querySelector(".copy");
    if (!b) return;
    b.addEventListener("click", function () {
      var pre = box.querySelector("pre:not([hidden])") || box.querySelector("pre");
      copyText(pre.innerText.replace(/\n$/, "")).then(function () {
        b.textContent = "Copied";
        b.classList.add("done");
        setTimeout(function () { b.textContent = "Copy"; b.classList.remove("done"); }, 1800);
      }, function () { b.textContent = "Press Ctrl+C"; });
    });
  });
})();
