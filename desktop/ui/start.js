// Start page of the desktop app: choose a project folder, then the Rust side
// starts the engine (crenel serve) and returns the console link, which this
// page opens. Only three app commands are reachable, and only from here.
"use strict";

const { invoke } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);
const RECENT = "crenel.recentProject";

function readRecent() {
  try { return localStorage.getItem(RECENT); } catch { return null; }
}
function saveRecent(dir) {
  try { localStorage.setItem(RECENT, dir); } catch { /* storage unavailable */ }
}

function setBusy(text) {
  $("busy").hidden = !text;
  if (text) $("busy-text").textContent = text;
  for (const b of document.querySelectorAll("button")) b.disabled = !!text;
}
function showError(text) {
  $("error").hidden = !text;
  $("error").textContent = text || "";
}
function showRecent() {
  const dir = readRecent();
  $("recent").hidden = !dir;
  if (dir) { $("recent").textContent = `Reopen ${dir}`; $("recent").title = dir; }
}

let pending = null;

async function open(dir, create) {
  showError("");
  $("noconfig").hidden = true;
  setBusy(create ? "Writing the starter config and starting the engine…" : "Starting the engine…");
  try {
    const link = await invoke("open_project", { dir, create });
    saveRecent(dir);
    window.location.replace(link);
  } catch (e) {
    setBusy("");
    if (String(e) === "no-config") {
      pending = dir;
      $("noconfig-dir").textContent = dir;
      $("noconfig").hidden = false;
      $("create").focus();
    } else {
      showError(String(e));
    }
  }
}

$("pick").addEventListener("click", async () => {
  showError("");
  try {
    const dir = await invoke("pick_project");
    if (dir) await open(dir, false);
  } catch (e) { showError(String(e)); }
});
$("recent").addEventListener("click", () => { const d = readRecent(); if (d) void open(d, false); });
$("create").addEventListener("click", () => { if (pending) void open(pending, true); });
$("cancel").addEventListener("click", () => { pending = null; $("noconfig").hidden = true; });

(async () => {
  showRecent();
  const err = new URLSearchParams(window.location.search).get("error");
  if (err) showError(err);
  try { $("version").textContent = await window.__TAURI__.app.getVersion(); } catch { /* not granted */ }
  if (!err) {
    try {
      const dir = await invoke("initial_project");
      if (dir) await open(dir, false);
    } catch (e) { showError(String(e)); }
  }
})();
