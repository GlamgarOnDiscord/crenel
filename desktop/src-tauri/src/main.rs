// Crenel desktop: a window around the console that `crenel serve` already
// serves. The engine is the standalone executable (scripts/build-sea.mjs),
// bundled as a Tauri sidecar and spawned from Rust only:
//
//   crenel serve --config crenel.config.yaml --port 0 --exit-with-stdin
//
// in the project folder the user picked. Port 0 lets the OS choose a free
// port (no race between choosing and binding); the engine prints its link
// (http://127.0.0.1:<port>/?token=<random>), which the window opens: the
// console trades the token for an HttpOnly SameSite=Strict cookie, exactly as
// in a browser. The engine stops when the app exits (killed) and, if the app
// itself dies, when its stdin closes (--exit-with-stdin).
//
// Security model (docs/DESKTOP.md): the web page never gets the shell. The only
// IPC is three app commands, answered only for the app's own start page; the
// console (a 127.0.0.1 page) has no capability, and navigation is limited to
// the start page and the engine's own origin.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::async_runtime::Receiver;
use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder};
use tauri::{AppHandle, Manager, RunEvent, State, Url, Webview, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

const CONFIG_NAME: &str = "crenel.config.yaml";
const SIDECAR: &str = "crenel";
const READY_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Default)]
struct Engine {
    child: Mutex<Option<CommandChild>>,
    /// Port of the running engine: the only non-local origin the window may load.
    port: Arc<Mutex<Option<u16>>>,
    /// Bumped on every start and stop, so a stale engine's exit is ignored.
    generation: AtomicU64,
    /// URL of the start page (tauri://localhost/... or http://tauri.localhost/...).
    home: Mutex<Option<Url>>,
}

fn stop_engine(engine: &Engine) {
    engine.generation.fetch_add(1, Ordering::SeqCst);
    *engine.port.lock().unwrap() = None;
    if let Some(child) = engine.child.lock().unwrap().take() {
        let _ = child.kill();
    }
}

/// The app's own start page, never the console or anything else.
fn is_local(url: &Url) -> bool {
    url.scheme() == "tauri" || url.host_str() == Some("tauri.localhost")
}

fn is_engine(url: &Url, port: &Mutex<Option<u16>>) -> bool {
    let current = *port.lock().unwrap();
    url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && current.is_some() && url.port() == current
}

fn ensure_local(webview: &Webview) -> Result<(), String> {
    match webview.url() {
        Ok(url) if is_local(&url) => Ok(()),
        _ => Err("refused: only the app's start page may call this".into()),
    }
}

/// Back to the start page, with a message when the engine stopped on its own.
fn go_home(app: &AppHandle, error: Option<String>) {
    let home = app.state::<Engine>().home.lock().unwrap().clone();
    if let (Some(mut url), Some(win)) = (home, app.get_webview_window("main")) {
        url.set_query(None);
        if let Some(e) = error {
            url.query_pairs_mut().append_pair("error", &e);
        }
        let _ = win.navigate(url);
    }
}

/// The link the engine prints once it listens: http://127.0.0.1:<port>/?token=...
fn find_link(text: &str) -> Option<Url> {
    let start = text.find("http://127.0.0.1:")?;
    let rest = &text[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let url = Url::parse(&rest[..end]).ok()?;
    let ok = url.host_str() == Some("127.0.0.1") && url.port().is_some() && url.query_pairs().any(|(k, _)| k == "token");
    ok.then_some(url)
}

fn push_tail(tail: &mut String, bytes: &[u8]) {
    tail.push_str(&String::from_utf8_lossy(bytes));
    tail.push('\n');
    if tail.len() > 4000 {
        let cut = tail.len() - 4000;
        let cut = (cut..tail.len()).find(|i| tail.is_char_boundary(*i)).unwrap_or(0);
        tail.drain(..cut);
    }
}

async fn wait_for_link(rx: &mut Receiver<CommandEvent>, tail: &mut String) -> Result<Url, String> {
    let mut out = String::new();
    while let Some(event) = rx.recv().await {
        match event {
            CommandEvent::Stdout(line) => {
                out.push_str(&String::from_utf8_lossy(&line));
                out.push('\n');
                if let Some(url) = find_link(&out) {
                    return Ok(url);
                }
            }
            CommandEvent::Stderr(line) => push_tail(tail, &line),
            CommandEvent::Error(e) => push_tail(tail, e.as_bytes()),
            CommandEvent::Terminated(p) => {
                return Err(format!("the engine stopped before it was ready (exit {:?}).\n{}", p.code, tail.trim()));
            }
            _ => {}
        }
    }
    Err(format!("the engine closed its output before it was ready.\n{}", tail.trim()))
}

#[tauri::command]
async fn pick_project(app: AppHandle, webview: Webview) -> Result<Option<String>, String> {
    ensure_local(&webview)?;
    let picked = app.dialog().file().set_title("Choose the project folder Crenel should scan").blocking_pick_folder();
    Ok(picked.and_then(|p| p.into_path().ok()).map(|p| p.display().to_string()))
}

/// CRENEL_PROJECT=<folder> opens that project at start (used by CI screenshots).
#[tauri::command]
fn initial_project(webview: Webview) -> Result<Option<String>, String> {
    ensure_local(&webview)?;
    Ok(std::env::var("CRENEL_PROJECT").ok().filter(|s| !s.is_empty()))
}

/// Start the engine on `dir` and return the console link. Without a config,
/// answers "no-config" unless `create` is set: then `crenel init` writes the
/// starter config (read-only checks, nothing active) first.
#[tauri::command]
async fn open_project(app: AppHandle, webview: Webview, engine: State<'_, Engine>, dir: String, create: bool) -> Result<String, String> {
    ensure_local(&webview)?;
    let dir = PathBuf::from(dir);
    if !dir.is_dir() {
        return Err(format!("{} is not a folder", dir.display()));
    }
    let shell = app.shell();
    if !dir.join(CONFIG_NAME).is_file() {
        if !create {
            return Err("no-config".into());
        }
        let out = shell
            .sidecar(SIDECAR)
            .map_err(|e| e.to_string())?
            .args(["init", "--config", CONFIG_NAME])
            .current_dir(&dir)
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("crenel init failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
    }

    stop_engine(&engine);
    let (mut rx, child) = shell
        .sidecar(SIDECAR)
        .map_err(|e| e.to_string())?
        .args(["serve", "--config", CONFIG_NAME, "--port", "0", "--exit-with-stdin"])
        .current_dir(&dir)
        .spawn()
        .map_err(|e| format!("could not start the engine: {e}"))?;
    let generation = engine.generation.fetch_add(1, Ordering::SeqCst) + 1;
    *engine.child.lock().unwrap() = Some(child);

    let mut tail = String::new();
    let link = match tokio::time::timeout(READY_TIMEOUT, wait_for_link(&mut rx, &mut tail)).await {
        Ok(Ok(link)) => link,
        Ok(Err(e)) => {
            stop_engine(&engine);
            return Err(e);
        }
        Err(_) => {
            stop_engine(&engine);
            return Err(format!("the engine did not answer in {} s.\n{}", READY_TIMEOUT.as_secs(), tail.trim()));
        }
    };
    *engine.port.lock().unwrap() = link.port();

    // Keep reading the engine: if it stops on its own, come back to the start page.
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stderr(line) => push_tail(&mut tail, &line),
                CommandEvent::Terminated(p) => {
                    let engine = handle.state::<Engine>();
                    if engine.generation.load(Ordering::SeqCst) == generation {
                        stop_engine(&engine);
                        go_home(&handle, Some(format!("The engine stopped (exit {:?}).\n{}", p.code, tail.trim())));
                    }
                    break;
                }
                _ => {}
            }
        }
    });
    Ok(link.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Engine::default())
        .invoke_handler(tauri::generate_handler![pick_project, initial_project, open_project])
        .setup(|app| {
            let port = app.state::<Engine>().port.clone();
            let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Crenel")
                .inner_size(1280.0, 840.0)
                .min_inner_size(880.0, 560.0)
                .on_navigation(move |url| is_local(url) || is_engine(url, &port))
                .build()?;
            *app.state::<Engine>().home.lock().unwrap() = win.url().ok();

            let open = MenuItemBuilder::with_id("open-project", "Open project…").accelerator("CmdOrCtrl+O").build(app)?;
            let quit = PredefinedMenuItem::quit(app, None)?;
            let file = SubmenuBuilder::new(app, "File").item(&open).separator().item(&quit).build()?;
            let edit = SubmenuBuilder::new(app, "Edit").undo().redo().separator().cut().copy().paste().select_all().build()?;
            let menu = MenuBuilder::new(app).item(&file).item(&edit).build()?;
            app.set_menu(menu)?;
            Ok(())
        })
        .on_menu_event(|app, event| {
            if event.id().0 == "open-project" {
                stop_engine(&app.state::<Engine>());
                go_home(app, None);
            }
        })
        .build(tauri::generate_context!())
        .expect("error while starting Crenel")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                stop_engine(&app.state::<Engine>());
            }
        });
}
