#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// --- imports (en haut du fichier, avec les autres use) ---
use flate2::read::GzDecoder;
use tar::Archive;

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, Path as AxumPath, State};
use axum::http::{header::CONTENT_TYPE, HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response as AxumResponse;
use axum::{middleware, routing::get, routing::post, Json, Router};
use dashmap::DashMap;
use mime_guess::mime;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use tokio::sync::RwLock;
use walkdir::WalkDir;
use zip::{write::FileOptions, CompressionMethod, ZipWriter};
use tauri::{GlobalShortcutManager, Manager};

use futures::StreamExt;
use http_body_util::BodyExt as _;
use tokio::io::AsyncWriteExt;

use deno_ast::{
    parse_module, EmitOptions, MediaType, ModuleSpecifier, ParseParams, TranspileModuleOptions,
    TranspileOptions,
};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::io;
// ✅ pour graceful shutdown
use tokio::sync::oneshot;
use include_dir::{include_dir, Dir};


#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const MARKER: &[u8] = b"---EMBED-ZIP-START---";

/// Limite (par flux) des logs cumulés en mémoire (tampon circulaire)
const LOG_CAP_BYTES: usize = 1_000_000;
// Embarque TOUT le dossier assets/ à la compilation
static ASSETS_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/assets/dist");



fn write_embedded_assets_to(code_dir: &Path) -> io::Result<()> {
    ASSETS_DIR
        .extract(code_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
/* -------------------- État & modèles -------------------- */
#[derive(Clone)]
struct AppState {
    // dossier actuellement servi (…/nomExecutable/code)
    root: Arc<RwLock<PathBuf>>,
    // dossier des exécutables (…/nomExecutable/executable) – modifiable à chaud
    exec_root: Arc<RwLock<PathBuf>>,
    // base des opérations /api/file/* (modifiable via /api/current-directory)
    file_path: Arc<RwLock<PathBuf>>,
    // processus détachés + logs
    procs: Arc<DashMap<u64, Arc<StdMutex<ProcInfo>>>>,
    next_proc_id: Arc<AtomicU64>,

    // Registre des serveurs enfants { port -> shutdown_tx }
    servers: Arc<DashMap<u16, Arc<StdMutex<Option<oneshot::Sender<()>>>>>>,
    // Port de CE serveur (si serveur enfant)
    self_port: Option<u16>,
    // Handle d'arrêt de CE serveur (si serveur enfant)
    self_shutdown: Option<Arc<StdMutex<Option<oneshot::Sender<()>>>>>,
}

struct ProcInfo {
    child: Option<std::process::Child>,
    pid: Option<u32>,
    name: String,
    args: Vec<String>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<i32>,
}

impl AppState {
    fn kill_all_children(&self) {
        let victims: Vec<_> = self.procs.iter().map(|e| e.value().clone()).collect();
        for info in victims {
            if let Ok(mut pi) = info.lock() {
                if let Some(child) = pi.child.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                    pi.exit_status = Some(-1);
                    pi.child = None;
                }
            }
        }
    }
}

static TS_CACHE: Lazy<DashMap<PathBuf, (SystemTime, Arc<String>)>> = Lazy::new(DashMap::new);

/* -------------------- Helpers -------------------- */
fn exe_title() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "App".into())
}

fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::from(root);
    for c in rel_path.components() {
        match c {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

fn default_served_base_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let exe_dir = exe.parent().unwrap_or_else(|| Path::new("."));
    let stem = exe.file_stem().and_then(|s| s.to_str()).unwrap_or("app");
    exe_dir.join(stem)
}

fn push_capped(buf: &mut Vec<u8>, chunk: &[u8]) {
    if chunk.is_empty() {
        return;
    }
    if buf.len() + chunk.len() <= LOG_CAP_BYTES {
        buf.extend_from_slice(chunk);
        return;
    }
    let overflow = buf.len() + chunk.len() - LOG_CAP_BYTES;
    if overflow >= buf.len() {
        buf.clear();
        if chunk.len() > LOG_CAP_BYTES {
            let start = chunk.len() - LOG_CAP_BYTES;
            buf.extend_from_slice(&chunk[start..]);
        } else {
            buf.extend_from_slice(chunk);
        }
    } else {
        buf.drain(0..overflow);
        buf.extend_from_slice(chunk);
    }
}

/* -------------------- Pack 2 répertoires -> exe -------------------- */
fn embed_two_folders_to_exe(code_folder: &Path, exe_folder: &Path, output_exe: &Path) {
    use std::io::Cursor;

    let current_exe =
        std::env::current_exe().expect("❌ Impossible de localiser l'exécutable courant");
    let base_exe_bytes = fs::read(&current_exe).expect("❌ Impossible de lire l'exécutable courant");

    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    let options = FileOptions::default().compression_method(CompressionMethod::Stored);

    for entry in WalkDir::new(code_folder).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path.is_file() {
            let rel = path
                .strip_prefix(code_folder)
                .expect("❌ strip_prefix")
                .to_string_lossy()
                .replace('\\', "/");
            let name = format!("code/{}", rel);
            zip.start_file(name, options).expect("❌ zip start_file(code)");
            let data = fs::read(path).expect("❌ lecture fichier");
            zip.write_all(&data).expect("❌ écriture zip");
        }
    }

    for entry in WalkDir::new(exe_folder).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path.is_file() {
            let rel = path
                .strip_prefix(exe_folder)
                .expect("❌ strip_prefix")
                .to_string_lossy()
                .replace('\\', "/");
            let name = format!("executable/{}", rel);
            zip.start_file(name, options)
                .expect("❌ zip start_file(executable)");
            let data = fs::read(path).expect("❌ lecture fichier");
            zip.write_all(&data).expect("❌ écriture zip");
        }
    }

    let cursor = zip.finish().expect("❌ zip finish");
    let zip_data = cursor.into_inner();

    let mut out =
        fs::File::create(output_exe).expect("❌ Impossible de créer le nouvel exécutable");
    out.write_all(&base_exe_bytes).expect("❌ write exe");
    out.write_all(MARKER).expect("❌ write marker");
    out.write_all(&zip_data).expect("❌ write zip");
    println!("✅ Exécutable autonome créé : {}", output_exe.display());
}

/* --- Wrapper rétro-compatible --- */
fn embed_folder_to_exe(folder: &PathBuf, output_exe: &PathBuf) {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    embed_two_folders_to_exe(folder.as_path(), exe_dir.as_path(), output_exe.as_path());
}

/* -------------------- Extraction zip embarqué -------------------- */
fn extract_embedded_zip(exe_path: &PathBuf, out_dir: &PathBuf) -> bool {
    let mut file = match fs::File::open(exe_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return false;
    }

    let pos = match buf.windows(MARKER.len()).rposition(|w| w == MARKER) {
        Some(p) => p,
        None => return false,
    };
    let zip_data = &buf[pos + MARKER.len()..];

    if fs::create_dir_all(out_dir).is_err() {
        return false;
    }

    let reader = std::io::Cursor::new(zip_data);
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("❌ ZIP invalide : {e}");
            return false;
        }
    };

    for i in 0..archive.len() {
        let mut f = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let name = f.name();
        let rel_path = Path::new(name);
        if rel_path.is_absolute()
            || rel_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            eprintln!("⚠️  Chemin suspect ignoré: {}", name);
            continue;
        }
        let outpath = out_dir.join(rel_path);
        if let Some(parent) = outpath.parent() {
            if fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        let mut outfile = match fs::File::create(&outpath) {
            Ok(f) => f,
            Err(_) => return false,
        };
        if std::io::copy(&mut f, &mut outfile).is_err() {
            return false;
        }
    }
    true
}

fn has_embedded_zip(exe_path: &Path) -> bool {
    if let Ok(mut file) = fs::File::open(exe_path) {
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_ok() {
            if let Some(pos) = buf.windows(MARKER.len()).rposition(|w| w == MARKER) {
                let zip_data = &buf[pos + MARKER.len()..];
                let reader = std::io::Cursor::new(zip_data);
                return zip::ZipArchive::new(reader).is_ok();
            }
        }
    }
    false
}


/* -------------------- Transpile TS -> JS -------------------- */
fn transpile_ts_file(ts_path: &PathBuf) -> Result<String> {
    let source = fs::read_to_string(ts_path)?;
    let media_type = deno_ast::MediaType::from_path(ts_path);

    match media_type {
        MediaType::TypeScript
        | MediaType::Mts
        | MediaType::Cts
        | MediaType::Dts
        | MediaType::Dmts
        | MediaType::Dcts => {
            let spec = ModuleSpecifier::parse(&format!("file:///{}", ts_path.display()))
                .expect("URL invalide");

            let parsed = parse_module(ParseParams {
                specifier: spec,
                text: Arc::<str>::from(source),
                media_type,
                capture_tokens: false,
                maybe_syntax: None,
                scope_analysis: false,
            })?;

            let emitted = parsed
                .transpile(
                    &TranspileOptions {
                        use_ts_decorators: false,
                        use_decorators_proposal: false,
                        emit_metadata: false,
                        verbatim_module_syntax: false,
                        ..Default::default()
                    },
                    &TranspileModuleOptions { ..Default::default() },
                    &EmitOptions { ..Default::default() },
                )?
                .into_source();

            Ok(emitted.text)
        }
        _ => Ok(fs::read_to_string(ts_path)?),
    }
} 
/* -------------------- /api/unzip -------------------- */
// --- types + helper (placer près des autres APIs) ---
#[derive(serde::Deserialize)]
struct UnzipReq {
    file: String,      // nom du .tgz (ex: "pkg-1.0.0.tgz")
    directory: String, // sous-dossier relatif à state.file_path
}

#[derive(serde::Serialize)]
struct UnzipResp {
    ok: bool,
    message: String,
    extracted: usize,
}

/// Extraction .tgz/.tar.gz sécurisée (ignore chemins absolus, .., symlinks)
fn extract_tgz_safe(tgz_path: &std::path::Path, out_dir: &std::path::Path) -> std::result::Result<usize, String> {
    let file = std::fs::File::open(tgz_path)
        .map_err(|e| format!("Ouverture {}: {e}", tgz_path.display()))?;
    let dec = GzDecoder::new(file);
    let mut ar = Archive::new(dec);

    let mut count = 0usize;
    let entries = ar.entries().map_err(|e| format!("Lecture archive: {e}"))?;
    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| format!("Entrée invalide: {e}"))?;
        let path_in_tar = entry.path().map_err(|e| format!("Chemin entrée: {e}"))?;
        let rel = path_in_tar.as_ref();

        // Pas de chemins absolus ni de .. ; pas de (hard) symlinks
        if rel.is_absolute() || rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            continue;
        }
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            continue;
        }

        let dest = out_dir.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Création dossier {}: {e}", parent.display()))?;
        }
        entry.unpack(&dest)
            .map_err(|e| format!("Unpack {}: {e}", dest.display()))?;
        count += 1;
    }
    Ok(count)
}

// --- handler (placer avec les autres handlers) ---
async fn api_unzip(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Json(req): axum::Json<UnzipReq>,
) -> (axum::http::StatusCode, axum::Json<UnzipResp>) {
    // Base = state.file_path
    let base = { state.file_path.read().await.clone() };

    // directory doit être RELATIF à base
    let Some(target_dir) = safe_join(&base, req.directory.trim()) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(UnzipResp { ok: false, message: "'directory' doit être relatif (pas de '..' ni absolu)".into(), extracted: 0 })
        );
    };

    // file doit être un nom simple (pas de sous-chemin)
    let p = std::path::Path::new(req.file.trim());
    if p.components().count() != 1 {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(UnzipResp { ok: false, message: "'file' doit être un nom de fichier sans chemin".into(), extracted: 0 })
        );
    }
    let lc = req.file.to_lowercase();
    if !(lc.ends_with(".tgz") || lc.ends_with(".tar.gz")) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(UnzipResp { ok: false, message: "Seuls .tgz ou .tar.gz sont acceptés".into(), extracted: 0 })
        );
    }

    if let Err(e) = tokio::fs::create_dir_all(&target_dir).await {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(UnzipResp { ok: false, message: format!("Création répertoire {}: {e}", target_dir.display()), extracted: 0 })
        );
    }
    let tgz_path = target_dir.join(&req.file);
    match tokio::fs::metadata(&tgz_path).await {
        Ok(m) if m.is_file() => {}
        _ => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(UnzipResp { ok: false, message: format!("Archive introuvable: {}", tgz_path.display()), extracted: 0 })
            );
        }
    }

    let dir_cl = target_dir.clone();
    let tgz_cl = tgz_path.clone();
    let res = tokio::task::spawn_blocking(move || extract_tgz_safe(&tgz_cl, &dir_cl)).await;

    match res {
        Ok(Ok(n)) => (
            axum::http::StatusCode::OK,
            axum::Json(UnzipResp { ok: true, message: format!("Décompressé dans {}", target_dir.display()), extracted: n }),
        ),
        Ok(Err(msg)) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(UnzipResp { ok: false, message: msg, extracted: 0 }),
        ),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(UnzipResp { ok: false, message: format!("Join error: {e}"), extracted: 0 }),
        ),
    }
}

/* -------------------- /api/embed -------------------- */
#[derive(Deserialize)]
struct EmbedReqAny {
    code: Option<String>,
    executable: Option<String>,
    output: String,
}
#[derive(Serialize)]
struct EmbedResp {
    ok: bool,
    message: String,
}
async fn api_embed(Json(payload): Json<EmbedReqAny>) -> (StatusCode, Json<EmbedResp>) {
    let code_dir = payload.code.unwrap_or_default();
    if code_dir.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(EmbedResp {
                ok: false,
                message: "Paramètre manquant: 'code' (ou 'folder')".into(),
            }),
        );
    }
    let exe_dir = match payload.executable {
        Some(s) if !s.is_empty() => s,
        _ => {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_string_lossy().into_owned()))
                .unwrap_or_else(|| ".".into())
        }
    };

    let code_path = PathBuf::from(code_dir);
    let exe_path = PathBuf::from(exe_dir);
    let output = PathBuf::from(payload.output);

    if !code_path.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(EmbedResp {
                ok: false,
                message: format!("'code' n'est pas un dossier: {}", code_path.display()),
            }),
        );
    }
    if !exe_path.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(EmbedResp {
                ok: false,
                message: format!("'executable' n'est pas un dossier: {}", exe_path.display()),
            }),
        );
    }

    let out_disp = output.display().to_string();
    let code_cl = code_path.clone();
    let exe_cl = exe_path.clone();
    let out_cl = output.clone();

    let res = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(|| embed_two_folders_to_exe(&code_cl, &exe_cl, &out_cl))
    })
    .await;

    match res {
        Ok(Ok(_)) => (
            StatusCode::OK,
            Json(EmbedResp {
                ok: true,
                message: format!("Exécutable créé: {}", out_disp),
            }),
        ),
        Ok(Err(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(EmbedResp {
                ok: false,
                message: "Échec d'empaquetage (panic)".into(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(EmbedResp {
                ok: false,
                message: format!("Join error: {e}"),
            }),
        ),
    }
}

/* -------------------- /api/useConfig -------------------- */
#[derive(Deserialize)]
struct UseConfigReq {
    code: String,
    executable: String,
}
#[derive(Serialize)]
struct UseConfigResp {
    ok: bool,
    message: String,
}
async fn api_use_config(
    State(state): State<AppState>,
    Json(payload): Json<UseConfigReq>,
) -> (StatusCode, Json<UseConfigResp>) {
    let folder = PathBuf::from(&payload.code);
    let execdir = PathBuf::from(&payload.executable);

    if !folder.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(UseConfigResp {
                ok: false,
                message: "folder n'est pas un dossier".into(),
            }),
        );
    }
    if !execdir.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(UseConfigResp {
                ok: false,
                message: "executable n'est pas un dossier".into(),
            }),
        );
    }

    {
        let mut w = state.root.write().await;
        *w = tokio::fs::canonicalize(&folder).await.unwrap_or(folder);
    }
    {
        let mut w = state.exec_root.write().await;
        *w = tokio::fs::canonicalize(&execdir).await.unwrap_or(execdir);
    }
    TS_CACHE.clear();

    (
        StatusCode::OK,
        Json(UseConfigResp {
            ok: true,
            message: "Configuration appliquée (code + executable)".into(),
        }),
    )
}

/* -------------------- /api/get-config -------------------- */
#[derive(Serialize)]
struct GetConfigResp {
    ok: bool,
    code: String,
    executable: String,
    fileBase: String,
}
async fn api_get_config(State(state): State<AppState>) -> (StatusCode, Json<GetConfigResp>) {
    let code = state.root.read().await.display().to_string();
    let exec = state.exec_root.read().await.display().to_string();
    let file_base = state.file_path.read().await.display().to_string();

    (
        StatusCode::OK,
        Json(GetConfigResp {
            ok: true,
            code,
            executable: exec,
            fileBase: file_base,
        }),
    )
}

/* -------------------- /api/current-directory -------------------- */
#[derive(Deserialize)]
struct CurrentDirReq {
    path: String, // peut être vide -> CWD
}
#[derive(Serialize)]
struct CurrentDirResp {
    ok: bool,
    message: String,
    current: String, // chemin absolu effectivement retenu
}

async fn api_current_directory(
    State(state): State<AppState>,
    Json(req): Json<CurrentDirReq>,
) -> (StatusCode, Json<CurrentDirResp>) {
    // Règle de résolution : comme /api/explorer
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let target: PathBuf = {
        let raw = req.path.trim();
        if raw.is_empty() {
            cwd.clone()
        } else {
            let p = PathBuf::from(raw);
            if p.is_absolute() {
                p
            } else {
                cwd.join(p)
            }
        }
    };

    // Doit exister et être un répertoire
    match tokio::fs::metadata(&target).await {
        Ok(m) if m.is_dir() => {
            let abs = tokio::fs::canonicalize(&target).await.unwrap_or(target.clone());
            {
                let mut w = state.file_path.write().await;
                *w = abs.clone();
            }
            (
                StatusCode::OK,
                Json(CurrentDirResp {
                    ok: true,
                    message: "Répertoire courant des fichiers mis à jour".into(),
                    current: abs.display().to_string(),
                }),
            )
        }
        Ok(_) => (
            StatusCode::BAD_REQUEST,
            Json(CurrentDirResp {
                ok: false,
                message: "Le chemin fourni n'est pas un dossier".into(),
                current: {
                    let cur = state.file_path.read().await.clone();
                    cur.display().to_string()
                },
            }),
        ),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(CurrentDirResp {
                ok: false,
                message: format!("Introuvable: {e}"),
                current: {
                    let cur = state.file_path.read().await.clone();
                    cur.display().to_string()
                },
            }),
        ),
    }
}

/* -------------------- /api/file/ -------------------- */
#[derive(Serialize)]
struct FileDeleteResp {
    ok: bool,
    message: String,
    path: String,
}

async fn api_delete_file(
    State(state): State<AppState>,
    AxumPath(rel_path): AxumPath<String>,
) -> AxumResponse {
    // base configurable via /api/current-directory
    let base = { state.file_path.read().await.clone() };

    let Some(target) = safe_join(&base, &rel_path) else {
        return AxumResponse::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
            .body(Body::from("Chemin invalide"))
            .unwrap();
    };

    match tokio::fs::metadata(&target).await {
        Ok(meta) => {
            if meta.is_file() {
                match tokio::fs::remove_file(&target).await {
                    Ok(_) => {
                        let payload = FileDeleteResp {
                            ok: true,
                            message: format!("Fichier supprimé: {}", target.display()),
                            path: rel_path,
                        };
                        let json = serde_json::to_vec(&payload).unwrap();
                        AxumResponse::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Body::from(json))
                            .unwrap()
                    }
                    Err(e) => AxumResponse::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                        .body(Body::from(format!(
                            "Échec suppression {}: {e}",
                            target.display()
                        )))
                        .unwrap(),
                }
            } else {
                AxumResponse::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                    .body(Body::from("Le chemin vise un dossier, pas un fichier"))
                    .unwrap()
            }
        }
        Err(_) => AxumResponse::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
            .body(Body::from("Fichier introuvable"))
            .unwrap(),
    }
}

#[derive(Serialize)]
struct FileWriteResp {
    ok: bool,
    message: String,
    path: String,
}
async fn api_write_file(
    State(state): State<AppState>,
    AxumPath(rel_path): AxumPath<String>,
    headers: HeaderMap,
    body: Body,
) -> AxumResponse {
    // Collecte le body pour savoir s'il est vide (lecture) ou non (écriture)
    let collected = match body.collect().await {
        Ok(c) => c,
        Err(e) => {
            return AxumResponse::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                .body(Body::from(format!("Erreur lecture flux: {e}")))
                .unwrap();
        }
    };
    let data = collected.to_bytes();

    // Base des opérations /api/file : state.file_path (modifiable via /api/current-directory)
    let base = { state.file_path.read().await.clone() };

    // 🔍 Si body vide → LECTURE
    if data.is_empty() {
        let Some(target) = safe_join(&base, &rel_path) else {
            return AxumResponse::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                .body(Body::from("Chemin invalide"))
                .unwrap();
        };
        if target.is_file() {
            match tokio::fs::read(&target).await {
                Ok(bytes) => {
                    let ct = mime_guess::from_path(&target)
                        .first_or_octet_stream()
                        .essence_str()
                        .to_string();
                    return AxumResponse::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, ct)
                        .body(Body::from(bytes))
                        .unwrap();
                }
                Err(e) => {
                    return AxumResponse::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                        .body(Body::from(format!(
                            "Erreur de lecture {}: {e}",
                            target.display()
                        )))
                        .unwrap();
                }
            }
        } else {
            return AxumResponse::builder()
                .status(StatusCode::NOT_FOUND)
                .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                .body(Body::from("Fichier introuvable"))
                .unwrap();
        }
    }

    // ✍️ Sinon (body NON vide) → ÉCRITURE dans base (= state.file_path)
    let ct_str = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let is_bytes_mode = ct_str.eq_ignore_ascii_case("application/octet-stream");

    let Some(mut dest) = safe_join(&base, &rel_path) else {
        return AxumResponse::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
            .body(Body::from("Chemin invalide"))
            .unwrap();
    };

    if let Some(parent) = dest.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return AxumResponse::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                .body(Body::from(format!("Impossible de créer le dossier: {e}")))
                .unwrap();
        }
    }

    // Vérif UTF-8 en mode texte
    if !is_bytes_mode {
        if let Err(e) = std::str::from_utf8(&data) {
            if e.error_len().is_some() {
                return AxumResponse::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                    .body(Body::from(format!("Corps non UTF-8 en mode texte: {e}")))
                    .unwrap();
            }
        }
    }

    match tokio::fs::write(&dest, &data).await {
        Ok(_) => {
            let payload = FileWriteResp {
                ok: true,
                message: format!("Fichier écrit: {}", dest.display()),
                path: rel_path,
            };
            let json = serde_json::to_vec(&payload).unwrap();
            AxumResponse::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(json))
                .unwrap()
        }
        Err(e) => AxumResponse::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
            .body(Body::from(format!(
                "Échec écriture {}: {e}",
                dest.display()
            )))
            .unwrap(),
    }
}

/* -------------------- /api/run (+ status/stop) -------------------- */

#[derive(Deserialize)]
#[serde(untagged)]
enum ArgsField {
    List(Vec<String>),
    One(String),
}

#[derive(Deserialize)]
struct RunReq {
    executableName: String,
    #[serde(default)]
    arguments: Option<ArgsField>,
}

#[derive(Serialize)]
struct RunResp {
    ok: bool,
    status: Option<i32>,
    message: String,
    stdout: String,
    stderr: String,
    id: Option<u64>,
    pid: Option<u32>,
}

fn split_args_line(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            cur.push(ch);
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch.is_whitespace() && !in_quotes {
            if !cur.is_empty() {
                args.push(cur.clone());
                cur.clear();
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        args.push(cur);
    }
    args
}

async fn api_run(
    State(state): State<AppState>,
    Json(payload): Json<RunReq>,
) -> (StatusCode, Json<RunResp>) {
    let name = payload.executableName.trim();
    let bad = Path::new(name)
        .components()
        .any(|c| !matches!(c, Component::Normal(_)));
    if name.is_empty() || bad {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunResp {
                ok: false,
                status: None,
                message: "executableName invalide (pas de répertoires, ni '..')".into(),
                stdout: String::new(),
                stderr: String::new(),
                id: None,
                pid: None,
            }),
        );
    }

    let work_dir = { state.file_path.read().await.clone() };
    let exec_root = { state.exec_root.read().await.clone() };
    let mut exe_path = exec_root.join(name);
    if !exe_path.exists() && cfg!(windows) {
        exe_path = exec_root.join(format!("{name}.exe"));
    }
    if !exe_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(RunResp {
                ok: false,
                status: None,
                message: format!("Exécutable introuvable: {}", exe_path.display()),
                stdout: String::new(),
                stderr: String::new(),
                id: None,
                pid: None,
            }),
        );
    }

    let args = match &payload.arguments {
        Some(ArgsField::List(v)) => v.clone(),
        Some(ArgsField::One(s)) => split_args_line(s),
        None => vec![],
    };

    let exe_clone = exe_path.clone();
    let args_clone = args.clone();
    let wd_clone = work_dir.clone();

    let child_res = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(&exe_clone);
        cmd.args(&args_clone)
            .current_dir(&wd_clone)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        cmd.spawn()
    })
    .await;

    let mut child = match child_res {
        Ok(Ok(ch)) => ch,
        Ok(Err(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RunResp {
                    ok: false,
                    status: None,
                    message: format!("Échec de lancement: {e}"),
                    stdout: String::new(),
                    stderr: String::new(),
                    id: None,
                    pid: None,
                }),
            )
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RunResp {
                    ok: false,
                    status: None,
                    message: format!("Join error: {e}"),
                    stdout: String::new(),
                    stderr: String::new(),
                    id: None,
                    pid: None,
                }),
            )
        }
    };

    let pid = child.id();

    let id = state.next_proc_id.fetch_add(1, Ordering::Relaxed);
    let info = Arc::new(StdMutex::new(ProcInfo {
        child: Some(child),
        pid: Some(pid),
        name: name.to_string(),
        args: args.clone(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_status: None,
    }));

    {
        let mut guard = info.lock().unwrap();
        let ch = guard.child.as_mut().unwrap();
        let mut out = ch.stdout.take();
        let mut err = ch.stderr.take();

        if let Some(mut reader) = out.take() {
            let info_clone = info.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Ok(mut pi) = info_clone.lock() {
                                push_capped(&mut pi.stdout, &buf[..n]);
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        if let Some(mut reader) = err.take() {
            let info_clone = info.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Ok(mut pi) = info_clone.lock() {
                                push_capped(&mut pi.stderr, &buf[..n]);
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }

    state.procs.insert(id, info);

    (
        StatusCode::OK,
        Json(RunResp {
            ok: true,
            status: None,
            message: format!("Processus lancé (id={id}, pid={pid})"),
            stdout: String::new(),
            stderr: String::new(),
            id: Some(id),
            pid: Some(pid),
        }),
    )
}

#[derive(Deserialize)]
struct ProcIdReq {
    id: u64,
}
#[derive(Serialize)]
struct ProcStatusResp {
    ok: bool,
    running: bool,
    status: Option<i32>,
    pid: Option<u32>,
    stdout: String,
    stderr: String,
    message: String,
}
#[derive(Serialize)]
struct ProcStopResp {
    ok: bool,
    message: String,
}
async fn api_run_status(
    State(state): State<AppState>,
    Json(req): Json<ProcIdReq>,
) -> (StatusCode, Json<ProcStatusResp>) {
    if let Some(entry) = state.procs.get(&req.id) {
        let info_arc = entry.value().clone();
        let mut running = false;
        let mut status_code = None;

        {
            let mut pi = info_arc.lock().unwrap();
            if let Some(ch) = pi.child.as_mut() {
                match ch.try_wait() {
                    Ok(Some(st)) => {
                        status_code = st.code();
                        pi.exit_status = status_code;
                        pi.child = None;
                    }
                    Ok(None) => {
                        running = true;
                        status_code = None;
                    }
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ProcStatusResp {
                                ok: false,
                                running: false,
                                status: None,
                                pid: pi.pid,
                                stdout: String::new(),
                                stderr: String::new(),
                                message: format!("try_wait error: {e}"),
                            }),
                        )
                    }
                }
            } else {
                running = false;
                status_code = pi.exit_status;
            }

            let out = String::from_utf8_lossy(&pi.stdout).to_string();
            let err = String::from_utf8_lossy(&pi.stderr).to_string();

            return (
                StatusCode::OK,
                Json(ProcStatusResp {
                    ok: true,
                    running,
                    status: status_code,
                    pid: pi.pid,
                    stdout: out,
                    stderr: err,
                    message: if running {
                        "Toujours en cours".into()
                    } else {
                        "Processus terminé".into()
                    },
                }),
            );
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(ProcStatusResp {
            ok: false,
            running: false,
            status: None,
            pid: None,
            stdout: String::new(),
            stderr: String::new(),
            message: "id inconnu".into(),
        }),
    )
}

async fn api_run_stop(
    State(state): State<AppState>,
    Json(req): Json<ProcIdReq>,
) -> (StatusCode, Json<ProcStopResp>) {
    if let Some(entry) = state.procs.get(&req.id) {
        let info_arc = entry.value().clone();
        let mut pi = info_arc.lock().unwrap();
        if let Some(ch) = pi.child.as_mut() {
            match ch.kill() {
                Ok(_) => {
                    let _ = ch.wait();
                    pi.exit_status = Some(-1);
                    pi.child = None;
                    return (
                        StatusCode::OK,
                        Json(ProcStopResp {
                            ok: true,
                            message: "Processus tué".into(),
                        }),
                    );
                }
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ProcStopResp {
                            ok: false,
                            message: format!("Échec kill: {e}"),
                        }),
                    )
                }
            }
        } else {
            return (
                StatusCode::OK,
                Json(ProcStopResp {
                    ok: true,
                    message: "Déjà terminé".into(),
                }),
            );
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(ProcStopResp {
            ok: false,
            message: "id inconnu".into(),
        }),
    )
}

/* -------------------- /api/run/stopAll -------------------- */
#[derive(Serialize)]
struct StopAllResp {
    ok: bool,
    message: String,
}
async fn api_run_stop_all(State(state): State<AppState>) -> (StatusCode, Json<StopAllResp>) {
    state.kill_all_children();
    (
        StatusCode::OK,
        Json(StopAllResp {
            ok: true,
            message: "Tous les processus ont été arrêtés".into(),
        }),
    )
}


// -------------------- Explorer (POST, body { path, type?, maxDeep?, maxSize? }) --------------------
use serde_json::json;

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum ExplorerMode {
    Array,
    Tree,
}

#[derive(Deserialize)]
struct ExplorerReq {
    #[serde(default)]
    path: String, // relatif OU absolu

    // "type": "array" | "tree"
    #[serde(default, rename = "type")]
    mode: Option<ExplorerMode>,

    #[serde(default, rename = "maxDeep")]
    max_deep: Option<usize>,

    #[serde(default, rename = "maxSize")]
    max_size: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArrayFileItem {
    name: String,
    path: String, // absolu
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TreeItem {
    r#type: String, // "file" | "directory"
    name: String,
    path: String, // absolu
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<Vec<TreeItem>>,
}

// 👉 Helper : convertit un Path en chaîne "humaine" (sans \\?\ et avec UNC propre)
#[cfg(windows)]
fn pretty_path_string(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        // \\?\UNC\server\share\...  ->  \\server\share\...
        format!(r"\\{}", rest)
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        // \\?\C:\...  ->  C:\...
        rest.to_string()
    } else {
        s
    }
}

#[cfg(not(windows))]
fn pretty_path_string(p: &std::path::Path) -> String {
    p.display().to_string()
}

// async version existante (utilisée plus haut dans ton fichier)
async fn to_abs_string(p: &PathBuf) -> String {
    match tokio::fs::canonicalize(p).await {
        Ok(c) => pretty_path_string(&c),
        Err(_) => pretty_path_string(p),
    }
}

// sync version (pour spawn_blocking)
fn to_abs_string_sync(p: &std::path::Path) -> String {
    match std::fs::canonicalize(p) {
        Ok(c) => pretty_path_string(&c),
        Err(_) => pretty_path_string(p),
    }
}

fn read_dir_sorted_sync(
    dir: &std::path::Path,
) -> Result<Vec<(String, std::path::PathBuf, std::fs::FileType)>, String> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| format!("Erreur lecture répertoire {}: {e}", dir.display()))?;

    let mut items = Vec::new();
    for ent in rd {
        let ent = match ent {
            Ok(e) => e,
            Err(_) => continue,
        };
        let ft = match ent.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        let name = ent.file_name().to_string_lossy().to_string();
        items.push((name, ent.path(), ft));
    }

    items.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
    Ok(items)
}

/// Collecte à plat (fichiers uniquement), avec limites
fn collect_files_array_sync(
    dir: &std::path::Path,
    depth_dir: usize,        // profondeur du dossier courant (root=0)
    max_deep: Option<usize>, // profondeur max des entrées (root children = 1)
    max_size: Option<usize>, // nombre max de fichiers retournés (global)
    out: &mut Vec<ArrayFileItem>,
    files_seen: &mut usize,
) -> Result<(), String> {
    if max_size.map(|s| *files_seen >= s).unwrap_or(false) {
        return Ok(());
    }

    let entries = read_dir_sorted_sync(dir)?;
    for (name, path, ft) in entries {
        if max_size.map(|s| *files_seen >= s).unwrap_or(false) {
            break;
        }
        if ft.is_symlink() {
            continue;
        }

        let entry_depth = depth_dir + 1; // enfant direct = 1
        if max_deep.map(|d| entry_depth > d).unwrap_or(false) {
            continue;
        }

        if ft.is_file() {
            out.push(ArrayFileItem {
                name,
                path: to_abs_string_sync(&path),
            });
            *files_seen += 1;
        } else if ft.is_dir() {
            let can_recurse = max_deep.map(|d| entry_depth < d).unwrap_or(true);
            if can_recurse {
                collect_files_array_sync(&path, entry_depth, max_deep, max_size, out, files_seen)?;
            }
        }
    }

    Ok(())
}

/// Construit un arbre (dossiers + fichiers), avec limites
fn build_tree_sync(
    dir: &std::path::Path,
    depth_dir: usize,        // profondeur du dossier courant (root=0)
    max_deep: Option<usize>, // profondeur max des entrées (root children = 1)
    max_size: Option<usize>, // nombre max de fichiers retournés (global)
    files_seen: &mut usize,
) -> Result<Vec<TreeItem>, String> {
    if max_size.map(|s| *files_seen >= s).unwrap_or(false) {
        return Ok(vec![]);
    }

    let entries = read_dir_sorted_sync(dir)?;
    let mut out = Vec::new();

    for (name, path, ft) in entries {
        if max_size.map(|s| *files_seen >= s).unwrap_or(false) {
            break;
        }
        if ft.is_symlink() {
            continue;
        }

        let entry_depth = depth_dir + 1;
        if max_deep.map(|d| entry_depth > d).unwrap_or(false) {
            continue;
        }

        if ft.is_file() {
            out.push(TreeItem {
                r#type: "file".into(),
                name,
                path: to_abs_string_sync(&path),
                content: None,
            });
            *files_seen += 1;
        } else if ft.is_dir() {
            let can_expand = max_deep.map(|d| entry_depth < d).unwrap_or(true);
            let content = if can_expand {
                Some(build_tree_sync(&path, entry_depth, max_deep, max_size, files_seen)?)
            } else {
                None
            };

            out.push(TreeItem {
                r#type: "directory".into(),
                name,
                path: to_abs_string_sync(&path),
                content,
            });
        }
    }

    Ok(out)
}

async fn api_explorer_post(
    State(_state): State<AppState>,
    Json(req): Json<ExplorerReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Règle : path vide -> CWD ; relatif -> CWD + rel ; absolu -> tel quel
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let target: PathBuf = {
        let raw = req.path.trim();
        if raw.is_empty() {
            cwd.clone()
        } else {
            let p = PathBuf::from(raw);
            if p.is_absolute() {
                p
            } else {
                cwd.join(p)
            }
        }
    };

    let meta = match tokio::fs::metadata(&target).await {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "type":"error", "message": format!("Introuvable: {}", e)
                })),
            );
        }
    };

    let abs_path = to_abs_string(&target).await;
    let parent_abs = target.parent().map(|p| p.to_path_buf());
    let parent_abs = match parent_abs {
        Some(p) => Some(to_abs_string(&p).await),
        None => None,
    };

    if meta.is_file() {
        let name = target
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| abs_path.clone());
        return (
            StatusCode::OK,
            Json(json!({
                "type": "file",
                "path": abs_path,
                "name": name,
                "parent": parent_abs
            })),
        );
    }

    if meta.is_dir() {
        // Backward compat :
        // - si mode absent => comportement "tree shallow" (maxDeep=1 par défaut)
        // - si mode présent => maxDeep illimité si non fourni
        let mode = req.mode.unwrap_or(ExplorerMode::Tree);

        let max_deep = if req.mode.is_none() {
            Some(req.max_deep.unwrap_or(1))
        } else {
            req.max_deep
        };

        let max_size = req.max_size;

        let target_cl = target.clone();
        let job = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
            let mut files_seen = 0usize;

            match mode {
                ExplorerMode::Array => {
                    let mut files = Vec::<ArrayFileItem>::new();
                    collect_files_array_sync(
                        &target_cl,
                        0,
                        max_deep,
                        max_size,
                        &mut files,
                        &mut files_seen,
                    )?;
                    serde_json::to_value(files).map_err(|e| e.to_string())
                }
                ExplorerMode::Tree => {
                    let content = build_tree_sync(&target_cl, 0, max_deep, max_size, &mut files_seen)?;
                    serde_json::to_value(content).map_err(|e| e.to_string())
                }
            }
        })
        .await;

        match job {
            Ok(Ok(content_value)) => {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "type": "directory",
                        "path": abs_path,
                        "parent": parent_abs,
                        "content": content_value
                    })),
                );
            }
            Ok(Err(msg)) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "type":"error", "message": msg })),
                );
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "type":"error", "message": format!("Join error: {e}") })),
                );
            }
        }
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "type":"error", "message":"Type de ressource non supporté"
        })),
    )
}


/* -------------------- Middleware TS -------------------- */
async fn ts_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> AxumResponse {
    use std::path::Path;

    let uri_path = req.uri().path().to_string();
    let current_root = { state.root.read().await.clone() };

    // 1) URL SANS EXTENSION -> essayer .ts puis .js
    if uri_path != "/" && Path::new(&uri_path).extension().is_none() {
        let rel = uri_path.trim_start_matches('/');

        let ts_path = current_root.join(format!("{rel}.ts"));
        let js_path = current_root.join(format!("{rel}.js"));

        // Prefer .ts si présent (transpile -> JS)
        if ts_path.exists() {
            match fs::metadata(&ts_path).and_then(|m| m.modified()) {
                Ok(mtime) => {
                    if let Some(entry) = TS_CACHE.get(&ts_path) {
                        if entry.value().0 == mtime {
                            let code = entry.value().1.clone();
                            return AxumResponse::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/javascript")
                                .body(Body::from(code.as_str().to_owned()))
                                .unwrap();
                        }
                    }
                    match transpile_ts_file(&ts_path) {
                        Ok(code) => {
                            let code_arc = Arc::new(code);
                            TS_CACHE.insert(ts_path.clone(), (mtime, code_arc.clone()));
                            return AxumResponse::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/javascript")
                                .body(Body::from(code_arc.as_str().to_owned()))
                                .unwrap();
                        }
                        Err(e) => {
                            let msg =
                                format!("Transpilation error for {}: {e}", ts_path.display());
                            eprintln!("❌ {msg}");
                            return AxumResponse::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                                .body(Body::from(msg))
                                .unwrap();
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("Cannot stat {}: {e}", ts_path.display());
                    eprintln!("❌ {msg}");
                    return AxumResponse::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                        .body(Body::from(msg))
                        .unwrap();
                }
            }
        }

        // Sinon, servir le .js si présent
        if js_path.exists() {
            match tokio::fs::read(&js_path).await {
                Ok(bytes) => {
                    return AxumResponse::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/javascript")
                        .body(Body::from(bytes))
                        .unwrap();
                }
                Err(e) => {
                    let msg = format!("Erreur de lecture {}: {e}", js_path.display());
                    eprintln!("❌ {msg}");
                    return AxumResponse::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                        .body(Body::from(msg))
                        .unwrap();
                }
            }
        }
        // Si ni .ts ni .js n'existent → on laisse passer vers le handler suivant
    }

    // 2) Comportement existant: .ts direct, ou .js avec .ts adjacent
    let mut fs_path = current_root.join(uri_path.trim_start_matches('/'));
    let mut needs_transpile = false;

    if fs_path.extension().and_then(|e| e.to_str()) == Some("ts") {
        needs_transpile = true;
    }
    if !needs_transpile && fs_path.extension().and_then(|e| e.to_str()) == Some("js") {
        let ts_candidate = fs_path.with_extension("ts");
        if ts_candidate.exists() {
            fs_path = ts_candidate;
            needs_transpile = true;
        }
    }

    if needs_transpile && fs_path.exists() {
        match fs::metadata(&fs_path).and_then(|m| m.modified()) {
            Ok(mtime) => {
                if let Some(entry) = TS_CACHE.get(&fs_path) {
                    if entry.value().0 == mtime {
                        let code = entry.value().1.clone();
                        return AxumResponse::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/javascript")
                            .body(Body::from(code.as_str().to_owned()))
                            .unwrap();
                    }
                }

                match transpile_ts_file(&fs_path) {
                    Ok(code) => {
                        let code_arc = Arc::new(code);
                        TS_CACHE.insert(fs_path.clone(), (mtime, code_arc.clone()));
                        return AxumResponse::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/javascript")
                            .body(Body::from(code_arc.as_str().to_owned()))
                            .unwrap();
                    }
                    Err(e) => {
                        let msg =
                            format!("Transpilation error for {}: {e}", fs_path.display());
                        eprintln!("❌ {msg}");
                        return AxumResponse::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                            .body(Body::from(msg))
                            .unwrap();
                    }
                }
            }
            Err(e) => {
                let msg = format!("Cannot stat {}: {e}", fs_path.display());
                eprintln!("❌ {msg}");
                return AxumResponse::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                    .body(Body::from(msg))
                    .unwrap();
            }
        }
    }

    next.run(req).await
}

/* -------------------- Handler statique -------------------- */
async fn static_handler(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> AxumResponse {
    let root = { state.root.read().await.clone() };
    let req_path = uri.path().to_string();

    // Cas général : servir le fichier demandé (sauf pour "/")
    if req_path != "/" {
        let rel = PathBuf::from(req_path.trim_start_matches('/'));
        let candidate = root.join(&rel);

        if candidate.is_file() {
            match tokio::fs::read(&candidate).await {
                Ok(bytes) => {
                    let ct = mime_guess::from_path(&candidate)
                        .first_or_octet_stream()
                        .essence_str()
                        .to_string();
                    return AxumResponse::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, ct)
                        .body(Body::from(bytes))
                        .unwrap();
                }
                Err(e) => {
                    let msg = format!("Erreur de lecture {}: {e}", candidate.display());
                    eprintln!("❌ {msg}");
                    return AxumResponse::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                        .body(Body::from(msg))
                        .unwrap();
                }
            }
        }

        // Fallback SPA classique : /anything -> index.html si présent
        let index = root.join("index.html");
        if index.is_file() {
            match tokio::fs::read(&index).await {
                Ok(bytes) => {
                    return AxumResponse::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "text/html; charset=utf-8")
                        .body(Body::from(bytes))
                        .unwrap();
                }
                Err(e) => {
                    let msg = format!("Erreur de lecture {}: {e}", index.display());
                    eprintln!("❌ {msg}");
                    return AxumResponse::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                        .body(Body::from(msg))
                        .unwrap();
                }
            }
        }

        // Sinon 404
        return AxumResponse::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
            .body(Body::from("404 Not Found"))
            .unwrap();
    }

    // Cas "/" : d'abord essayer index.html
    let index = root.join("index.html");
    if index.is_file() {
        match tokio::fs::read(&index).await {
            Ok(bytes) => {
                return AxumResponse::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Body::from(bytes))
                    .unwrap();
            }
            Err(e) => {
                let msg = format!("Erreur de lecture {}: {e}", index.display());
                eprintln!("❌ {msg}");
                return AxumResponse::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                    .body(Body::from(msg))
                    .unwrap();
            }
        }
    }

    // Fallback demandé : si pas d'index.html, chercher index.ts puis index.js
    let index_ts = root.join("index.ts");
    let index_js = root.join("index.js");

    let use_boot = if tokio::fs::metadata(&index_ts)
        .await
        .ok()
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        Some("index.ts")
    } else if tokio::fs::metadata(&index_js)
        .await
        .ok()
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        Some("index.js")
    } else {
        None
    };

    if let Some(entry) = use_boot {
        // HTML minimal qui charge le module juste après l'ouverture de <body>
        let html = format!(
            r#"<!doctype html>
<meta charset="utf-8">
<title>{}</title>
<body>
<script type="module" src="/{}"></script>
</body>
"#,
            exe_title(),
            entry
        );

        return AxumResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(html))
            .unwrap();
    }

    // Rien trouvé
    AxumResponse::builder()
        .status(StatusCode::NOT_FOUND)
        .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
        .body(Body::from("404 Not Found"))
        .unwrap()
}

/* -------------------- Fabrique de Router -------------------- */
fn make_app_router(state: AppState) -> Router {
    Router::new()
        .route("/api/embed", post(api_embed))
        .route("/api/useConfig", post(api_use_config))
        .route("/api/get-config", post(api_get_config))
        // /api/file/*file : base sur state.file_path (lecture si body vide, écriture sinon)
          .route("/api/file/*file",post(api_write_file).delete(api_delete_file))
        // modifier la base /api/file via body { path: string }
        .route("/api/current-directory", post(api_current_directory))
        // --- route (dans make_app_router) ---
        .route("/api/unzip", post(api_unzip))

        .route("/api/run", post(api_run))
        .route("/api/run/status", post(api_run_status))
        .route("/api/run/stop", post(api_run_stop))
        .route("/api/run/stopAll", post(api_run_stop_all))
        // nouvelles routes:
        .route("/api/newServer", post(api_new_server))
        .route("/api/stop", post(api_stop_server))
        // --- Explorer (POST avec body { path }) ---
        .route("/api/explorer", post(api_explorer_post))
        // statique (en dernier)
        .route("/*path", get(static_handler))
        .route("/", get(static_handler))
        .layer(middleware::from_fn_with_state(state.clone(), ts_middleware))
        .with_state(state)
}

/* -------------------- Démarrage (principal) -------------------- */
async fn start_static_server(state: AppState) -> Result<SocketAddr> {
    let app = make_app_router(state.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;

    tauri::async_runtime::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("static server error: {e}");
        }
    });

    Ok(addr)
}

/* -------------------- Démarrage serveurs enfants + shutdown -------------------- */
async fn spawn_additional_server(
    mut child_state: AppState,
    req_port: Option<u16>,
) -> std::result::Result<u16, String> {
    let self_shutdown = Arc::new(StdMutex::new(None));
    child_state.self_shutdown = Some(self_shutdown.clone());

    let bind_port = req_port.unwrap_or(0);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", bind_port))
        .await
        .map_err(|e| format!("Bind échoué sur le port {}: {}", bind_port, e))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let port = addr.port();
    child_state.self_port = Some(port);

    let app = make_app_router(child_state.clone());

    let (tx, rx) = oneshot::channel::<()>(); // 👈 bien appeler la fonction

    {
        let mut guard = self_shutdown.lock().unwrap();
        *guard = Some(tx);
    }

    let servers_map = child_state.servers.clone();
    servers_map.insert(port, self_shutdown.clone());

    tauri::async_runtime::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
        {
            eprintln!("child server {port} error: {e}");
        }
        servers_map.remove(&port);
        println!("🛑 child server {port} stopped");
    });

    Ok(port)
}

/* -------------------- /api/newServer -------------------- */
#[derive(Deserialize)]
struct NewServerReq {
    code: String,
    executable: String,
    #[serde(default)]
    port: Option<u16>,
}
#[derive(Serialize)]
struct NewServerResp {
    ok: bool,
    port: Option<u16>,
    message: String,
}async fn api_new_server(
    State(state): State<AppState>,
    Json(req): Json<NewServerReq>,
) -> (StatusCode, Json<NewServerResp>) {
    let code = PathBuf::from(&req.code);
    let exec = PathBuf::from(&req.executable);
    if !code.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(NewServerResp {
                ok: false,
                port: None,
                message: format!("'code' n'est pas un dossier: {}", code.display()),
            }),
        );
    }
    if !exec.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(NewServerResp {
                ok: false,
                port: None,
                message: format!("'executable' n'est pas un dossier: {}", exec.display()),
            }),
        );
    }

    let child_state = AppState {
        root: Arc::new(RwLock::new(code)),
        exec_root: Arc::new(RwLock::new(exec)),
        file_path: Arc::new(RwLock::new(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        )),
        procs: Arc::new(DashMap::new()),
        next_proc_id: Arc::new(AtomicU64::new(1)),
        servers: state.servers.clone(),
        self_port: None,
        self_shutdown: None,
    };

    match spawn_additional_server(child_state, req.port).await {
        Ok(port) => (
            StatusCode::OK,
            Json(NewServerResp {
                ok: true,
                port: Some(port),
                message: format!("Nouveau serveur lancé sur http://127.0.0.1:{port}"),
            }),
        ),
        Err(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(NewServerResp {
                ok: false,
                port: None,
                message: msg,
            }),
        ),
    }
}


/* -------------------- /api/stop -------------------- */
#[derive(Deserialize)]
struct StopServerReq {
    #[serde(default)]
    port: Option<u16>,
}
#[derive(Serialize)]
struct StopServerResp {
    ok: bool,
    port: Option<u16>,
    message: String,
}
async fn api_stop_server(
    State(state): State<AppState>,
    Json(req): Json<StopServerReq>,
) -> (StatusCode, Json<StopServerResp>) {
    if let Some(p) = req.port {
        if let Some(entry) = state.servers.get(&p) {
            let arc = entry.value().clone();
            drop(entry);
            let tx_opt = {
                let mut guard = arc.lock().unwrap();
                guard.take()
            };
            if let Some(tx) = tx_opt {
                let _ = tx.send(());
                return (
                    StatusCode::OK,
                    Json(StopServerResp {
                        ok: true,
                        port: Some(p),
                        message: format!("Demande d'arrêt envoyée au serveur {p}"),
                    }),
                );
            } else {
                return (
                    StatusCode::OK,
                    Json(StopServerResp {
                        ok: true,
                        port: Some(p),
                        message: "Déjà en cours d'arrêt ou arrêté".into(),
                    }),
                );
            }
        }
        return (
            StatusCode::NOT_FOUND,
            Json(StopServerResp {
                ok: false,
                port: Some(p),
                message: "Serveur inconnu (port non enregistré)".into(),
            }),
        );
    }

    if let Some(sh) = &state.self_shutdown {
        let tx_opt = {
            let mut guard = sh.lock().unwrap();
            guard.take()
        };
        if let Some(tx) = tx_opt {
            let p = state.self_port;
            let _ = tx.send(());
            return (
                StatusCode::OK,
                Json(StopServerResp {
                    ok: true,
                    port: p,
                    message: "Demande d'arrêt envoyée (ce serveur)".into(),
                }),
            );
        } else {
            return (
                StatusCode::OK,
                Json(StopServerResp {
                    ok: true,
                    port: state.self_port,
                    message: "Déjà en cours d'arrêt ou arrêté".into(),
                }),
            );
        }
    }

    (
        StatusCode::BAD_REQUEST,
        Json(StopServerResp {
            ok: false,
            port: None,
            message:
                "Ce serveur ne peut pas être arrêté via /api/stop sans préciser { port }".into(),
        }),
    )
}

/* -------------------- Serveur + routes (alias, si besoin) -------------------- */
async fn start_static_server_init(state: AppState) -> Result<SocketAddr> {
    start_static_server(state).await
}

/* -------------------- Tauri -------------------- */
fn run_tauri_serving_dir(root_dir: PathBuf, has_embedding: bool) {
    let default_exec = root_dir
        .parent()
        .unwrap_or(&root_dir)
        .join("executable");

    let state = AppState {
        root: Arc::new(RwLock::new(root_dir.clone())),
        exec_root: Arc::new(RwLock::new(default_exec)),
        file_path: Arc::new(RwLock::new(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        )),
        procs: Arc::new(DashMap::new()),
        next_proc_id: Arc::new(AtomicU64::new(1)),
        servers: Arc::new(DashMap::new()),
        self_port: None,
        self_shutdown: None,
    };

    let state_for_server = state.clone();
    let state_for_runloop = state.clone();

    let builder = tauri::Builder::default()
        .manage(state.clone())
        .setup(move |app| {
            let title = exe_title();
            let window = app.get_window("main").unwrap_or_else(|| {
                tauri::WindowBuilder::new(app, "main", tauri::WindowUrl::App("about:blank".into()))
                    .title(&title)
                    .maximized(true)
                    .build()
                    .expect("failed to create main window")
            });
            let _ = window.set_title(&title);
            window.maximize();

            {
                let mut gsm = app.global_shortcut_manager();
                let w_f5 = window.clone();
                gsm.register("F5", move || {
                    let _ = w_f5.eval("location.reload()");
                })?;
                let w_r = window.clone();
                gsm.register("CmdOrCtrl+R", move || {
                    let _ = w_r.eval("location.reload()");
                })?;
            }

            let win_for_spawn = window.clone();
            let has_embedding_q = has_embedding;
            tauri::async_runtime::spawn(async move {
                match start_static_server(state_for_server).await {
                    Ok(addr) => {
                        let url = format!(
                            "http://{}/?hasEmbeding={}",
                            addr,
                            if has_embedding_q { "true" } else { "false" }
                        );
                        println!("🚀 Static server on {url}");
                        let _ = win_for_spawn.eval(&format!("console.log('🚀 {}')", url));
                        let _ = win_for_spawn.eval(&format!("window.location.replace('{url}')"));
                    }
                    Err(e) => eprintln!("❌ Impossible de démarrer le serveur statique: {e}"),
                }
            });

            Ok(())
        });

    let app = builder
        .build(tauri::generate_context!())
        .expect("error while building tauri app");

    app.run(move |_app_handle, event| match event {
        tauri::RunEvent::ExitRequested { .. } => {
            state_for_runloop.kill_all_children();
        }
        tauri::RunEvent::WindowEvent {
            event: tauri::WindowEvent::CloseRequested { .. },
            ..
        } => {
            state_for_runloop.kill_all_children();
        }
        _ => {}
    });
}

/* -------------------- main -------------------- */
fn main() {
    let base_dir = default_served_base_dir();
    if let Err(e) = fs::create_dir_all(&base_dir) {
        eprintln!(
            "❌ Impossible de créer le dossier {} : {}",
            base_dir.display(),
            e
        );
    }
    println!("📂 Répertoire (base) : {}", base_dir.display());

    let code_dir = base_dir.join("code");
    if let Err(e) = fs::create_dir_all(&code_dir) {
        eprintln!("❌ Impossible de créer {}", code_dir.display());
    }

 let exe = env::current_exe().expect("exe");
let fallback_pathIndex = code_dir.join("index.html");


let has_embedding = if !fallback_pathIndex.exists() {
    // Matérialise TOUT le contenu de assets/ dans code_dir
    let _ = fs::create_dir_all(&code_dir);
    let _ = write_embedded_assets_to(&code_dir);

    // Votre logique existante
    extract_embedded_zip(&exe, &base_dir)
} else {
    has_embedded_zip(&exe)
};


    run_tauri_serving_dir(code_dir, has_embedding);
}
