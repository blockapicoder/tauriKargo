# TauriKargo

> 💾 **Downloads**
>
> • **Pre-release:** [v0.1.0-rc1](https://github.com/blockapicoder/tauriKargo/releases)
>


A portable, self-contained Tauri + Axum utility for bundling a **web UI folder** and an **executable folder** into a single binary, then serving the UI locally with live TypeScript transpile and a small HTTP API for file/process orchestration.

> TL;DR: Point TauriKargo at a `code/` folder (your web app) and an `executable/` folder (your CLI tools). It can package both into one `.exe`, extract them on first run, host the UI on `127.0.0.1:<port>`, and let the UI manage files and spawn processes via HTTP.

---

## Key Features

* **Single-binary packaging**: Packs two folders (UI `code/` + `executable/`) into the running binary using a custom marker and embedded ZIP.
* **Auto-extract at runtime**: On first run, unpacks embedded assets to a derived base directory alongside the executable name.
* **Local web server (Axum)**: Serves static files, supports SPA fallback, and exposes a JSON API under `/api/*`.
* **TypeScript → JavaScript on the fly**: Requests to `.ts` (or extension-less paths) are transpiled using `deno_ast` and cached by mtime.
* **Process orchestration**: Start external tools, stream/collect capped logs, poll status, and kill processes.
* **File operations with a movable base**: Read/write arbitrary files relative to a configurable working directory.
* **Child servers**: Spin up additional isolated servers bound to `127.0.0.1` on dynamic ports, with graceful shutdown.
* **Tauri desktop shell**: Launches a native window, maximized by default, with shortcuts for reload (`F5`, `Cmd/Ctrl+R`).

---

## How It Works

1. **Packaging**: `POST /api/embed` writes the current binary bytes + `---EMBED-ZIP-START---` marker + ZIP payload of two folders:

   * `code/` → served as the web root.
   * `executable/` → location for child processes you want to run.
2. **Extraction**: On startup, TauriKargo checks for the marker. If present, it extracts into a base dir like `<exe_dir>/<exe_stem>/`.
3. **Serving**: Axum binds to `127.0.0.1:<dynamic>`, serves `index.html` or falls back to `index.ts/js` boot. Tauri window navigates to that URL.
4. **Transpile**: Requests to TS assets are transpiled with `deno_ast` and cached (mtime-based) before sending JS.
5. **Control Plane**: The `/api/*` routes manage packaging, config, files, processes, and child servers.

---

## REST API Overview

> Full OpenAPI spec is available as `api-doc.json`.

### Embed / Packaging

* `POST /api/embed` – Bundle `code` + `executable` into a new single binary.

### Configuration

* `POST /api/useConfig` – Point the server to new `code` and `executable` roots.
* `POST /api/get-config` – Read current roots and file base.

### Files & Working Directory

* `POST /api/current-directory` – Set the base directory for file ops.
* `POST /api/file/{file}` – **Read or write** a file relative to the base.

  * Empty body ⇒ **read** (returns file bytes or text)
  * Non-empty body ⇒ **write** (returns JSON confirmation)

### Process Control

* `POST /api/run` – Launch an executable found in `executable/`.
* `POST /api/run/status` – Poll a process by `id` (stdout/stderr buffered with cap).
* `POST /api/run/stop` – Kill a specific process by `id`.
* `POST /api/run/stopAll` – Kill all spawned processes.

### Explorer

* `POST /api/explorer` – Describe a file or list a directory (absolute or relative to CWD).

### Child Servers

* `POST /api/newServer` – Start an isolated server with its own `code`/`executable` roots.
* `POST /api/stop` – Stop a specific child (`{ port }`) or attempt to stop the current server.

---

## Quick Start

1. **Build** your Rust Tauri app (requires Rust toolchain and Tauri setup).
2. **Prepare folders**:

   * `code/`: your web assets (`index.html`, or `index.ts`/`index.js` entry).
   * `executable/`: tools you want to run from the UI.
3. **Run** the app once; it creates a base directory like `<exe_dir>/<exe_stem>/` and a `code/` subfolder.
4. **Develop**:

   * Drop your UI files into `code/`. Hitting `/` serves `index.html`, otherwise it will try `index.ts`/`index.js` boot.
   * Use the API from your UI to read/write files, run executables, or spawn child servers.
5. **Package everything**:

   * `POST /api/embed` with JSON body `{ "code": "/abs/path/to/code", "executable": "/abs/path/to/executable", "output": "/abs/path/NewApp.exe" }`.

> On Windows, processes are spawned with `CREATE_NO_WINDOW` to avoid console flashes.

---

## Example Requests

**Embed**

```bash
curl -X POST http://127.0.0.1:8080/api/embed \
  -H "Content-Type: application/json" \
  -d '{"code":"C:/apps/MyApp/code","executable":"C:/apps/MyApp/executable","output":"C:/apps/MyApp/MyApp.exe"}'
```

**Write a file**

```bash
curl -X POST http://127.0.0.1:8080/api/file/logs/app.txt \
  -H "Content-Type: text/plain; charset=utf-8" \
  --data-binary @local.txt
```

**Read a file** (empty body)

```bash
curl -X POST http://127.0.0.1:8080/api/file/logs/app.txt --data '' --output -
```

**Run a tool**

```bash
curl -X POST http://127.0.0.1:8080/api/run \
  -H "Content-Type: application/json" \
  -d '{"executableName":"mycli","arguments":["--help"]}'
```

**Poll status**

```bash
curl -X POST http://127.0.0.1:8080/api/run/status \
  -H "Content-Type: application/json" \
  -d '{"id":1}'
```

**Stop all**

```bash
curl -X POST http://127.0.0.1:8080/api/run/stopAll
```

---

## Directory Layout

At runtime (after extraction):

```
<exe_dir>/<exe_stem>/
├─ code/           # web root served by Axum (TS transpiled on request)
└─ executable/     # binaries/tools launched via /api/run
```

`/api/current-directory` controls a third, independent base for `/api/file/*` read/writes.

---

## Security Notes

* Server binds to `127.0.0.1` only.
* File API is constrained by a safe-join path guard to avoid `..` traversal.
* Logs from child processes are capped in memory (`LOG_CAP_BYTES`).
* Child servers inherit the same constraints and support graceful shutdown.

> Review your threat model before shipping to end users. Exposed endpoints should be used by your own local UI.

---

## Development Tips

* **Hot reload**: Use `F5` or `Cmd/Ctrl+R` in the Tauri window.
* **TS transpile**: The middleware will serve `.ts` as JS using `deno_ast`; mtime cache avoids repeated work.
* **SPA support**: Non-existent paths fall back to `index.html` when present.
* **Diagnostics**: The console prints the local URL once the server is up.

---

## Troubleshooting

* **`/api/file` returns 400/404**: Ensure `current-directory` is set to an existing folder and your path is relative.
* **Executable not found**: Place the program in `executable/` (or use the OS extension like `.exe` on Windows).
* **Port conflicts**: Child servers choose a free port when `port` is omitted.
* **TypeScript not served**: Confirm requests hit `.ts` or extension-less paths; check transpile errors in logs.

---

## License

MIT 
