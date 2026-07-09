# TauriKargo

TauriKargo is a desktop packaging and launcher tool built with Tauri, Rust, Axum, and TypeScript. It turns a folder-based web application into a local desktop experience, serves it from `127.0.0.1`, gives the UI access to controlled file and process APIs, and can bundle the web UI plus external executables into a single self-contained binary.

The built-in interface is created with [`tauri-kargo-tools`](https://github.com/blockapicoder/tauriKargoTools), a small declarative TypeScript UI toolkit used by this project to build the explorer, launcher, tester, dialogs, forms, lists, and API client.

## What It Does

TauriKargo is designed for projects that are made of two parts:

- a `code/` folder containing a web UI (`index.ts`, `index.js`, `index.html`, or an `index.json` start entry);
- an `executable/` folder containing command-line tools or binaries that the UI can start.

At runtime, TauriKargo starts a local Axum server, opens a native Tauri window, serves the selected UI folder, transpiles TypeScript on demand, and exposes local APIs for packaging, files, directories, processes, test helpers, and child servers.

## Main Features

- Desktop shell powered by Tauri.
- Local-only HTTP server bound to `127.0.0.1`.
- Web UI serving with SPA fallback.
- Static route mapping to extra local folders or HTTP/HTTPS proxy targets.
- TypeScript and TSX transpilation through `deno_ast`.
- Import map support through `importmap.json`.
- Runtime extraction of embedded `code/` and `executable/` folders.
- Single-binary packaging through `/api/embed`.
- File read, write, delete, and directory creation APIs.
- Process launcher with status polling, capped logs, and stop controls.
- Child server management for running multiple packaged apps at once.
- Built-in project explorer, app launcher, packager, and test runner UI.

## Built-In Interface

The default UI is stored in `src-tauri/assets` and is compiled into the application. If no embedded app is found on startup, TauriKargo writes this default interface into the runtime `code/` folder and opens it.

The interface is built with `tauri-kargo-tools`:

- `defineVue(...)` declares UI layouts directly from TypeScript models.
- `boot(...)` mounts a model into the page.
- `createClient()` creates a typed client for the TauriKargo HTTP API.
- Builder components such as flows, labels, inputs, buttons, dialogs, selects, images, menus, and nested views are used to compose the UI.

### Explorer

The explorer lets you browse local directories from inside the app. When it finds a folder containing an app entry file (`index.ts`, `index.js`, `index.html`, or `index.json`), it can register that folder as a launchable application.

The explorer is also reused to choose:

- the folder that contains external executables;
- the output folder where packaged binaries should be written.

### Launcher

The launcher displays registered applications from `applications.json`. From there you can:

- select an application;
- run it in a new local child server;
- open it in a new browser window;
- stop the child server automatically when the window closes;
- remove the application from the launcher;
- choose the executable folder;
- choose the packaging output folder;
- package the selected application into a new executable.

Registered applications are stored as:

```json
{
  "applications": {
    "MyApp": {
      "code": "C:/path/to/MyApp"
    }
  },
  "executable": "C:/path/to/executable",
  "packagerOutput": "C:/path/to/output"
}
```

### Test Runner

The test runner looks for files in the selected project's `test/` folder and runs them as module workers through the local server. It supports:

- running one selected test;
- running all tests;
- filtering logs, passed assertions, failed assertions, and terminate events;
- snapshot updates written to `test/snapshots`;
- snapshot cleanup from the UI.

## Runtime Layout

When the application starts, it creates a base directory beside the executable:

```text
<exe_dir>/<exe_stem>/
|-- code/          # web root served by the local server
`-- executable/    # binaries used by /api/run
```

For example, if the executable is `TauriKargo.exe`, the default runtime folder is:

```text
TauriKargo/
|-- code/
`-- executable/
```

The file API has its own current directory, controlled by `/api/current-directory`. This is where `applications.json` is read and written by the default UI.

## Static Routes And Proxies

`POST /api/useConfig` and `POST /api/newServer` accept an optional `routes` object:

```ts
routes?: { [base: string]: string }
```

Each key is a URL base path handled by TauriKargo. The longest matching base wins.

If the value is a local directory, TauriKargo serves the rest of the request path from that directory:

```json
{
  "code": "C:/apps/MyApp/code",
  "executable": "C:/apps/MyApp/executable",
  "routes": {
    "/assets": "C:/shared/assets"
  }
}
```

With this configuration, `/assets/logo.png` is served from `C:/shared/assets/logo.png`.

If the value starts with `http://` or `https://`, the route becomes a proxy. TauriKargo forwards the method, query string, body, and useful headers to the target URL, and adds CORS headers to proxy responses:

```json
{
  "code": "C:/apps/MyApp/code",
  "executable": "C:/apps/MyApp/executable",
  "routes": {
    "/remote-api": "https://example.com/api"
  }
}
```

With this configuration, `/remote-api/users?id=1` is proxied to `https://example.com/api/users?id=1`.

## How Packaging Works

Packaging is handled by `POST /api/embed`.

The endpoint reads the currently running executable, appends a marker (`---EMBED-ZIP-START---`), then appends a ZIP archive containing:

```text
code/
executable/
```

When the generated executable starts, TauriKargo detects the embedded ZIP and extracts it into the runtime base directory. The extracted `code/` folder becomes the served UI, and the extracted `executable/` folder becomes the process root.

## Quick Start

1. Build or download TauriKargo.
2. Start the app.
3. Use the explorer to register a folder that contains `index.ts`, `index.js`, `index.html`, or `index.json`.
4. Select the registered app in the launcher.
5. Click `Executer` to run it on a child local server.
6. Set the executable folder if your app needs to run external tools.
7. Set the package output folder.
8. Click `Packager`, choose an executable name, and generate a self-contained binary.

## App Entry Points

TauriKargo chooses the served entry in this order:

1. `index.json` with a valid `start` field.
2. `index.ts`.
3. `index.html`.

Example `index.json`:

```json
{
  "start": "src/main.ts"
}
```

The `start` path must be relative and must point to an existing file inside the served `code/` folder.

## Development

The default UI lives in:

```text
src-tauri/assets/
```

Install and build the UI assets from that folder:

```bash
cd src-tauri/assets
npm install
npm run build
```

Run or build the Tauri application from `src-tauri`:

```bash
cd ../
cargo tauri dev
cargo tauri build
```

The UI depends on the published package:

```json
{
  "dependencies": {
    "tauri-kargo-tools": "^0.3.5"
  }
}
```

The local `tauriKargoTools` repository is the source project for that package. It contains:

- the declarative UI runtime (`src/vue.ts`, `src/vue-builder.ts`, `src/vue-model.ts`);
- UI builders and models (`src/builder/*`, `src/model/*`);
- the typed HTTP client (`src/api.ts`);
- shared API types (`src/types.ts`);
- test helpers and sample components.

## API Overview

The application exposes a local JSON API under `/api`.

### Configuration

- `POST /api/useConfig` changes the served `code` and `executable` roots.
- `POST /api/useConfig` can also set `routes` for local folder routing or HTTP/HTTPS proxying.
- `POST /api/get-config` returns the active roots, routes, and file directory.

### Files And Directories

- `POST /api/current-directory` sets the base directory for file operations.
- `GET /api/current-directory` returns the current file base directory.
- `POST /api/file/{file}` reads or writes a file relative to the current directory.
- `DELETE /api/file/{file}` deletes a file relative to the current directory.
- `POST /api/directory/create` creates a directory.
- `POST /api/explorer` describes a file or lists a directory.
- `POST /api/unzip` extracts an archive.

### TypeScript Tools

- `POST /api/typescript/transpile` transpiles TypeScript source.
- `POST /api/typescript/ast` parses a TypeScript file and returns a simplified AST.

### Processes

- `POST /api/run` starts an executable from the executable root.
- `POST /api/run/status` returns the status and capped logs for one process.
- `GET|POST /api/allRunStatus` returns all tracked process statuses.
- `POST /api/run/stop` stops one process.
- `POST /api/run/stopAll` stops every spawned process.

### Servers

- `POST /api/newServer` starts an isolated child server for another `code` and `executable` pair.
- `POST /api/newServer` also accepts `routes` for that child server.
- `POST /api/stop` stops a child server by port, or the current child server when applicable.

### Packaging

- `POST /api/embed` creates a new executable containing the selected `code` and `executable` folders.

Example:

```bash
curl -X POST http://127.0.0.1:8080/api/embed \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"C:/apps/MyApp/code\",\"executable\":\"C:/apps/MyApp/executable\",\"output\":\"C:/apps/MyApp/MyApp.exe\"}"
```

## Using The API Client

`tauri-kargo-tools` provides a small TypeScript client:

```ts
import { createClient } from "tauri-kargo-tools/api";

const client = createClient();

const config = await client.getConfig();
await client.useConfig({
  code: "C:/path/to/code",
  executable: "C:/path/to/executable",
  routes: {
    "/assets": "C:/path/to/shared-assets",
    "/remote-api": "https://example.com/api"
  }
});

const run = await client.run({
  executableName: "my-tool.exe",
  arguments: ["--help"]
});

const status = await client.runStatus({ id: run.id! });
```

## Security Notes

- The server binds to `127.0.0.1`.
- File paths are checked to reject absolute paths and parent-directory traversal where relative paths are expected.
- Process logs are capped in memory.
- Spawned child processes are stopped when the main window exits.
- Child servers are tracked and can be stopped through the API.

TauriKargo is intended for trusted local desktop workflows. Review the exposed API surface before distributing a packaged app to end users.

## License

MIT
