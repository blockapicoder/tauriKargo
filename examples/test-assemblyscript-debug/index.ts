// index.ts
import asc from "assemblyscript/asc";

const btn = document.getElementById("build") as HTMLButtonElement;
const logEl = document.getElementById("log") as HTMLPreElement;
const srcEl = document.getElementById("as-src") as HTMLTextAreaElement;

const td = new TextDecoder();
const toStr = (d: unknown) => (typeof d === "string" ? d : td.decode(d as Uint8Array));
const log = (s: string) => { logEl.textContent += s + "\n"; };

function asUint8(v: string | Uint8Array | undefined): Uint8Array | undefined {
  if (v == null) return undefined;
  return typeof v === "string" ? new TextEncoder().encode(v) : v;
}
function asString(v: string | Uint8Array | undefined): string | undefined {
  if (v == null) return undefined;
  return typeof v === "string" ? v : td.decode(v);
}

// Charge un WebAssembly binaire depuis une URL, avec cache-bust optionnel.
export async function loadWasm(
  url: string,
  imports: WebAssembly.Imports = {},
  opts: { cacheBust?: boolean } = {}
): Promise<{ instance: WebAssembly.Instance; module: WebAssembly.Module }> {
  const { cacheBust = true } = opts;
  const bust = cacheBust ? (url.includes("?") ? "&" : "?") + "v=" + Date.now() : "";
  const finalUrl = url + bust;

  const resp = await fetch(finalUrl);
  if (!resp.ok) throw new Error(`Échec HTTP ${resp.status} ${resp.statusText} pour ${finalUrl}`);

  // Essaye instantiateStreaming si dispo + bon Content-Type
  try {
    if ("instantiateStreaming" in WebAssembly) {
      const { instance, module } = await WebAssembly.instantiateStreaming(resp.clone(), imports);
      return { instance, module };
    }
  } catch (_) {
    // Souvent dû à un mauvais MIME (pas application/wasm) → fallback ArrayBuffer
  }

  const bytes = await resp.arrayBuffer();
  const { instance, module } = await WebAssembly.instantiate(bytes, imports);
  return { instance, module };
}

// Optionnel : petit helper pour uploader un fichier et logguer l’erreur sans casser le flux
async function tryUpload(path: string, contentType: string, body: BodyInit) {
  try {
    const r = await fetch(path, { method: "POST", headers: { "Content-Type": contentType }, body });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    log(`💾 Écriture ${path} OK`);
  } catch (e: any) {
    log(`⚠️ Échec écriture ${path}: ${e?.message ?? e}`);
  }
}

btn.addEventListener("click", async () => {
  try {
    logEl.textContent = "⏳ Compilation AssemblyScript...\n";
    const source = srcEl.value;

    const outputs: Record<string, string | Uint8Array<ArrayBufferLike>> = Object.create(null);

    const { error, stdout, stderr } = await asc.main(
      [
        "main.ts",
        "--outFile", "module.wasm",
        "--debug",
        "--sourceMap",        // produit module.wasm.map
        "--bindings", "esm",  // produit module.js (bindings ESM) — pas nécessaire ici mais utile
        // "--noEmit",         // si tu veux juste valider sans générer les fichiers
        // "--stats",
      ],
      {
        readFile: (name) => (name === "main.ts" ? source : null),
        writeFile: (name, contents) => { outputs[name] = contents; },
        listFiles: () => [],

        // Affiche TOUT ce que le compilateur écrit sur stdout/stderr
        stdout: { write: (d) => log(toStr(d)) },
        stderr: { write: (d) => log(toStr(d)) },

        // Diagnostics jolis (fichier:ligne:colonne + message)
        reportDiagnostic: (diag) => {
          const file = (diag.range && ((diag.range as any).source || (diag.range as any).file)) || "main.ts";
          const line = diag.range?.start != null ? diag.range.end + 1 : "?";
          const col = diag.range?.start != null ? diag.range.end + 1 : "?";
          log(`🔎 ${file}:${line}:${col} ${diag.message}`);
        },
      }
    );

    // En plus, logguer l’agrégat stdout/stderr retourné par asc.main
    if (stdout && typeof (stdout as any).toString === "function") log((stdout as any).toString());
    if (stderr && typeof (stderr as any).toString === "function") log((stderr as any).toString());

    if (error) {
      log("❌ Compilation échouée: " + error.message);
      return;
    }

    // Récup artefacts
    const wasm = outputs["module.wasm"];
    const map = outputs["module.wasm.map"];
    const js = outputs["module.js"];       // bindings ESM (non utilisés ici)
    // const dts  = outputs["module.d.ts"];   // selon version

    if (!wasm || !map) {
      log("⚠️ Build OK, mais fichier manquant (wasm/map).");
      return;
    }

    // Upload (optionnel) — on continue même si ça échoue
    log("💾 Écriture des artefacts…");
    const rep = await fetch("/api/get-config", { method: 'POST' })
    const value = await rep.json()
    await fetch("/api/current-directory", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: value.code })
    })
    await tryUpload("/api/file/build/module.wasm", "application/octet-stream", asUint8(wasm)!);
    await tryUpload("/api/file/build/module.wasm.map", "application/json", asString(map)!);

    // --- Instanciation manuelle du .wasm avec imports.env requis ---
    const asImports: WebAssembly.Imports = {
      env: {
        // Signatures minimales utilisées par AS en debug
        abort: (_msg: number, _file: number, line: number, col: number) => {
          log(`❗ AssemblyScript abort @ ${line}:${col}`);
        },
        trace: (_msg: number, n: number, a0?: number, a1?: number, a2?: number, a3?: number, a4?: number) => {
          const args = [a0, a1, a2, a3, a4].filter(v => v !== undefined).join(", ");
          log(`🧵 trace n=${n} args=${args}`);
        },
      },
    };

    log("🔧 Chargement / instanciation du WebAssembly…");
    const { instance } = await loadWasm("/build/module.wasm", asImports);
    const ex = instance.exports as any;

    // Appels d’exemple à tes exports
    if (typeof ex.main === "function") {
      log("main() = " + ex.main());
    }
    if (typeof ex.add === "function") {
      log("add(2, 40) = " + ex.add(2, 40));
    }

    log("✅ Terminé.");

  } catch (e: any) {
    log("❌ Erreur: " + (e?.message ?? e));
  }
});
