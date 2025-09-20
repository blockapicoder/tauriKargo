
import * as asc from "assemblyscript/asc";                // ← le compilateur AssemblyScript côté web
import binaryen from "binaryen";           // backend utilisé par le compilateur
import Long from "long";                   // dépendance transitve requise par l’outil


const log = (...x: any[]) => (document.getElementById('log')!.textContent += x.join(' ') + "\n");

document.getElementById('build')!.onclick = async () => {
    try {
        // compileString => .wasm en mémoire
        const name: string = "index.ts"
        const elt  = document.getElementById('as-src')! as HTMLTextAreaElement
        const src = elt.value
        const result = await asc.compileString(
            { [name]: src},
            { optimizeLevel: 3, shrinkLevel: 1, noAssert: true }
        ); // API de compilation programmatique [5](https://deepwiki.com/AssemblyScript/assemblyscript/4.1-compiler-api)

        if (!result.binary) throw new Error("Compilation échouée");
        const { instance } = await WebAssembly.instantiate(result.binary, {});
        const value: any = instance.exports
        log("add(40,2) =>", value.main());
    } catch (_e) {
        const e: any = _e as any
        log("Erreur:", e.message || e);
    }
};