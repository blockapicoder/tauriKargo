import { Explorateur } from "./explorer"
import { Lanceur } from "./launcher"
import { boot } from "./node_modules/tauri-kargo-tools/src/vue"
import * as tools from "./tools"
import { createClient, TauriKargoClient } from "./node_modules/tauri-kargo-tools/src/api"

(async () => {
    const client = createClient()
    const config = await client.getConfig()
    const listener = async () => {
        /*if (this.worker) {
            this.worker.terminate()
        }*/
        await client.useConfig(config)
    }
    window.addEventListener("beforeunload", listener);
    const applications = await tools.recupererApplications()
    if (Object.keys(applications.applications).length) {
        const lanceur: Lanceur = new Lanceur()
        lanceur.applications = applications
        boot(lanceur)
    } else {
        boot(new Explorateur())
    }
})()
