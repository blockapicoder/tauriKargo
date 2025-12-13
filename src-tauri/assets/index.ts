import { Explorateur } from "./explorer"
import { Lanceur } from "./launcher"
import { boot } from "./node_modules/tauri-kargo-tools/src/vue"
import * as tools from "./tools"


const applications = await tools.recupererApplications()
if (Object.keys(applications.applications).length) {
    const lanceur: Lanceur = new Lanceur()
    lanceur.applications = applications
    boot(lanceur)
} else {
    boot(new Explorateur())
}
