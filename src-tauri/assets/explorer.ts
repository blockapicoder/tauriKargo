import { boot, defineVue } from "./node_modules/tauri-kargo-tools/src/vue"
import * as tools from "./tools"
import { createClient, TauriKargoClient } from "./node_modules/tauri-kargo-tools/src/api"
import { Lanceur } from "./launcher";

class Noeud {
    nom!: string
    explorateur!: Explorateur
    constructor() {

    }
}
class Reperoire extends Noeud {


    explorer() {
        this.explorateur.explorer(this.nom)
    }
}
class ApplicationRepertoire extends Noeud {
    modal?: DialogueAjoutApplication
    applicationName!: string
    async ajouter() {
        this.modal = new DialogueAjoutApplication()
        this.modal.name = this.applicationName
        this.modal.path = this.nom
        this.modal.parent = this;
        try {

            this.modal.applications = await tools.recupererApplications()
            this.modal.autoriserValider = !this.modal.applications.applications[this.applicationName]
        } catch (e) {

        }

    }
}
class DialogueAjoutApplication {
    name: string = ""
    path!: string
    autoriserValider!: boolean
    parent!: ApplicationRepertoire
    applications?: tools.Applications
    async valider() {
        await tools.ajouterApplication(this.name, { code: this.path })
        this.parent.explorateur.activerLanceur = true
        this.parent.explorateur.noeuds = this.parent.explorateur.noeuds.filter((e) => e !== this.parent)
        this.parent.modal = undefined

    }
    annuler() {
        this.parent.modal = undefined
    }
    verifier() {
        if (this.applications) {
            this.autoriserValider = !this.applications.applications[this.name]
        }


    }

}
defineVue(DialogueAjoutApplication, {
    kind: 'flow',
    orientation: "column",
    gap: 10,


    children: [
        { kind: 'input', name: "name", update: "verifier", width: '100%' },
        {
            kind: "flow", orientation: "row", gap: 10, children: [
                { kind: "staticButton", label: "Valider", action: "valider", width: '50%', enable: "autoriserValider" },
                { kind: "staticButton", label: "Annuler", action: "valider", width: '50%' }
            ]
        }
    ]
})

defineVue(Reperoire, {
    kind: "flow",
    orientation: "row",
    gap: 10,
    children: [
        { kind: "label", name: "nom", width: '90%' },
        { kind: "staticButton", label: "Explorer", action: "explorer", width: '10%' }
    ]
})
defineVue(ApplicationRepertoire, {
    kind: "flow",
    orientation: "row",
    gap: 10,
    children: [
        { kind: "label", name: "nom", width: '90%' },
        { kind: "dialog", label: "Ajouter", name: "modal", width: '50%', action: "ajouter", buttonWidth: "10%" }
    ]
})
export class Explorateur {
    racine: string = "."
    parents: string[] = []
    noeuds: Noeud[] = []
    tauriKargoClient!: TauriKargoClient
    peutRemonter: boolean = false
    activerLanceur: boolean = true
    labelAction: string = "Lanceur"
    typeAction:"setExecutePath"|"setPackagerOutput"|"addApp" ="addApp"
    constructor() {
        this.tauriKargoClient = createClient();
        this.explorerRacine()

    }
    explorerRacine() {
        this.explorer(this.racine)
    }
    lanceur() {
      
        const r = new Lanceur()
        if (this.typeAction !=="addApp") {
            r.explorateur = this
        }
        return r
    }
    async explorer(chemin: string) {
        const path = chemin == "." ? undefined : chemin
        const applications = await tools.recupererApplications()
        this.activerLanceur = Object.keys(applications.applications).length > 0

        const r = await this.tauriKargoClient.explorer({ path: path })
        const noeuds: Noeud[] = []
        this.racine = chemin
        if (r.type === "directory") {
            if (r.parent) {
                this.parents.push(r.parent)
                this.peutRemonter = true
            }

            for (const e of r.content) {
                if (e.type === "directory") {
                    try {
                        const children = await this.tauriKargoClient.explorer({ path: e.path })
                        if (children.type === "directory") {
                            if (this.typeAction==="addApp" && children.content.some((e) => ['index.ts', 'index.html', 'index.js'].includes(e.name))) {
                                if (Object.values(applications.applications).every((a) => a.code !== e.path)) {
                                    const rep: ApplicationRepertoire = new ApplicationRepertoire()
                                    rep.nom = e.path
                                    rep.applicationName = e.name
                                    rep.explorateur = this
                                    noeuds.push(rep)
                                }
                            } else {
                                const rep: Reperoire = new Reperoire()
                                rep.nom = e.path
                                rep.explorateur = this
                                noeuds.push(rep)
                            }
                        }
                    } catch (e) {

                    }

                }

            }
        }
        this.noeuds = noeuds


    }
    remonter() {
        const e = this.parents.pop()
        if (e) {
            this.explorer(e)
        }
        this.peutRemonter = this.parents.length > 0





    }
}
defineVue(Explorateur, {
    kind: 'flow',
    orientation: "column",
    gap: 10,
    height: '100vh',

    children: [
        {
            kind: 'flow',
            orientation: "row",
            gap: 10,

            children: [{ kind: "input", name: "racine", update: "explorerRacine", width: "50%" },
            { kind: "staticButton", label: "Remonter", enable: "peutRemonter", action: "remonter", width: "25%" },
            { kind: "bootVue", label: "labelAction", enable: "activerLanceur", factory: "lanceur", width: "25%" }]
        }
        ,
        {
            kind: "listOfVue",
            list: "noeuds",
            gap: 10,
            orientation: "column",
            width: '100%',

            style: {
                overflow: "auto"
            }
        }
    ]
})
