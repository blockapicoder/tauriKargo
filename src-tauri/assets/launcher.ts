import * as tools from './tools'
import { boot, defineVue } from "./node_modules/tauri-kargo-tools/src/vue"
import { Explorateur } from './explorer';

interface Execution {
    window: Window
    port: number
    name: string
}
interface Executions {
    lanceur?: Lanceur
    executions: Execution[]
    messages: string
}
const executions: Executions = { executions: [], messages: "" }

const timer = setInterval(async () => {
    const newExecutions: Execution[] = []
    for (const e of executions.executions) {
        if (e.window.closed) {
            executions.messages += `\n🛑 WebView ${e.name}-${e.port} fermée — arrêt du serveur...`;
            try {
                await tools.tauriKargoClient.stopServer({ port: e.port })
                executions.messages += `\n✅ Serveur ${e.name}-${e.port}  arrêté.`;
            } catch (e: any) {
                executions.messages += `\n❌ Échec arrêt ${e.name}-${e.port} : ${(e.message || e)}`;
            }
        } else {
            newExecutions.push(e)
        }

    }
    executions.executions = newExecutions
    if (executions.lanceur) {
        executions.lanceur.messages = executions.messages
    }
}, 600);
export class ModalPackager {
    lanceur!:Lanceur;
    nomExecutable!: string 
    async valider() {
        this.lanceur.packager(this.nomExecutable)
         this.lanceur.modelPackager = undefined

    }
    annuler() {
        this.lanceur.modelPackager = undefined

    }

}
defineVue(ModalPackager,{
    kind:"flow",
    orientation:"column",
    gap:25,
    children:[
        {kind:'input', name:"nomExecutable"},
        {kind:"flow" , orientation:"row",gap:10,children:[
            {kind:"staticButton",action:"annuler",label:"Annuler",width:"50%"},
            {kind:"staticButton",action:"valider",label:"Valider",width:"50%"}
        ]}
    ]
})
export class Lanceur {
    applications!: tools.Applications
    names!: string[]
    selections: number[] = []
    activerAction: boolean = false
    messages: string = ""
    executablePath: string = ""
    packagerOutputPath: string = ""
    explorateur?: Explorateur
    modelPackager?:ModalPackager
    constructor() {

    }
    async init(div: HTMLDivElement) {
        if (!this.applications) {
            this.applications = await tools.recupererApplications()
        }
        this.names = Object.keys(this.applications.applications)
        if (this.explorateur) {
            if (this.explorateur.typeAction === "setExecutePath") {
                this.applications.executable = this.explorateur.racine
            }
            if (this.explorateur.typeAction === "setPackagerOutput") {
                this.applications.packagerOutput = this.explorateur.racine
            }
            await tools.enregistrerApplications(this.applications)
            this.explorateur = undefined
        }
        executions.lanceur = this
        this.messages = executions.messages
        this.executablePath = `Chemin des executables ${this.applications.executable}`
        this.packagerOutputPath = `Chemin du packaging ${this.applications.packagerOutput}`

    }
    afficherName(name: string) {
        return name
    }
    explorerExecutablePath() {
        const r = new Explorateur()
        r.typeAction = "setExecutePath"
        return r
    }
    explorerPackagerOutputPath() {
        const r = new Explorateur()
        r.typeAction = "setPackagerOutput"
        return r

    }
    selectionnerName() {
        this.activerAction = (this.selections.length > 0)

    }
    explorer() {
        return new Explorateur()
    }
    creerModalPackager() {
        const name = this.names[this.selections[0]]
        this.modelPackager = new ModalPackager()
        this.modelPackager.nomExecutable = `${name}.exe`
        this.modelPackager.lanceur = this
        return this.modelPackager
    }
    async packager(nomExecutable:string ) {
        const name = this.names[this.selections[0]]
        executions.messages += `\n✅ Packaging lancé sur ${name} `;
        try {
            const r = await tools.tauriKargoClient.embed({
                code: this.applications.applications[name].code,
                executable: this.applications.executable,
                output: `${this.applications.packagerOutput}\\${nomExecutable}`
            })
            if (r.ok) {
                executions.messages += `\n✅ Packaging ok sur ${name} executable ${nomExecutable}`;
            } else {
                executions.messages += `\n❌ Packaging ko sur ${name} : ${r.message}`;
            }
        } catch (e: any) {
            executions.messages += `\n❌ Packaging ko sur ${name} : ${e.message}`;
        }



    }
    async supprimer() {
        const name = this.names[this.selections[0]]
        delete this.applications.applications[name]
        this.names = [...Object.keys(this.applications.applications)]
        this.selections = []
        this.activerAction = false
        await tools.enregistrerApplications(this.applications)

    }
    async executer() {
        const name = this.names[this.selections[0]]
        const newServeur = await tools.tauriKargoClient.newServer({
            code: this.applications.applications[name].code,
            executable: this.applications.executable
        })
        if (newServeur.ok) {
            const url = `http://127.0.0.1:${newServeur.port}/`;
            const w = window.open(url, name);
            if (w) {
                const execution: Execution = {
                    name: name,
                    port: newServeur.port!,
                    window: w

                }
                executions.messages += `\n✅ Serveur lancé sur ${name} ${url}\n🪟 Ouverture (target = ${execution.port})...`;

                executions.executions.push(execution)
                this.messages = executions.messages


            }
        }
    }



}
defineVue(Lanceur, (vue) => {
    vue.flow({ orientation: "column", gap: 10 }, () => {
        vue.flow({ orientation: "row", gap: 10 }, () => {
            vue.select({ mode: "dropdown", list: "names", displayMethod: "afficherName", selection: "selections", update: "selectionnerName", width: "80%" })
            vue.staticBootVue({ factory: "explorer", label: "Explorer" })
            vue.staticButton({ action: "executer", label: "Executer", enable: "activerAction" })
            vue.staticButton({ action: "supprimer", label: "Supprimer", enable: "activerAction" })
            vue.dialog({ name:"modelPackager",action:"creerModalPackager", label: "Packager", enable: "activerAction" , width:300,height:150})
        })
        vue.flow({ orientation: "row", gap: 10 }, () => {
            vue.label("executablePath", { width: "80%" })
            vue.staticBootVue({ factory: "explorerExecutablePath", label: "Explorer", width: "20%" })

        })
        vue.flow({ orientation: "row", gap: 10 }, () => {
            vue.label("packagerOutputPath", { width: "80%" })
            vue.staticBootVue({ factory: "explorerPackagerOutputPath", label: "Explorer", width: "20%" })

        })
        vue.label("messages")

    })
}, {
    init: "init"
})