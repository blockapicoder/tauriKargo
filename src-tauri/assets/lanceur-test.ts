import { createClient, TauriKargoClient } from "./node_modules/tauri-kargo-tools/src/api"
import { defineVue } from "./node_modules/tauri-kargo-tools/src/vue"
import { Assert, GetConfigResp, Log, TestEvent, UpdateSnapshot } from "./node_modules/tauri-kargo-tools/src/types"
import { Lanceur } from "./launcher"

interface TestEventForFile {
    file: string
    event: TestEvent | UpdateSnapshot
}
export class SnapshotAction {
    selected!: boolean
    name!: string
    constructor() {

    }

}
defineVue(SnapshotAction, (vue) => {
    vue.flow({ orientation: "row" ,gap:5}, () => {
        vue.input({ name: "selected", inputType: "checkbox" ,width:"10%"})
        vue.label("name",{width:"90%"})
    })
})
export class GestionSnapshot {
    parent!: LanceurTest
    snapshots: SnapshotAction[] = []


    tousSelectionne() {
        for (const sa of this.snapshots) {
            sa.selected = true
        }

    }
    aucuneSelection() {
        for (const sa of this.snapshots) {
            sa.selected = false
        }

    }
    async valider() {
        const client = this.parent.client
        const currentDirectory = await client.getCurrentDirectory()
        await client.setCurrentDirectory({ path: this.parent.repertoireProjet })
        for (const i of this.snapshots) {
            if (i.selected) {
                await client.deleteFile(`test/snapshots/${i.name}`)
            }
        }
        await client.setCurrentDirectory({ path: currentDirectory.current })
        this.parent.gestionSnapshot = undefined

    }
    annuler() {
        this.parent.gestionSnapshot = undefined

    }
    displaySnapshot(s: string) {
        return s
    }
    selectionner() {

    }
    async init(div: HTMLDivElement) {
        const client = this.parent.client
        try {
            const r = await client.explorer({ path: `${this.parent.repertoireProjet}/test/snapshots`, type: "array" })

            if (r.type === "directory") {
                this.snapshots = r.content.map((e) => {
                    const sa = new SnapshotAction()
                    sa.name = e.name
                    sa.selected = false
                    return sa
                })
            }
        } catch (e) {
            const currentDirectory = await client.getCurrentDirectory()
            await client.setCurrentDirectory({ path: this.parent.repertoireProjet })
            await client.createDirectory('test/snapshots')
            await client.setCurrentDirectory({ path: currentDirectory.current })

        }
    }

}
defineVue(GestionSnapshot, (vue) => {
    vue.flow({ orientation: "column", gap: 10 }, () => {
        vue.flow({ orientation: "row", gap: 10 }, () => {
            vue.staticButton({ action: "aucuneSelection", label: "Aucune sélection", width: "50%" })
            vue.staticButton({ action: "tousSelectionne", label: "Tous sélectioner", width: "50%" })
        })
        vue.listOfVue({ list:"snapshots"})
        vue.flow({ orientation: "row", gap: 10 }, () => {
            vue.staticButton({ action: "annuler", label: "Annuler", width: "50%" })
            vue.staticButton({ action: "valider", label: "Valider", width: "50%" })
        })

    })
}, { init: "init" })
export class LanceurTest {

    tests: string[] = []
    repertoireProjet!: string
    client!: TauriKargoClient
    testSelection: number[] = []
    testResultSelection: number[] = []
    config!: GetConfigResp
    workers: Worker[] = []
    lanceur!: Lanceur
    testResults: TestEventForFile[] = []
    mapTestResults: { [file: string]: (TestEvent | UpdateSnapshot)[] } = {}
    afficherInformation = true
    afficherPassed = true
    afficherTerminate = true
    afficherFailed = true
    executionUnitaire = false
    gestionSnapshot?: GestionSnapshot

    constructor() {
        this.client = createClient()
    }
    async initialiserTests(div: HTMLDivElement) {
        await this.chargerTests()
        this.config = await this.client.getConfig()

    }
    ouvrirGestionSnapshot() {
   
        this.gestionSnapshot = new GestionSnapshot()
        this.gestionSnapshot.parent = this
        this.gestionSnapshot.snapshots =  []
    }
    async chargerTests() {
        const r = await this.client.explorer({ path: `${this.repertoireProjet}/test`, type: "array" })
        if (r.type === "directory") {
            this.tests = r.content.filter((e) => !e.path.startsWith(`${this.repertoireProjet}\\test\\snapshots\\`)).map((e) => e.name)
        }

    }
    initTestResults() {
        const ls: TestEventForFile[] = []
        for (const file of this.tests) {
            const lsTestEvent = this.mapTestResults[file] ?? []
            for (const e of lsTestEvent) {
                if (e.type === "log" && this.afficherInformation) {
                    ls.push({ event: e, file: file })
                }
                if (e.type === "assert" && e.value && this.afficherPassed) {
                    ls.push({ event: e, file: file })
                }
                if (e.type === "assert" && !e.value && this.afficherFailed) {
                    ls.push({ event: e, file: file })
                }
                if (e.type === "terminate" && this.afficherTerminate) {
                    ls.push({ event: e, file: file })
                }
                if (e.type === "snapshot" && this.afficherInformation) {
                    ls.push({ event: e, file: file })
                }
            }
        }
        this.testResults = ls
    }

    stopWorkers() {
        for (const w of this.workers) {
            w.terminate()

        }
        this.workers = []
    }
    async run() {

        this.testResults = []
        this.mapTestResults = {}
        if (this.testSelection.length === 0) {
            return;
        }
        this.stopWorkers()
        await this.client.useConfig({ code: this.repertoireProjet, executable: this.config.executable??'.' })
        const file = this.tests[this.testSelection[0]]
        this.mapTestResults[file] = []
        const worker = new Worker(`/test/${this.tests[this.testSelection[0]]}`, { type: "module" })
        this.workers.push(worker)
        worker.addEventListener("message", async (m) => {
            this.mapTestResults[file].push(m.data)
            if (m.data.type === "snapshot") {
                const us: UpdateSnapshot = m.data
                this.updateSnapshot(us)
            }
            if (m.data.type === "terminate") {
                this.stopWorkers()
                await this.client.useConfig(this.config)


            }

            if (m.data.type === "assert") {
                const assert: Assert = m.data

                if (!assert.value) {
                    this.stopWorkers()
                }

            }
            this.initTestResults()

        })

    }
    async updateSnapshot(us: UpdateSnapshot) {
        const client = this.client
        const currentDirectory = await client.getCurrentDirectory()
        await client.setCurrentDirectory({ path: this.repertoireProjet })
        await client.createDirectory('test/snapshots')
        await this.client.writeFileText(`test/snapshots/${us.name}.json`, JSON.stringify(us.value))
        await client.setCurrentDirectory({ path: currentDirectory.current })

    }
    async runAll() {

        this.testResults = []
        this.mapTestResults = {}

        this.stopWorkers()
        await this.client.useConfig({ code: this.repertoireProjet, executable: this.config.executable??'.' })
        for (const file of this.tests) {
            this.mapTestResults[file] = []
            const worker = new Worker(`/test/${file}`, { type: "module" })
            this.workers.push(worker)
            worker.addEventListener("message", async (m) => {
                this.mapTestResults[file].push(m.data)
                if (m.data.type === "snapshot") {
                    const us: UpdateSnapshot = m.data
                    this.updateSnapshot(us)
                }
                if (m.data.type === "terminate") {
                    worker.terminate()
                    this.workers = this.workers.filter((w) => w !== worker)
                    if (this.workers.length === 0) {
                        await this.client.useConfig(this.config)
                    }
                }

                if (m.data.type === "assert") {
                    const assert: Assert = m.data

                    if (!assert.value) {
                        worker.terminate()
                        this.workers = this.workers.filter((w) => w !== worker)
                        if (this.workers.length === 0) {
                            await this.client.useConfig(this.config)
                        }
                    }

                }
                this.initTestResults()

            })
        }

    }
    displayTest(t: string) {
        return t
    }
    selectionneTest() {
        this.executionUnitaire = this.testSelection.length > 0

    }
    selectionneTestResult() {

    }
    displayTestEvent(te: TestEvent | UpdateSnapshot) {
        if (te.type === "terminate") {
            return `terminate ✅`
        }
        if (te.type === "log") {
            if (Array.isArray(te.message)) {
                return `${te.message.join(" ")} ℹ️`
            }
            return `${te.message} ℹ️`
        }
        if (te.type === "assert") {
            if (te.value) {
                return `${te.message} passed ✅`
            }
            return `${te.message} ❌ failed`
        }
        if (te.type === "snapshot") {
            return `${te.name} update snapshot ℹ️`
        }

    }
    displayTestEventForFile(t: TestEventForFile) {
        return `${t.file} ${this.displayTestEvent(t.event)}`
    }
    recupererLanceur() {
        this.client.useConfig(this.config)
        return this.lanceur

    }
    modifierFiltre() {
        this.initTestResults()

    }

}
defineVue(LanceurTest, (vue) => {
    vue.flow({ orientation: "column", gap: 5 }, () => {
        vue.flow({ orientation: "row", gap: 10, align: "center", justify: "center" }, () => {
            vue.staticButton({ action: "run", label: "Test", enable: "executionUnitaire" })
            vue.staticButton({ action: "runAll", label: "Test tous" })
            vue.staticButton({ action: "chargerTests", label: "Recharger tests disponnible" })
            vue.dialog({ label: "Snapshots", name: "gestionSnapshot", action: "ouvrirGestionSnapshot", width:400 })
            vue.staticBootVue({ factory: "recupererLanceur", label: "Lanceur" })
            vue.staticLabel("afficher passed ✅")
            vue.input({ inputType: "checkbox", update: "modifierFiltre", name: "afficherPassed" })
            vue.staticLabel("afficher ℹ️")
            vue.input({ inputType: "checkbox", update: "modifierFiltre", name: "afficherInformation" })
            vue.staticLabel("afficher ❌")
            vue.input({ inputType: "checkbox", update: "modifierFiltre", name: "afficherFailed" })
            vue.staticLabel("afficher terminate ✅")
            vue.input({ inputType: "checkbox", update: "modifierFiltre", name: "afficherTerminate" })
        })

        vue.flow({ orientation: "row", gap: 5 }, () => {
            vue.select({ list: "tests", displayMethod: "displayTest", selection: "testSelection", update: "selectionneTest", width: 200 })
            vue.select({ list: "testResults", displayMethod: "displayTestEventForFile", update: "selectionneTestResult", selection: "testResultSelection" })
        })


    })

}, { init: "initialiserTests" })