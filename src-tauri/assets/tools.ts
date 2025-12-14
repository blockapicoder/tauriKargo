import { createClient, TauriKargoClient } from "./node_modules/tauri-kargo-tools/src/api"

export interface Application {
    code: string
}
export interface Applications {
    applications: { [name: string]: Application }
    executable: string
    packagerOutput: string
}
export const tauriKargoClient: TauriKargoClient = createClient()
export const APPLICATIONS_FILE = "applications.json"

export async function ajouterApplication(name: string, application: Application) {
    const applications = await recupererApplications()
    applications.applications[name] = application
    await enregistrerApplications(applications)
}

export async function enregistrerApplications(applications: Applications) {
    await tauriKargoClient.writeFileText(APPLICATIONS_FILE, JSON.stringify(applications, null, 2))
}
export async function recupererApplications() {
    let applications: Applications = { applications: {}, executable: ".", packagerOutput: "." }
    try {
        const src = await tauriKargoClient.readFileText(APPLICATIONS_FILE)
        applications = JSON.parse(src)

    } catch (e) {

    }
    return applications
}


export async function stopServer(port: number) {

    const r = await tauriKargoClient.stopServer({ port: port })

    if (!r.ok) {
        throw new Error(r.message || "Échec arrêt");
    }
    return r


}
