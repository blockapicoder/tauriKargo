
// ask-ollama.ts
// Run with: node --loader ts-node/esm ask-ollama.ts  (ou transpile avec tsc puis node)

// Si vous êtes sur Node <18, installez un polyfill fetch (node-fetch) et ajustez l'import.

type GenerateRequest = {
    model: string;
    prompt?: string;
    stream?: boolean;
    format?: string;
    // options?: Record<string, any>; // décommentez si vous voulez personnaliser
};

async function askOllama(prompt: string, model = "gemma3:4b") {
    const url = "http://localhost:11434/api/generate";

    const body: GenerateRequest = {
        model,
        prompt,
        stream: false, // réponse en une seule fois (facile à parser)
        // format: "json" // optionnel — si vous attendez du JSON strict de la part du modèle
    };

    try {
        const res = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                // Pas d'auth par défaut pour une instance locale d'Ollama
            },
            body: JSON.stringify(body),
        });

        if (!res.ok) {
            const text = await res.text();
            throw new Error(`Ollama HTTP ${res.status}: ${text}`);
        }

        // La doc montre que la réponse non-streaming est un objet JSON contenant
        // au moins les champs comme "model", "created_at", "response", "done", etc.
        // On essaye donc d'extraire json.response.
        const json = await res.json();

        // Robustesse : différents endpoints/librairies renvoient parfois un champ différent.
        const answer =
            (json && (json.response ?? json.result ?? json.output ?? json.message ?? json.text)) ??
            JSON.stringify(json);

        console.log("== Réponse d'Ollama ==");
        console.log(answer);
        return answer;
    } catch (err) {
        console.error("Erreur en appelant Ollama :", err);
        throw err;
    }
}
const question = "creer moi un unique personnage de film fantastique en une seul ligne , repond en français et repond uniquement la description de se personnage , pas de baratin"
let personnages: string[] = []
async function load() {
    try {
        const r = await fetch("/api/file/personnages.json", {
            method: "POST"
            , cache: "no-cache"
        })
        personnages = await r.json()
        for (const p of personnages) {
            ajouterPersonnage(p)
        }
    } catch (e) {
        console.log("pas de fichier")

    }
}
function ajouterPersonnage(descriptionPerso: string) {
    const li = document.createElement("li");
    li.innerHTML = `
      <span>${descriptionPerso}</span>
    `;
    const removeButton = document.createElement("button")
    removeButton.setAttribute("class", "delete-btn")
    removeButton.addEventListener("click", (btn) => {
        personnages = personnages.filter((p) => p !== descriptionPerso)
        removeButton.parentElement!.remove();
    })
    li.appendChild(removeButton)

    
    document.getElementById("list")!.appendChild(li);
}
function addItem() {


    const bouton = document.getElementById("addItem") as HTMLButtonElement;
    // Désactiver
    bouton.disabled = true;
    document.getElementById("addItem")!.setAttribute("enable", "false")
    askOllama(question).then((rep) => {
        const descriptionPerso = rep
        ajouterPersonnage(descriptionPerso)
        personnages.push(descriptionPerso)
        bouton.disabled = false;
    })


}
document.getElementById("addItem")!.addEventListener("click", addItem)
async function save() {
    await fetch("/api/file/personnages.json", {
        method: "POST",
        body: JSON.stringify(personnages, null, 2)
    })


}
document.getElementById("save")!.addEventListener("click", save)
load().then(() => {
    console.log("load")
})
/*
const question = "creer moi un unique personnage de film fantastique en une seul ligne , repond en français et repond uniquement la description de se personnage , pas de baratin"
document.body.append(question)
document.body.appendChild(document.createElement("br"))
askOllama(question).then(async (rep) => {
    document.body.append(JSON.stringify(rep, null, 2))
})
*/