/* Exemple Worker TypeScript */
declare const self: DedicatedWorkerGlobalScope;
export {};

function log(...args:any[]) {
  self.postMessage({ type:'log', data: args.map(x => typeof x==='object' ? JSON.stringify(x) : String(x)) });
}

log("👋 Worker TS démarré", new Date().toISOString());

self.onmessage = (e: MessageEvent) => {
  log("Message reçu:", e.data);
  if (e.data === "ping") self.postMessage("pong");
};

let n = 0;
setInterval(() => self.postMessage({ tick: ++n, at: Date.now() }), 1000);
