/* Exemple Worker TypeScript */

export {};

function log(...args:any[]) {
  self.postMessage({ type:'log', data: args.map(x => typeof x==='object' ? JSON.stringify(x) : String(x)) });
}

function f(x) {
  return (-9.81/(2*21*21))*x*x+3.5

}

log("👋 Worker TS démarré", f(1));
