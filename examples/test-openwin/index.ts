document.getElementById("btnOpen")?.addEventListener("click",async () => {
    const w = window.open("https://www.google.com", "AA")
    const body= w?.document.body
    console.log(body)
    if (body) {
      //  body.textContent ='Helllo'
    }
    console.log(w)
    const i = setInterval( ()=> {
        if (w?.closed) {
            console.log("close")
            clearInterval(i)
        }
    },500)

 



})
document.getElementById("btnRun")?.addEventListener("click",async () => {
  
    await fetch("/api/window/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "AA", scriptPath: "script.js"  ,url:"https://www.google.com"})
    });
 



})