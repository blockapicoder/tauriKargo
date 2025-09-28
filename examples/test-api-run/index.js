document.body.append("hello");

(async () => {

  const resServe = await fetch("/api/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      executableName: "deno",
      arguments: " run test.ts ",
      detatch: true,
    }),
  });
  const r = await resServe.json();
  document.body.append(JSON.stringify(r));
})();
