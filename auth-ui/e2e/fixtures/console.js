// issuer.spec.ts's console: an app on 127.0.0.1 signing users in at the
// e2e server's issuer, localhost (another origin, the same server).
const mod = await import("/__auth-ui/client.js")
const issuer = location.origin.replace("://127.0.0.1:", "://localhost:")
const client = mod.createIssuerClient({
  issuer,
  clientId: "e2e-console",
  redirectUri: "/console.html",
  resource: `${issuer}/__test/resource`,
  scope: "openid profile email e2e:read",
  postLogoutRedirectUri: "/signed-out.html",
})
window.issuer = client
window.callback = await client.completeSignIn().then(
  (r) => r,
  (e) => ({ error: e.error ?? String(e) })
)
if (window.callback?.kind !== "popup") {
  client.start()
  await client.ready()
}
document.getElementById("popup").onclick = () => {
  window.popupResult = client.signIn({ popup: true }).then(
    () => "ok",
    (e) => e.error ?? String(e)
  )
}
window.booted = true
