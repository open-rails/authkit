package httpapi

import "net/http"

// handlePasskeyWindowGET serves the window that creates a passkey where a
// cross-origin iframe cannot (Safari never allows it, WebAuthn L3 §5.1.3).
// The signed-in iframe on the same origin opens it, begins the ceremony with
// its own session and posts the options here; this top-level page calls
// navigator.credentials.create on a click and posts the credential back for
// the iframe to finish. It trusts only its opener on its own origin and
// holds no authority itself. Its URL fragment carries the opener's nonce.
func (s *Service) handlePasskeyWindowGET(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(passkeyWindowHTML))
}

// passkeyWindowHTML speaks AUTHKIT_PASSKEY_*: it posts READY, takes OPTIONS
// ({options: PublicKeyCredentialCreationOptions, labels: {title, create}}),
// and answers RESULT with the credential's fields (ArrayBuffers, which
// postMessage clones) or the DOMException's name, then closes.
const passkeyWindowHTML = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title></title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font:16px/1.5 system-ui,sans-serif;background:#fff;color:#111}
main{max-width:22rem;padding:1.5rem;text-align:center}
button{font:inherit;padding:.75rem 1.5rem;border:0;border-radius:.5rem;background:#111;color:#fff;cursor:pointer}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}button{background:#eee;color:#111}}
</style></head>
<body><main><p id="title"></p><button id="create" type="button" hidden></button></main>
<script>
(function () {
  var origin = location.origin;
  var nonce = new URLSearchParams(location.hash.slice(1)).get("nonce") || "";
  var opener = window.opener;
  function post(data) {
    data.type = "AUTHKIT_PASSKEY_RESULT";
    data.nonce = nonce;
    if (opener) opener.postMessage(data, origin);
    window.close();
  }
  if (!opener || !nonce) return;
  window.addEventListener("message", function (ev) {
    var d = ev.data;
    if (ev.origin !== origin || ev.source !== opener || !d || d.type !== "AUTHKIT_PASSKEY_OPTIONS" || d.nonce !== nonce) return;
    var labels = d.labels || {};
    document.title = labels.title || "";
    document.getElementById("title").textContent = labels.title || "";
    var button = document.getElementById("create");
    button.textContent = labels.create || "Create a passkey";
    button.hidden = false;
    button.onclick = function () {
      button.disabled = true;
      navigator.credentials.create({ publicKey: d.options }).then(function (c) {
        var r = c.response;
        post({ credential: {
          id: c.id, rawId: c.rawId, type: c.type,
          authenticatorAttachment: c.authenticatorAttachment || undefined,
          clientExtensionResults: c.getClientExtensionResults(),
          response: { clientDataJSON: r.clientDataJSON, attestationObject: r.attestationObject,
            transports: r.getTransports ? r.getTransports() : [] }
        } });
      }, function (err) {
        post({ error: (err && err.name) || "Error" });
      });
    };
  });
  opener.postMessage({ type: "AUTHKIT_PASSKEY_READY", nonce: nonce }, origin);
})();
</script></body></html>
`
