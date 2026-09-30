// WebAuthn JSON <-> browser credential conversion for passkey registration.
// AuthKit (go-webauthn) sends and reads binary fields as unpadded base64url.

type Rec = Record<string, unknown>

const rec = (v: unknown): Rec =>
  v !== null && typeof v === "object" ? (v as Rec) : {}

function fromBase64url(text: string): ArrayBuffer {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/")
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer
}

function toBase64url(buf: ArrayBuffer): string {
  let bin = ""
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

// The creation options AuthKit's register/begin answered, as the browser
// takes them.
export function creationOptions(
  body: unknown
): PublicKeyCredentialCreationOptions {
  const pk = rec(rec(body).publicKey)
  const user = rec(pk.user)
  return {
    ...(pk as unknown as PublicKeyCredentialCreationOptions),
    challenge: fromBase64url(String(pk.challenge ?? "")),
    user: {
      ...(user as unknown as PublicKeyCredentialUserEntity),
      id: fromBase64url(String(user.id ?? "")),
    },
    excludeCredentials: (Array.isArray(pk.excludeCredentials)
      ? pk.excludeCredentials
      : []
    ).map((c: unknown) => ({
      ...(rec(c) as unknown as PublicKeyCredentialDescriptor),
      id: fromBase64url(String(rec(c).id ?? "")),
    })),
  }
}

// The new credential as AuthKit's register/finish reads it.
export function registrationBody(credential: PublicKeyCredential): Rec {
  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      attestationObject: toBase64url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
  }
}
