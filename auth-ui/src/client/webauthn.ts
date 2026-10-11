// WebAuthn JSON <-> browser credential conversion for passkey ceremonies.
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

// The request options a passkey sign-in or step-up began with, as the browser
// takes them.
export function requestOptions(
  body: unknown
): PublicKeyCredentialRequestOptions {
  const pk = rec(rec(body).publicKey)
  return {
    ...(pk as unknown as PublicKeyCredentialRequestOptions),
    challenge: fromBase64url(String(pk.challenge ?? "")),
    allowCredentials: (Array.isArray(pk.allowCredentials)
      ? pk.allowCredentials
      : []
    ).map((c: unknown) => ({
      ...(rec(c) as unknown as PublicKeyCredentialDescriptor),
      id: fromBase64url(String(rec(c).id ?? "")),
    })),
  }
}

// The assertion as AuthKit's passkey finish reads it.
export function assertionBody(credential: PublicKeyCredential): Rec {
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      authenticatorData: toBase64url(response.authenticatorData),
      signature: toBase64url(response.signature),
      userHandle: response.userHandle
        ? toBase64url(response.userHandle)
        : undefined,
    },
  }
}

// Asks the browser's authenticator for an assertion over options: from a
// click, or conditional (the page's autofill offers saved passkeys, WebAuthn
// L3 conditional mediation) until signal aborts it.
export async function getAssertion(
  options: unknown,
  opts: { conditional?: boolean; signal?: AbortSignal } = {}
): Promise<Rec> {
  const credential = await navigator.credentials.get({
    publicKey: requestOptions(options),
    ...(opts.conditional ? { mediation: "conditional" as const } : {}),
    signal: opts.signal,
  })
  if (!(credential instanceof PublicKeyCredential))
    throw new Error("the browser returned no passkey")
  return assertionBody(credential)
}

export const webAuthnAvailable = () =>
  typeof window !== "undefined" && "PublicKeyCredential" in window

// The user closed the browser's passkey prompt, or it timed out.
export const passkeyDismissed = (error: unknown) =>
  error instanceof DOMException &&
  (error.name === "NotAllowedError" || error.name === "AbortError")

// Whether the browser can offer saved passkeys in a field's autofill
// (autocomplete="username webauthn").
export async function conditionalMediationAvailable(): Promise<boolean> {
  if (!webAuthnAvailable()) return false
  const check = (
    PublicKeyCredential as unknown as {
      isConditionalMediationAvailable?: () => Promise<boolean>
    }
  ).isConditionalMediationAvailable
  try {
    return check ? await check.call(PublicKeyCredential) : false
  } catch {
    return false
  }
}
