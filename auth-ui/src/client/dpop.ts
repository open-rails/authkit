// RFC 9449 DPoP for browser clients: a non-extractable ES256 key kept in
// IndexedDB (memory when unavailable), proofs, and fetch with the server
// nonce handshake.

export type DPoPKey = {
  // RFC 7638 thumbprint: a bound token's cnf.jkt.
  thumbprint: string
  // A single-use proof for method and url (its query and fragment dropped);
  // accessToken is the token it accompanies, absent at a token endpoint.
  proof(
    method: string,
    url: string | URL,
    opts?: { accessToken?: string; nonce?: string }
  ): Promise<string>
}

const DB = "authkit-dpop"
const STORE = "keys"

const b64url = (bytes: ArrayBuffer | Uint8Array): string => {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let bin = ""
  for (const b of arr) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}
const utf8 = (s: string) => new TextEncoder().encode(s)

const memory = new Map<string, Promise<CryptoKeyPair>>()

// The key pair named name: loaded from IndexedDB, else generated (private
// key non-extractable) and stored. Concurrent tabs converge on one pair.
export function loadDPoPKey(name: string): Promise<DPoPKey> {
  let pair = memory.get(name)
  if (!pair) {
    pair = loadPair(name)
    memory.set(name, pair)
    pair.catch(() => memory.delete(name))
  }
  return pair.then(dpopKey)
}

// Forgets the key named name (sign-out): tokens bound to it become useless.
export async function deleteDPoPKey(name: string): Promise<void> {
  memory.delete(name)
  try {
    const db = await openDB()
    await tx(db, "readwrite", (s) => s.delete(name))
    db.close()
  } catch {
    // no IndexedDB: the key lived in memory only
  }
}

async function loadPair(name: string): Promise<CryptoKeyPair> {
  const db = await openDB().catch(() => null)
  try {
    if (db) {
      const found = await tx<CryptoKeyPair | undefined>(db, "readonly", (s) =>
        s.get(name)
      )
      if (found?.privateKey && found.publicKey) return found
    }
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    )
    if (!db) return pair
    try {
      await tx(db, "readwrite", (s) => s.add(pair, name))
      return pair
    } catch {
      // another tab stored one first: use it
      const won = await tx<CryptoKeyPair | undefined>(db, "readonly", (s) =>
        s.get(name)
      )
      return won ?? pair
    }
  } finally {
    db?.close()
  }
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined")
      return reject(new Error("no IndexedDB"))
    const req = indexedDB.open(DB, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function tx<T>(
  db: IDBDatabase,
  mode: IDBTransactionMode,
  op: (s: IDBObjectStore) => IDBRequest
): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode)
    const req = op(t.objectStore(STORE))
    t.oncomplete = () => resolve(req.result as T)
    t.onerror = () => reject(t.error ?? req.error)
    t.onabort = () => reject(t.error ?? req.error)
  })
}

async function dpopKey(pair: CryptoKeyPair): Promise<DPoPKey> {
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  const pub = { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }
  const thumbprint = b64url(
    await crypto.subtle.digest(
      "SHA-256",
      utf8(`{"crv":"P-256","kty":"EC","x":"${pub.x}","y":"${pub.y}"}`)
    )
  )
  return {
    thumbprint,
    async proof(method, url, opts = {}) {
      const target = new URL(String(url), globalThis.location?.href)
      target.search = ""
      target.hash = ""
      const jti = new Uint8Array(16)
      crypto.getRandomValues(jti)
      const claims: Record<string, unknown> = {
        jti: b64url(jti),
        htm: method.toUpperCase(),
        htu: target.toString(),
        iat: Math.floor(Date.now() / 1000),
      }
      if (opts.accessToken)
        claims.ath = b64url(
          await crypto.subtle.digest("SHA-256", utf8(opts.accessToken))
        )
      if (opts.nonce) claims.nonce = opts.nonce
      const header = { typ: "dpop+jwt", alg: "ES256", jwk: pub }
      const input = `${b64url(utf8(JSON.stringify(header)))}.${b64url(utf8(JSON.stringify(claims)))}`
      const sig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        utf8(input)
      )
      return `${input}.${b64url(sig)}`
    },
  }
}

// Server nonces (RFC 9449 §8), per origin, as servers last sent them.
export type DPoPNonces = Map<string, string>

// fetch with a DPoP proof (and, with accessToken, the DPoP Authorization
// header). A use_dpop_nonce refusal is retried once with the server's
// nonce; every DPoP-Nonce a response carries is remembered for its origin.
// The body must be replayable (not a stream).
export async function dpopFetch(
  doFetch: typeof fetch,
  key: DPoPKey,
  nonces: DPoPNonces,
  input: string | URL,
  init: RequestInit = {},
  accessToken?: string
): Promise<Response> {
  const url = new URL(String(input), globalThis.location?.href)
  const method = (init.method ?? "GET").toUpperCase()
  for (let attempt = 0; ; attempt++) {
    const headers = new Headers(init.headers)
    headers.set(
      "DPoP",
      await key.proof(method, url, {
        accessToken,
        nonce: nonces.get(url.origin),
      })
    )
    if (accessToken) headers.set("Authorization", `DPoP ${accessToken}`)
    const res = await doFetch(url, { ...init, method, headers })
    const nonce = res.headers.get("DPoP-Nonce")
    if (nonce) nonces.set(url.origin, nonce)
    if (attempt === 0 && nonce && (await asksForNonce(res))) continue
    return res
  }
}

// A resource server answers 401 with WWW-Authenticate; a token endpoint
// answers 400 {"error": "use_dpop_nonce"}.
async function asksForNonce(res: Response): Promise<boolean> {
  if (/error="use_dpop_nonce"/.test(res.headers.get("WWW-Authenticate") ?? ""))
    return true
  if (res.status !== 400) return false
  try {
    const body = (await res.clone().json()) as { error?: unknown }
    return body?.error === "use_dpop_nonce"
  } catch {
    return false
  }
}
