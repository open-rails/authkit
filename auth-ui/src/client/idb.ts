// auth-ui's IndexedDB: DPoP key pairs and issuer sessions (a DPoP-bound
// refresh token is useless without its non-extractable key, so both live
// here, never in localStorage). Every call fails soft to "unavailable".

const DB = "authkit"
export const STORES = ["dpop-keys", "issuer-sessions"] as const
export type StoreName = (typeof STORES)[number]

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined")
      return reject(new Error("IndexedDB unavailable"))
    const req = indexedDB.open(DB, 1)
    req.onupgradeneeded = () => {
      for (const s of STORES)
        if (!req.result.objectStoreNames.contains(s))
          req.result.createObjectStore(s)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function run<T>(
  store: StoreName,
  mode: IDBTransactionMode,
  op: (s: IDBObjectStore) => IDBRequest
): Promise<T> {
  const db = await open()
  try {
    return await new Promise<T>((resolve, reject) => {
      const t = db.transaction(store, mode)
      const req = op(t.objectStore(store))
      t.oncomplete = () => resolve(req.result as T)
      t.onerror = () => reject(t.error ?? req.error)
      t.onabort = () => reject(t.error ?? req.error)
    })
  } finally {
    db.close()
  }
}

export const idbGet = <T>(store: StoreName, key: string) =>
  run<T | undefined>(store, "readonly", (s) => s.get(key))

export const idbPut = (store: StoreName, key: string, value: unknown) =>
  run<IDBValidKey>(store, "readwrite", (s) => s.put(value, key))

// Stores value only when key is absent; rejects otherwise.
export const idbAdd = (store: StoreName, key: string, value: unknown) =>
  run<IDBValidKey>(store, "readwrite", (s) => s.add(value, key))

export const idbDelete = (store: StoreName, key: string) =>
  run<undefined>(store, "readwrite", (s) => s.delete(key))
