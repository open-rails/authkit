// @vitest-environment jsdom
import "../test/dom.ts"
import { expect, it, vi } from "vitest"
import { createAuthClient } from "./client.ts"
import { AuthSessionChangedError } from "./errors.ts"
import {
  complete,
  deferred,
  json,
  stubFetch,
  stubPasskey,
  tokenSet,
} from "./testing.ts"

it("does not finish or install an old account's enrollment after switching accounts during the native prompt", async () => {
  stubPasskey()
  const native = deferred<Credential | null>()
  const create = vi.fn(() => native.promise)
  Object.assign(navigator.credentials, { create })
  const finished = vi.fn(() => json(200, complete("alice")))
  const client = createAuthClient({
    sessionHint: false,
    fetch: stubFetch({
      "POST /api/v1/me/passkeys/enroll/begin": () =>
        json(200, {
          publicKey: {
            challenge: "AQID",
            rp: { id: "x.test", name: "X" },
            user: { id: "AQI", name: "alice", displayName: "Alice" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        }),
      "POST /api/v1/me/passkeys/enroll/finish": finished,
    }),
  })
  const pending = client.enrollPasskey(tokenSet("alice"))
  await vi.waitFor(() => expect(create).toHaveBeenCalledOnce())
  await client.completeSignIn(async () => complete("bob"))
  native.resolve(null)
  await expect(pending).rejects.toBeInstanceOf(AuthSessionChangedError)
  expect(finished).not.toHaveBeenCalled()
  expect(client.getSnapshot()).toMatchObject({
    status: "authenticated",
    userId: "bob",
  })
})
