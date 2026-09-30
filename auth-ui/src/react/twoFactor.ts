import { useCallback, useEffect, useState } from "react"

import type { AuthKitError } from "../client/errors.ts"
import type { TwoFactorMethod, TwoFactorStatus } from "../client/types.ts"
import type { GuardOptions } from "./account.ts"
import {
  sessionIdentity,
  useAuthClient,
  useSession,
  useUser,
} from "./context.ts"
import { toAuthKitError, unguarded, useTask } from "./task.ts"

export type TwoFactorEnrollmentState =
  | { step: "idle" }
  | {
      step: "totp"
      secret: string
      otpauthUri: string
      makeDefault?: boolean
    }
  | {
      step: "code_sent"
      method: "email" | "sms"
      phoneNumber?: string
      makeDefault?: boolean
      // The masked address the setup code went to.
      destination: string | null
    }
  // Show once; they are not retrievable later.
  | { step: "backup_codes"; codes: string[] }

export function useTwoFactorSettings(options: GuardOptions = {}) {
  const client = useAuthClient()
  const guard = options.guard ?? unguarded
  const { refetch: refetchUser } = useUser()
  const key = sessionIdentity(useSession())
  const authed = key.startsWith("authenticated:")
  const { busy, error, run, clearError } = useTask()
  const [enrollment, setEnrollment] = useState<TwoFactorEnrollmentState>({
    step: "idle",
  })
  const [nonce, setNonce] = useState(0)
  const request = `${key}|${nonce}`
  const [loaded, setLoaded] = useState<{
    request: string
    status: TwoFactorStatus | null
    error: AuthKitError | null
  } | null>(null)

  useEffect(() => {
    if (!authed) return
    const ctl = new AbortController()
    client.getTwoFactor(ctl.signal).then(
      (status) => setLoaded({ request, status, error: null }),
      (err: unknown) => {
        if (!ctl.signal.aborted)
          setLoaded({ request, status: null, error: toAuthKitError(err) })
      }
    )
    return () => ctl.abort()
  }, [client, authed, request])

  const refetch = useCallback(() => {
    setNonce((n) => n + 1)
    void refetchUser()
  }, [refetchUser])

  // TOTP answers its secret; email and SMS send a setup code.
  const start = useCallback(
    (input: {
      method: TwoFactorMethod
      phoneNumber?: string
      makeDefault?: boolean
    }) =>
      run(async () => {
        const setup = await guard(() => client.setupTwoFactor(input))
        if (input.method === "totp")
          setEnrollment({
            step: "totp",
            secret: setup.secret ?? "",
            otpauthUri: setup.otpauth_uri ?? "",
            makeDefault: input.makeDefault,
          })
        else
          setEnrollment({
            step: "code_sent",
            method: input.method,
            phoneNumber: input.phoneNumber,
            makeDefault: input.makeDefault,
            destination: setup.destination,
          })
      }),
    [client, guard, run]
  )

  // Confirms the started factor with its code; backup codes follow the
  // first factor.
  const confirm = useCallback(
    (code: string) =>
      run(async () => {
        if (enrollment.step !== "totp" && enrollment.step !== "code_sent")
          return
        const created = await guard(() =>
          client.addTwoFactorFactor({
            method: enrollment.step === "totp" ? "totp" : enrollment.method,
            code: code.trim(),
            phoneNumber:
              enrollment.step === "code_sent"
                ? enrollment.phoneNumber
                : undefined,
            makeDefault: enrollment.makeDefault,
          })
        )
        setEnrollment(
          created.backup_codes.length
            ? { step: "backup_codes", codes: created.backup_codes }
            : { step: "idle" }
        )
        refetch()
      }),
    [client, guard, run, enrollment, refetch]
  )

  const setDefault = useCallback(
    (factorId: string) =>
      run(async () => {
        await guard(() => client.setDefaultTwoFactorFactor(factorId))
        refetch()
      }),
    [client, guard, run, refetch]
  )

  // Removing the last factor turns 2FA off.
  const remove = useCallback(
    (factorId: string) =>
      run(async () => {
        await guard(() => client.removeTwoFactorFactor(factorId))
        refetch()
      }),
    [client, guard, run, refetch]
  )

  // Removes every factor and backup code.
  const disable = useCallback(
    () =>
      run(async () => {
        await guard(() => client.disableTwoFactor())
        refetch()
      }),
    [client, guard, run, refetch]
  )

  const regenerateBackupCodes = useCallback(
    () =>
      run(async () => {
        const codes = await guard(() => client.regenerateBackupCodes())
        setEnrollment({ step: "backup_codes", codes })
        refetch()
      }),
    [client, guard, run, refetch]
  )

  // Leaves backup codes or an unfinished enrollment.
  const dismiss = useCallback(() => {
    clearError()
    setEnrollment({ step: "idle" })
  }, [clearError])

  const current =
    authed && loaded?.request.startsWith(`${key}|`) ? loaded : null
  return {
    status: current?.status ?? null,
    loading: authed && loaded?.request !== request,
    enrollment,
    busy,
    error: error ?? current?.error ?? null,
    refetch,
    start,
    confirm,
    setDefault,
    remove,
    disable,
    regenerateBackupCodes,
    dismiss,
  }
}
