import { useCallback, useEffect, useState } from "react"

import type { AuthKitError } from "../client/errors.ts"
import type {
  RemovedMfaRole,
  TwoFactorMethod,
  TwoFactorStatus,
} from "../client/types.ts"
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

  const start = useCallback(
    (input: {
      method: TwoFactorMethod
      phoneNumber?: string
      makeDefault?: boolean
    }) =>
      run(async () => {
        const out = await guard(() => client.enableTwoFactor(input))
        if (out.kind === "totp_started")
          setEnrollment({
            step: "totp",
            secret: out.secret,
            otpauthUri: out.otpauthUri,
            makeDefault: input.makeDefault,
          })
        else if (out.kind === "code_sent" && input.method !== "totp")
          setEnrollment({
            step: "code_sent",
            method: input.method,
            phoneNumber: input.phoneNumber,
            makeDefault: input.makeDefault,
          })
        else if (out.kind === "enabled") {
          setEnrollment(
            out.backupCodes.length
              ? { step: "backup_codes", codes: out.backupCodes }
              : { step: "idle" }
          )
          refetch()
        }
      }),
    [client, guard, run, refetch]
  )

  const confirm = useCallback(
    (code: string) =>
      run(async () => {
        if (enrollment.step !== "totp" && enrollment.step !== "code_sent")
          return
        const method = enrollment.step === "totp" ? "totp" : enrollment.method
        const out = await guard(() =>
          client.enableTwoFactor({
            method,
            code: code.trim(),
            phoneNumber:
              enrollment.step === "code_sent"
                ? enrollment.phoneNumber
                : undefined,
            makeDefault: enrollment.makeDefault,
          })
        )
        if (out.kind !== "enabled") return
        setEnrollment(
          out.backupCodes.length
            ? { step: "backup_codes", codes: out.backupCodes }
            : { step: "idle" }
        )
        refetch()
      }),
    [client, guard, run, enrollment, refetch]
  )

  const setDefault = useCallback(
    (factor: { factorId: string; method: TwoFactorMethod }) =>
      run(async () => {
        await guard(() =>
          client.enableTwoFactor({
            method: factor.method,
            factorId: factor.factorId,
            makeDefault: true,
          })
        )
        refetch()
      }),
    [client, guard, run, refetch]
  )

  // Without factorId every factor goes. Returns roles lost for lacking MFA.
  const disable = useCallback(
    (input: { factorId?: string } = {}) =>
      run(async () => {
        const removed: RemovedMfaRole[] = await guard(() =>
          client.disableTwoFactor(input)
        )
        refetch()
        return removed
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
    disable,
    regenerateBackupCodes,
    dismiss,
  }
}
