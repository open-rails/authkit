import { useCallback, useEffect, useRef, useState } from "react"

import type { SignInResult } from "../client/authResult.ts"
import { AuthKitError, errorMetadata } from "../client/errors.ts"
import { passkeyDismissed, webAuthnAvailable } from "../client/webauthn.ts"
import type {
  AccountRecoveryConfirmation,
  Agreement,
  DeviceVerificationStep,
  EnrollmentStep,
  SecondFactorStep,
  TwoFactorMethod,
  VerificationStep,
} from "../client/types.ts"
import { useAuthClient, useCapabilities } from "./context.ts"
import { toAuthKitError, useTask } from "./task.ts"

// returnTo: where the flow began, handed back after sign-in.
export type LoginState =
  | { step: "credentials"; recovered?: boolean }
  // challenge.factor is the factor codes are checked against;
  // sendTwoFactorCode(id) switches it.
  | { step: "two_factor"; challenge: SecondFactorStep; returnTo?: string }
  | {
      step: "enrollment"
      enrollment: EnrollmentStep
      returnTo?: string
      // Set once startEnrollment picked a method.
      method?: TwoFactorMethod
      phoneNumber?: string
      totp?: { secret: string; otpauthUri: string }
      // The masked address an email/SMS setup code went to.
      codeSentTo?: string
    }
  | { step: "recovery"; recovery: AccountRecoveryConfirmation }
  // A new device past the account's limit: a code went to the owner.
  | {
      step: "new_device"
      verification: DeviceVerificationStep
      returnTo?: string
    }
  | {
      step: "verification"
      verification: VerificationStep
      returnTo?: string
    }
  // A code went to identifier, an email or phone (contact-first sign-in).
  | { step: "code"; identifier: string; returnTo?: string }
  // The code proved a new contact: the sign-up accepts these first.
  | {
      step: "signup_agreements"
      identifier: string
      code: string
      agreements: Agreement[]
      returnTo?: string
    }
  // Signed in, and these documents are due: never accepted, or a new
  // version to accept again.
  | { step: "agreements"; agreements: Agreement[]; returnTo?: string }
  // Signed up with a code: a passkey makes the next sign-in one tap.
  | { step: "passkey_offer"; returnTo?: string }
  // Signed in, but newly issued backup codes must be shown first.
  | { step: "backup_codes"; codes: string[]; returnTo?: string }
  | { step: "done"; returnTo?: string }

export type LoginOptions = {
  // Called once the session exists and any backup codes were acknowledged.
  onSignedIn?: (result: { returnTo?: string }) => void
}

const refs = (agreements: Agreement[]) =>
  agreements.map(({ key, version }) => ({ key, version }))

// Password, passkey or contact-code sign-in plus every step an AuthResult
// can name next.
export function useLogin(options: LoginOptions = {}) {
  const client = useAuthClient()
  const { capabilities } = useCapabilities()
  const passkeys = !!capabilities?.passkeys.login
  const { busy, error, run, clearError } = useTask()
  const [state, setState] = useState<LoginState>({ step: "credentials" })
  // Kept so account recovery can sign straight back in.
  const credentials = useRef<{ identifier: string; password: string } | null>(
    null
  )
  // Backup codes a forced enrollment issued, shown once signed in.
  const pendingCodes = useRef<string[]>([])
  // A code sign-up offers a passkey once it is signed in.
  const offerPasskey = useRef(false)
  const onSignedIn = useRef(options.onSignedIn)
  useEffect(() => {
    onSignedIn.current = options.onSignedIn
  })

  const finish = useCallback((returnTo?: string) => {
    const codes = pendingCodes.current
    credentials.current = null
    pendingCodes.current = []
    if (codes.length) {
      setState({ step: "backup_codes", codes, returnTo })
      return
    }
    setState({ step: "done", returnTo })
    onSignedIn.current?.({ returnTo })
  }, [])

  // After the documents due: the passkey offer, then finish.
  const accepted = useCallback(
    (returnTo?: string) => {
      const offer = offerPasskey.current && passkeys && webAuthnAvailable()
      offerPasskey.current = false
      if (offer) return setState({ step: "passkey_offer", returnTo })
      finish(returnTo)
    },
    [finish, passkeys]
  )

  const complete = useCallback(
    (result: SignInResult, returnTo?: string) => {
      offerPasskey.current = offerPasskey.current && result.created
      const due = result.agreements_due ?? []
      if (due.length)
        return setState({ step: "agreements", agreements: due, returnTo })
      accepted(returnTo)
    },
    [accepted]
  )

  const apply = useCallback(
    (result: SignInResult, returnTo = result.return_to ?? undefined) => {
      switch (result.status) {
        case "complete":
          return complete(result, returnTo)
        case "second_factor_required":
          return setState({
            step: "two_factor",
            challenge: result.second_factor,
            returnTo,
          })
        case "enrollment_required":
          return setState({
            step: "enrollment",
            enrollment: result.enrollment,
            returnTo,
          })
        case "account_recovery_required":
          return setState({ step: "recovery", recovery: result.recovery })
        case "verification_required":
          return setState({
            step: "verification",
            verification: result.verification,
            returnTo,
          })
        case "device_verification_required":
          return setState({
            step: "new_device",
            verification: result.device_verification,
            returnTo,
          })
      }
    },
    [complete]
  )

  const signIn = useCallback(
    (input: { identifier: string; password: string }) =>
      run(async () => {
        credentials.current = input
        pendingCodes.current = []
        apply(await client.signInWithPassword(input))
      }),
    [client, run, apply]
  )

  // Sends a code to identifier (an email, or a phone in E.164) for a
  // contact-first sign-in: a sign-up when nobody has it yet.
  const sendCode = useCallback(
    (
      identifier: string,
      opts: { returnTo?: string; inviteCode?: string } = {}
    ) =>
      run(async () => {
        credentials.current = null
        pendingCodes.current = []
        await client.startPasswordless({
          identifier,
          mode: "code",
          returnTo: opts.returnTo,
          inviteCode: opts.inviteCode,
        })
        setState({ step: "code", identifier, returnTo: opts.returnTo })
      }),
    [client, run]
  )

  const resendCode = useCallback(
    () =>
      run(async () => {
        if (state.step !== "code") return
        await client.startPasswordless({
          identifier: state.identifier,
          mode: "code",
          returnTo: state.returnTo,
        })
      }),
    [client, run, state]
  )

  // A new contact's code answers agreement_required: the sign-up step.
  const confirmCode = useCallback(
    (code: string) =>
      run(async () => {
        if (state.step !== "code") return
        const { identifier, returnTo } = state
        offerPasskey.current = true
        try {
          apply(
            await client.confirmPasswordless({ identifier, code: code.trim() }),
            returnTo
          )
        } catch (err) {
          const required = errorMetadata(err, "agreement_required")
          if (!required) throw err
          setState({
            step: "signup_agreements",
            identifier,
            code: code.trim(),
            agreements: required.agreements,
            returnTo,
          })
        }
      }),
    [client, run, apply, state]
  )

  const acceptSignUp = useCallback(
    () =>
      run(async () => {
        if (state.step !== "signup_agreements") return
        const { identifier, code, agreements, returnTo } = state
        offerPasskey.current = true
        apply(
          await client.confirmPasswordless({
            identifier,
            code,
            agreements: refs(agreements),
          }),
          returnTo
        )
      }),
    [client, run, apply, state]
  )

  // Accepts the documents a sign-in found due, then continues.
  const acceptAgreements = useCallback(
    () =>
      run(async () => {
        if (state.step !== "agreements") return
        await client.acceptAgreements(refs(state.agreements))
        accepted(state.returnTo)
      }),
    [client, run, accepted, state]
  )

  // Declining what is due signs out.
  const declineAgreements = useCallback(
    () =>
      run(async () => {
        if (state.step !== "agreements") return
        await client.signOut()
        setState({ step: "credentials" })
      }),
    [client, run, state]
  )

  // Adds a passkey after a code sign-up; closing the prompt keeps the offer.
  const addPasskey = useCallback(
    () =>
      run(async () => {
        if (state.step !== "passkey_offer") return
        try {
          await client.registerPasskey()
        } catch (err) {
          if (passkeyDismissed(err)) return
          throw err
        }
        finish(state.returnTo)
      }),
    [client, run, finish, state]
  )

  const skipPasskey = useCallback(() => {
    if (state.step !== "passkey_offer") return
    finish(state.returnTo)
  }, [finish, state])

  // Waits for the contact field's autofill to offer a saved passkey
  // (conditional mediation) until signal aborts. It never marks the form
  // busy; a failure other than the user's dismissal shows as the error.
  const autofillPasskey = useCallback(
    async (signal: AbortSignal) => {
      let result: SignInResult
      try {
        result = await client.signInWithPasskey({ conditional: true, signal })
      } catch (err) {
        if (signal.aborted || passkeyDismissed(err)) return
        void run(() => Promise.reject(toAuthKitError(err)))
        return
      }
      credentials.current = null
      pendingCodes.current = []
      apply(result)
    },
    [client, run, apply]
  )

  // Passkey sign-in with one the browser offers; call from a click. Closing
  // the browser's prompt leaves the form as it was.
  const signInWithPasskey = useCallback(
    () =>
      run(async () => {
        credentials.current = null
        pendingCodes.current = []
        let result: SignInResult
        try {
          result = await client.signInWithPasskey()
        } catch (err) {
          if (passkeyDismissed(err)) return
          throw err
        }
        apply(result)
      }),
    [client, run, apply]
  )

  // Provider sign-in in a popup; call from the click handler itself.
  // Popup failures surface as error codes popup_blocked/popup_closed/
  // popup_timeout/session_changed or the provider's code.
  const signInWithPopup = useCallback(
    (provider: string, opts: { returnTo?: string; inviteCode?: string } = {}) =>
      run(async () => {
        credentials.current = null
        pendingCodes.current = []
        const out = await client.signInWithPopup(provider, opts)
        if (out.ok) return apply(out.result)
        const code =
          out.reason === "provider_error"
            ? out.code
            : out.reason === "session_changed"
              ? out.reason
              : `popup_${out.reason}`
        throw new AuthKitError(0, { type: "local", code, message: code })
      }),
    [client, run, apply]
  )

  // Enter the flow from a result produced elsewhere (OIDC popup/redirect,
  // registration, a refresh that needs another step).
  const resume = useCallback(
    (result: SignInResult) => {
      clearError()
      apply(result)
    },
    [apply, clearError]
  )

  const verifyTwoFactor = useCallback(
    (code: string, opts: { backupCode?: boolean } = {}) =>
      run(async () => {
        if (state.step !== "two_factor") return
        const { challenge, returnTo } = state
        const result = await client.verifyTwoFactor({
          userId: challenge.user_id,
          challenge: challenge.challenge,
          code: code.trim(),
          factorId: opts.backupCode ? undefined : challenge.factor.id,
          backupCode: opts.backupCode || undefined,
        })
        apply(result, result.return_to ?? returnTo)
      }),
    [client, run, apply, state]
  )

  // Resends the current factor's code, or switches to another factor.
  const sendTwoFactorCode = useCallback(
    (factorId?: string) =>
      run(async () => {
        if (state.step !== "two_factor") return
        const { challenge, returnTo } = state
        const next = await client.sendTwoFactorChallenge({
          userId: challenge.user_id,
          challenge: challenge.challenge,
          factorId: factorId ?? challenge.factor.id,
        })
        setState({
          step: "two_factor",
          challenge: next.second_factor,
          returnTo,
        })
      }),
    [client, run, state]
  )

  const confirmNewDevice = useCallback(
    (code: string) =>
      run(async () => {
        if (state.step !== "new_device") return
        const { verification, returnTo } = state
        const result = await client.confirmDeviceVerification({
          userId: verification.user_id,
          challenge: verification.challenge,
          code: code.trim(),
        })
        apply(result, result.return_to ?? returnTo)
      }),
    [client, run, apply, state]
  )

  // Resends the new device's code, or sends it to the other channel.
  const sendNewDeviceCode = useCallback(
    (channel?: "email" | "sms") =>
      run(async () => {
        if (state.step !== "new_device") return
        const { verification, returnTo } = state
        const next = await client.sendDeviceVerification({
          userId: verification.user_id,
          challenge: verification.challenge,
          channel,
        })
        setState({
          step: "new_device",
          verification: next.device_verification,
          returnTo,
        })
      }),
    [client, run, state]
  )

  // TOTP answers with a secret; SMS/email send a code.
  const startEnrollment = useCallback(
    (input: { method: TwoFactorMethod; phoneNumber?: string }) =>
      run(async () => {
        if (state.step !== "enrollment") return
        const setup = await client.setupTwoFactor(input, {
          enrollmentToken: state.enrollment.token_set,
        })
        setState({
          step: "enrollment",
          enrollment: state.enrollment,
          returnTo: state.returnTo,
          method: input.method,
          phoneNumber: input.phoneNumber,
          totp:
            setup.secret && setup.otpauth_uri
              ? { secret: setup.secret, otpauthUri: setup.otpauth_uri }
              : undefined,
          codeSentTo:
            input.method === "totp"
              ? undefined
              : (setup.destination ?? input.phoneNumber ?? ""),
        })
      }),
    [client, run, state]
  )

  const confirmEnrollment = useCallback(
    (code: string) =>
      run(async () => {
        if (state.step !== "enrollment" || !state.method) return
        const created = await client.addTwoFactorFactor(
          {
            method: state.method,
            phoneNumber: state.phoneNumber,
            code: code.trim(),
          },
          { enrollmentToken: state.enrollment.token_set }
        )
        if (!created.auth) throw new Error("AuthKit returned no sign-in")
        pendingCodes.current = created.backup_codes
        apply(created.auth, created.auth.return_to ?? state.returnTo)
      }),
    [client, run, apply, state]
  )

  // Restores a soft-deleted account, then signs in again if we can.
  const confirmRecovery = useCallback(
    () =>
      run(async () => {
        if (state.step !== "recovery") return
        await client.confirmAccountRecovery(state.recovery.token)
        const again = credentials.current
        if (!again) return setState({ step: "credentials", recovered: true })
        apply(await client.signInWithPassword(again))
      }),
    [client, run, apply, state]
  )

  const resendVerification = useCallback(
    () =>
      run(async () => {
        if (state.step !== "verification") return
        await client.requestVerification({
          identifier: state.verification.identifier,
        })
      }),
    [client, run, state]
  )

  const confirmVerification = useCallback(
    (code: string) =>
      run(async () => {
        if (state.step !== "verification") return
        const result = await client.confirmVerification({
          identifier: state.verification.identifier,
          code: code.trim(),
        })
        if (result) apply(result, result.return_to ?? state.returnTo)
      }),
    [client, run, apply, state]
  )

  const acknowledgeBackupCodes = useCallback(() => {
    if (state.step !== "backup_codes") return
    setState({ step: "done", returnTo: state.returnTo })
    onSignedIn.current?.({ returnTo: state.returnTo })
  }, [state])

  const reset = useCallback(() => {
    credentials.current = null
    pendingCodes.current = []
    offerPasskey.current = false
    clearError()
    setState({ step: "credentials" })
  }, [clearError])

  return {
    state,
    busy,
    error,
    signIn,
    signInWithPasskey,
    autofillPasskey,
    signInWithPopup,
    sendCode,
    resendCode,
    confirmCode,
    acceptSignUp,
    acceptAgreements,
    declineAgreements,
    addPasskey,
    skipPasskey,
    resume,
    verifyTwoFactor,
    sendTwoFactorCode,
    confirmNewDevice,
    sendNewDeviceCode,
    startEnrollment,
    confirmEnrollment,
    confirmRecovery,
    resendVerification,
    confirmVerification,
    acknowledgeBackupCodes,
    reset,
  }
}
