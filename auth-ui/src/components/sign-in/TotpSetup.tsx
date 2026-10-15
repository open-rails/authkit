import QRCode from "react-qr-code"
import { useId, useState, useSyncExternalStore } from "react"

import { useMessages } from "#authui/i18n/context"
import { Button } from "#authui/ui/button"
import { CopyButton } from "./parts.tsx"

export type TotpSetupProps = {
  secret: string
  otpauthUri?: string | null
}

// QR for a second device, a link for an authenticator on this one, and the
// key for typing in by hand.
export function TotpSetup({ secret, otpauthUri }: TotpSetupProps) {
  const { t } = useMessages()
  const account = provisioningAccount(otpauthUri)
  const mobile = useSyncExternalStore(
    noPlatformChanges,
    mobilePlatform,
    () => false
  )
  const [showKey, setShowKey] = useState(false)
  const keyId = useId()
  return (
    <div className="flex flex-col items-center gap-3">
      {otpauthUri && (
        <>
          {account && (
            <div className="text-center">
              <p className="font-medium">{account.issuer}</p>
              <p className="text-sm text-muted-foreground">{account.name}</p>
            </div>
          )}
          {/* Fixed black on white in both themes: scanners need it. */}
          <div className="rounded-lg bg-white p-3 ring-1 ring-foreground/10">
            <QRCode
              value={otpauthUri}
              size={152}
              viewBox="0 0 256 256"
              style={{ width: 152, height: "auto", maxWidth: "100%" }}
              aria-hidden="true"
            />
          </div>
          <p className="text-center text-sm text-balance text-muted-foreground">
            {t("twoFactor.scanQr")}
          </p>
          {mobile && (
            <>
              <Button
                variant="outline"
                className="w-full"
                nativeButton={false}
                render={<a href={otpauthUri} />}
              >
                {t("twoFactor.openInAuthenticator")}
              </Button>
              <p className="text-center text-xs text-muted-foreground">
                {t("twoFactor.deviceSetupHint")}
              </p>
            </>
          )}
        </>
      )}
      <div className="flex w-full flex-col gap-1.5 rounded-lg bg-muted p-3">
        <Button
          variant="ghost"
          size="sm"
          className="w-fit"
          aria-expanded={showKey}
          aria-controls={keyId}
          onClick={() => setShowKey((shown) => !shown)}
        >
          {showKey ? t("twoFactor.hideSetupKey") : t("twoFactor.showSetupKey")}
        </Button>
        {showKey && (
          <div id={keyId} className="grid gap-2">
            <p className="text-xs text-muted-foreground">
              {t("twoFactor.enterSecretManually")}
            </p>
            <div className="flex items-center gap-2">
              <code
                aria-label={t("enrollment.secretLabel")}
                className="min-w-0 flex-1 font-mono text-sm break-all"
              >
                {secret}
              </code>
              <CopyButton text={secret} size="sm" />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

const noPlatformChanges = () => () => {}

// A presentation hint, never app-install detection. The OS chooses which
// handler opens an otpauth link; QR and manual setup remain available to all.
function mobilePlatform() {
  if (typeof navigator === "undefined") return false
  const nav = navigator as Navigator & { userAgentData?: { mobile?: boolean } }
  if (typeof nav.userAgentData?.mobile === "boolean")
    return nav.userAgentData.mobile
  return (
    /Android|iPhone|iPad|iPod/i.test(nav.userAgent) ||
    (nav.platform === "MacIntel" && nav.maxTouchPoints > 1)
  )
}

// Display metadata only; the original URI goes unchanged to both QR and link.
function provisioningAccount(uri?: string | null) {
  if (!uri) return null
  try {
    const url = new URL(uri)
    if (url.protocol !== "otpauth:" || url.hostname !== "totp") return null
    const label = decodeURIComponent(url.pathname.slice(1))
    const separator = label.indexOf(":")
    const issuer = url.searchParams.get("issuer")
    const name = label.slice(separator + 1)
    return separator > 0 &&
      issuer === label.slice(0, separator) &&
      name &&
      !name.includes(":")
      ? { issuer, name }
      : null
  } catch {
    return null
  }
}
