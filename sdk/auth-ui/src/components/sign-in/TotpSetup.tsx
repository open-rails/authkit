import QRCode from "react-qr-code"

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
  return (
    <div className="flex flex-col items-center gap-3">
      {otpauthUri && (
        <>
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
          <Button
            variant="outline"
            className="w-full"
            nativeButton={false}
            render={<a href={otpauthUri} />}
          >
            {t("twoFactor.openInAuthenticator")}
          </Button>
        </>
      )}
      <div className="flex w-full flex-col gap-1.5 rounded-lg bg-muted p-3">
        <span className="text-xs text-muted-foreground">
          {t("twoFactor.enterSecretManually")}
        </span>
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
    </div>
  )
}
