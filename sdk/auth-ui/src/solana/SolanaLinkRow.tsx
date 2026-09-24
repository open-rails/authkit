import { Wallet01Icon } from "@hugeicons/core-free-icons"
import { useEffect, useMemo, useRef, useState } from "react"

import { useStepUpGuard } from "../components/account/step-up-context.ts"
import {
  ConfirmDialog,
  Notice,
  SettingRow,
  StatusBadge,
} from "../components/account/shared.tsx"
import { useMessages } from "../i18n/context.ts"
import { useAuthClient, useUser } from "../react/context.ts"
import { Button } from "../ui/button.tsx"
import { Spinner } from "../ui/spinner.tsx"
import {
  createSolanaAuth,
  isSolanaWalletError,
  signerFromWallet,
  type SolanaSigner,
  type WalletAdapterLike,
} from "./core.ts"

export interface SolanaLinkRowProps {
  /** wallet-adapter's `useWallet()`, or any `WalletAdapterLike`. */
  wallet?: WalletAdapterLike | null
  /** Opens the host's wallet picker; linking resumes once it connects. */
  onConnectRequest?: () => void
  /**
   * For hosts that load the wallet stack only on demand: resolves a connected
   * signer when Link is pressed (used instead of `wallet`).
   */
  acquireSigner?: () => Promise<SolanaSigner>
}

const shorten = (a: string) => `${a.slice(0, 4)}…${a.slice(-4)}`

/** Link, verify or unlink a Solana wallet; for `LinkedProvidersPanel.extraRows`. */
export function SolanaLinkRow({
  wallet,
  onConnectRequest,
  acquireSigner,
}: SolanaLinkRowProps) {
  const { t, error: message } = useMessages()
  const client = useAuthClient()
  const guard = useStepUpGuard()
  const { user, refetch } = useUser()
  const solana = useMemo(() => createSolanaAuth(client), [client])
  const [busy, setBusy] = useState<"link" | "unlink" | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [awaiting, setAwaiting] = useState(false)
  const [confirm, setConfirm] = useState(false)

  const account = user?.solana_linked_account
  const address = account?.address ?? user?.solana_address ?? null
  const unverified = !!account && !account.verified
  const shown = account?.primary_sns_name ?? (address ? shorten(address) : null)

  const perform = async (
    kind: "link" | "unlink",
    fn: () => Promise<unknown>
  ) => {
    setBusy(kind)
    setError(null)
    try {
      await guard(fn)
      await refetch()
    } catch (err) {
      const rejected = isSolanaWalletError(err) && err.reason === "rejected"
      const cancelled =
        err instanceof Error &&
        "code" in err &&
        err.code === "step_up_cancelled"
      if (!rejected && !cancelled) setError(err)
    } finally {
      setBusy(null)
    }
  }

  const link = () => {
    if (acquireSigner) {
      void perform("link", async () =>
        solana.link(await acquireSigner(), { linkedAddress: address })
      )
      return
    }
    if (!(wallet?.connected && wallet.publicKey) && onConnectRequest) {
      setAwaiting(true)
      onConnectRequest()
      return
    }
    setAwaiting(false)
    void perform("link", () =>
      solana.link(signerFromWallet(wallet), { linkedAddress: address })
    )
  }

  // Resume the link that asked for a wallet once one connects.
  const latestLink = useRef(link)
  useEffect(() => {
    latestLink.current = link
  })
  const ready = !!(wallet?.connected && wallet.publicKey)
  useEffect(() => {
    if (ready && awaiting) latestLink.current()
  }, [ready, awaiting])

  const walletError =
    isSolanaWalletError(error) && error.reason === "not_connected"
      ? t("account.wallet.notConnected")
      : isSolanaWalletError(error)
        ? t("account.wallet.unsupported")
        : error
          ? message(error)
          : null

  return (
    <>
      <SettingRow
        icon={Wallet01Icon}
        title={t("account.wallet.title")}
        badge={
          <StatusBadge on={!!address && !unverified}>
            {address && !unverified
              ? t("account.providers.linked")
              : t("account.providers.notLinked")}
          </StatusBadge>
        }
        description={
          !address
            ? t("account.wallet.notLinked")
            : unverified
              ? t("account.wallet.verificationRequired", {
                  address: shown ?? "",
                })
              : t("account.wallet.linked", { address: shown ?? "" })
        }
        actions={
          <>
            {(!address || unverified) && (
              <Button
                variant="outline"
                size="sm"
                disabled={!!busy || !user}
                onClick={link}
              >
                {busy === "link" && <Spinner />}
                {unverified
                  ? busy === "link"
                    ? t("account.wallet.verifying")
                    : t("account.wallet.verify")
                  : busy === "link" || awaiting
                    ? t("account.wallet.linking")
                    : t("account.wallet.link")}
              </Button>
            )}
            {address && (
              <Button
                variant="outline"
                size="sm"
                disabled={!!busy}
                onClick={() => setConfirm(true)}
              >
                {busy === "unlink" && <Spinner />}
                {busy === "unlink"
                  ? t("account.wallet.unlinking")
                  : t("account.wallet.unlink")}
              </Button>
            )}
          </>
        }
      >
        {walletError && (
          <Notice tone="error">
            {walletError}
            {error instanceof Error &&
              "code" in error &&
              error.code === "cannot_unlink_last_login_method" && (
                <span className="mt-1 block text-foreground/80">
                  {t("account.providers.lastMethodHint")}
                </span>
              )}
          </Notice>
        )}
      </SettingRow>
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={t("account.wallet.unlink")}
        description={t("account.wallet.unlinkConfirm")}
        confirmLabel={t("account.wallet.unlink")}
        destructive
        onConfirm={() => {
          setConfirm(false)
          void perform("unlink", () => solana.unlink())
        }}
      />
    </>
  )
}
