// @vitest-environment jsdom
import "../../test/dom.ts"

import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import { TotpSetup } from "./TotpSetup.tsx"

const { qr } = vi.hoisted(() => ({ qr: vi.fn() }))
vi.mock("react-qr-code", () => ({
  default: ({ value }: { value: string }) => {
    qr(value)
    return <svg data-testid="totp-qr" />
  },
}))

const secret = "JBSWY3DPEHPK3PXP"
const uri = `otpauth://totp/Doujins:reader%40example.test?issuer=Doujins&secret=${secret}&algorithm=SHA1&digits=6&period=30`
afterEach(() => vi.restoreAllMocks())

it("shows issuer and account beside an unchanged QR, without a desktop app link", () => {
  vi.spyOn(navigator, "userAgent", "get").mockReturnValue(
    "Mozilla/5.0 (X11; Linux x86_64)"
  )
  const view = render(<TotpSetup secret={secret} otpauthUri={uri} />)
  expect(qr).toHaveBeenCalledWith(uri)
  expect(
    screen.getByText(/In Microsoft Authenticator, choose \+ → Other account/)
  ).toBeInTheDocument()
  expect(view.container.querySelector("a[href]")).toBeNull()
  expect(screen.getByText("Doujins")).toBeInTheDocument()
  expect(screen.getByText("reader@example.test")).toBeInTheDocument()
})

it("offers a best-effort mobile app link without claiming installation detection", () => {
  vi.spyOn(navigator, "userAgent", "get").mockReturnValue(
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"
  )
  const view = render(<TotpSetup secret={secret} otpauthUri={uri} />)
  expect(view.container.querySelector("a[href]")).toHaveAttribute("href", uri)
  expect(
    screen.getByText(/Your device chooses which app opens/)
  ).toBeInTheDocument()
})

it("hides the manual setup key until revealed, then copies the same key", async () => {
  const user = userEvent.setup()
  const copy = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue()
  render(<TotpSetup secret={secret} otpauthUri={uri} />)
  expect(screen.queryByLabelText("Setup key")).toBeNull()
  expect(screen.queryByRole("button", { name: "Copy" })).toBeNull()
  await user.click(
    screen.getByRole("button", { name: "Show manual setup key" })
  )
  expect(screen.getByLabelText("Setup key")).toHaveTextContent(secret)
  await user.click(screen.getByRole("button", { name: "Copy" }))
  expect(copy).toHaveBeenCalledWith(secret)
  await user.click(
    screen.getByRole("button", { name: "Hide manual setup key" })
  )
  expect(screen.queryByLabelText("Setup key")).toBeNull()
})
