// @vitest-environment jsdom
import "../test/dom.ts"

import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it } from "vitest"

import { AuthUiProvider } from "../provider.tsx"
import { AuthUiRoot } from "../scope.tsx"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogTitle,
} from "./alert-dialog.tsx"
import { Badge } from "./badge.tsx"
import { Button } from "./button.tsx"
import { Card, CardContent, CardHeader, CardTitle } from "./card.tsx"
import { Dialog, DialogContent, DialogTitle, DialogTrigger } from "./dialog.tsx"
import { Field, FieldError } from "./field.tsx"
import { Input } from "./input.tsx"
import { InputOTP, InputOTPGroup, InputOTPSlot } from "./input-otp.tsx"
import { Label } from "./label.tsx"
import { RadioGroup, RadioGroupItem } from "./radio-group.tsx"
import { Separator } from "./separator.tsx"
import { Spinner } from "./spinner.tsx"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./tabs.tsx"

describe("primitives", () => {
  it("render inside a themed root", () => {
    render(
      <AuthUiProvider
        appearance={{
          theme: "dark",
          variables: { primary: "red", radius: "4px" },
        }}
      >
        <AuthUiRoot data-testid="root">
          <Card>
            <CardHeader>
              <CardTitle>Title</CardTitle>
            </CardHeader>
            <CardContent>
              <Field>
                <Label htmlFor="email">Email</Label>
                <Input id="email" aria-invalid />
                <FieldError>Bad email</FieldError>
                <FieldError />
              </Field>
              <Tabs defaultValue="a">
                <TabsList>
                  <TabsTrigger value="a">A</TabsTrigger>
                  <TabsTrigger value="b">B</TabsTrigger>
                </TabsList>
                <TabsContent value="a">Panel A</TabsContent>
              </Tabs>
              <RadioGroup defaultValue="sms">
                <RadioGroupItem value="sms" aria-label="sms" />
                <RadioGroupItem value="email" aria-label="email" />
              </RadioGroup>
              <InputOTP maxLength={6}>
                <InputOTPGroup>
                  {[0, 1, 2, 3, 4, 5].map((i) => (
                    <InputOTPSlot key={i} index={i} />
                  ))}
                </InputOTPGroup>
              </InputOTP>
              <Separator />
              <Badge>New</Badge>
              <Spinner />
              <Button>Submit</Button>
            </CardContent>
          </Card>
        </AuthUiRoot>
      </AuthUiProvider>
    )

    const root = screen.getByTestId("root")
    expect(root).toHaveClass("authui")
    expect(root).toHaveAttribute("data-authui-theme", "dark")
    expect(root.style.getPropertyValue("--authui-primary")).toBe("red")
    expect(root.style.getPropertyValue("--authui-radius")).toBe("4px")
    expect(screen.getByRole("button", { name: "Submit" })).toBeInTheDocument()
    expect(screen.getByLabelText("Email")).toHaveAttribute(
      "aria-invalid",
      "true"
    )
    expect(screen.getAllByRole("alert")).toHaveLength(1)
    expect(screen.getByRole("tab", { name: "A" })).toBeInTheDocument()
    expect(screen.getAllByRole("radio")).toHaveLength(2)
    expect(
      screen.getByRole("status", { name: "Loading..." })
    ).toBeInTheDocument()
  })

  it("portals dialogs into their own styling root with localized chrome", async () => {
    render(
      <AuthUiProvider
        appearance={{ theme: "inherit" }}
        messages={{ common: { close: "Schließen" } }}
      >
        <Dialog>
          <DialogTrigger>Open</DialogTrigger>
          <DialogContent>
            <DialogTitle>Sign in</DialogTitle>
          </DialogContent>
        </Dialog>
      </AuthUiProvider>
    )
    await userEvent.click(screen.getByRole("button", { name: "Open" }))
    const dialog = await screen.findByRole("dialog", { name: "Sign in" })
    const portal = dialog.closest('[data-slot="dialog-portal"]')
    expect(portal).toHaveClass("authui")
    expect(portal).toHaveAttribute("data-authui-theme", "inherit")
    expect(
      screen.getByRole("button", { name: "Schließen" })
    ).toBeInTheDocument()
  })

  it("lets className win Tailwind conflicts over variant classes", () => {
    render(<Button className="h-10 bg-secondary px-2">Go</Button>)
    const cls = screen.getByRole("button", { name: "Go" }).className.split(" ")
    expect(cls).toEqual(
      expect.arrayContaining(["h-10", "bg-secondary", "px-2"])
    )
    expect(cls).toContain("hover:bg-primary-solid/80")
    expect(cls).not.toContain("h-9")
    expect(cls).not.toContain("px-2.5")
    expect(cls).not.toContain("bg-primary-solid")
  })

  it("renders alert dialogs in a scoped portal", () => {
    render(
      <AlertDialog open>
        <AlertDialogContent>
          <AlertDialogTitle>Delete?</AlertDialogTitle>
          <AlertDialogCancel>No</AlertDialogCancel>
          <AlertDialogAction>Yes</AlertDialogAction>
        </AlertDialogContent>
      </AlertDialog>
    )
    const dialog = screen.getByRole("alertdialog", { name: "Delete?" })
    const portal = dialog.closest('[data-slot="alert-dialog-portal"]')
    expect(portal).toHaveClass("authui")
    expect(portal).toHaveAttribute("data-authui-theme", "auto")
  })
})
