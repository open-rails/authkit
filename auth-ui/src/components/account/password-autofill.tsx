import { useUser } from "../../react/context.ts"

// A password manager still needs the login identifier when the person does
// not have to type it again. Use a real account credential, never its display
// name or internal ID. CSS hiding retains a normal autofill-capable text input.
export function PasswordUsername() {
  const { user } = useUser()
  const username = [user?.email, user?.username, user?.phone_number]
    .find((value) => value?.trim())
    ?.trim()
  if (!username) return null
  return (
    <input
      type="text"
      name="username"
      autoComplete="username"
      value={username}
      readOnly
      tabIndex={-1}
      aria-hidden="true"
      className="hidden"
    />
  )
}
