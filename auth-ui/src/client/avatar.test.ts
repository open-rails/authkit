import { expect, it } from "vitest"

import { avatarURL } from "./avatar.ts"

it("reads the host's picture from public metadata", () => {
  const user = {
    public_metadata: {
      avatar: "https://cdn.example/a.png",
      photo: "/p.webp",
      bad: 7,
    },
  }
  expect(avatarURL(user)).toBe("https://cdn.example/a.png")
  expect(avatarURL(user, "photo")).toBe("/p.webp")
  expect(avatarURL(user, "bad")).toBeNull()
  expect(avatarURL(user, "missing")).toBeNull()
  expect(avatarURL({ public_metadata: { avatar: "" } })).toBeNull()
  expect(avatarURL({ public_metadata: {} })).toBeNull()
  expect(avatarURL(null)).toBeNull()
})
