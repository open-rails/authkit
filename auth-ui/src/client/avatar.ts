// AuthKit stores no picture of its own: a host keeps one in a user's public
// metadata. avatarURL reads it from a profile or public user, under key
// ("avatar" unless the host chose another), or null.
export const avatarURL = (
  user: { public_metadata?: Record<string, unknown> } | null | undefined,
  key = "avatar"
): string | null => {
  const value = user?.public_metadata?.[key]
  return typeof value === "string" && value !== "" ? value : null
}
