// GET /me/permissions answers the concrete permissions a role expands to, so
// holding one is set membership.
export const hasPermission = (
  permissions: readonly string[] | null | undefined,
  required: string
): boolean => !!permissions && permissions.includes(required)
