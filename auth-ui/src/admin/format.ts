export const dateTime = (
  value: string | null | undefined,
  language?: string
) =>
  value
    ? new Date(value).toLocaleString(language, {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : ""
