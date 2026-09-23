// Email/phone identifier handling without a phone-metadata dependency: numbers
// without a country code get the host's default country calling code.

// prettier-ignore
const CALLING_CODES: Record<string, string> = {
  US: "1", CA: "1", PR: "1", GB: "44", IE: "353", AU: "61", NZ: "64",
  DE: "49", AT: "43", CH: "41", FR: "33", BE: "32", NL: "31", LU: "352",
  ES: "34", PT: "351", IT: "39", GR: "30", SE: "46", NO: "47", DK: "45",
  FI: "358", IS: "354", PL: "48", CZ: "420", SK: "421", HU: "36", RO: "40",
  BG: "359", HR: "385", SI: "386", RS: "381", UA: "380", EE: "372",
  LV: "371", LT: "370", TR: "90", IL: "972", AE: "971", SA: "966",
  EG: "20", ZA: "27", NG: "234", KE: "254", MA: "212", IN: "91",
  PK: "92", BD: "880", LK: "94", CN: "86", HK: "852", TW: "886",
  JP: "81", KR: "82", SG: "65", MY: "60", TH: "66", VN: "84", PH: "63",
  ID: "62", MX: "52", BR: "55", AR: "54", CL: "56", CO: "57", PE: "51",
  VE: "58", UY: "598", RU: "7", KZ: "7",
}

// NANP numbers keep their leading digits; elsewhere a national trunk 0 drops.
const KEEPS_TRUNK_ZERO = new Set(["IT"])

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const PHONE_CHARS = /^\+?[\d\s().-]+$/

export type IdentifierKind = "email" | "phone" | "other"

export function identifierKind(value: string): IdentifierKind {
  const v = value.trim()
  if (v.includes("@")) return "email"
  if (PHONE_CHARS.test(v) && v.replace(/\D/g, "").length >= 6) return "phone"
  return "other"
}

export const isEmail = (value: string) => EMAIL.test(value.trim())

// E.164 for phone-looking input, trimmed input otherwise.
export function normalizeIdentifier(
  value: string,
  defaultCountry?: string
): string {
  const v = value.trim()
  if (identifierKind(v) !== "phone") return v
  const digits = v.replace(/\D/g, "")
  if (v.startsWith("+")) return `+${digits}`
  if (digits.startsWith("00")) return `+${digits.slice(2)}`
  const country = defaultCountry?.toUpperCase()
  const code = country ? CALLING_CODES[country] : undefined
  if (!code) return `+${digits}`
  if (code === "1" && digits.length === 11 && digits.startsWith("1"))
    return `+${digits}`
  const national =
    country && !KEEPS_TRUNK_ZERO.has(country)
      ? digits.replace(/^0+/, "")
      : digits
  return `+${code}${national}`
}

export const isE164 = (value: string) => /^\+[1-9]\d{6,14}$/.test(value)
