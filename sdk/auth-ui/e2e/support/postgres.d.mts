export function startPostgres(): Promise<{ name: string; dsn: string }>
export function stopPostgres(name: string | undefined): void
