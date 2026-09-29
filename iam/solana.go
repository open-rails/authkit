package iam

// SolanaNetwork is the chain Sign In With Solana signs for. The zero value
// leaves SIWS off.
type SolanaNetwork string

const (
	SolanaMainnet SolanaNetwork = "mainnet"
	SolanaTestnet SolanaNetwork = "testnet"
	SolanaDevnet  SolanaNetwork = "devnet"
)
