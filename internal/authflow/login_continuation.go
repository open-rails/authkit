package authflow

// LoginChallengeInput supplies the second proof; clients never supply AMR or
// first-factor provenance. Backup codes are independently stored recovery keys.
type LoginChallengeInput struct {
	UserID     string
	Challenge  string
	FactorID   string
	Code       string
	BackupCode bool
	UserAgent  string
	IP         string
}
