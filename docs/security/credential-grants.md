# Credential and recovery grants

Password changes, administrative password replacement, successful password reset,
and changes to an account's recovery email or phone invalidate outstanding
password-reset grants. These operations use a durable per-account credential
version. The password, version and session revocations commit together.

Reset grants contain the account UUID, credential version, recovery channel and
contact as observed at issuance. Completion checks the current version and contact
while holding the account row lock. Completing one reset invalidates sibling
reset grants. Grants issued before versioning fail closed after upgrade.

Provider-link continuations require the initiating session to remain live and
fresh at completion. Linking and session revocation serialize on the initiating
session row; a revoked continuation cannot become a new login.
