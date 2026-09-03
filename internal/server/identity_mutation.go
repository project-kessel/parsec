package server

// IdentityMutator is responsible for mutating identity based on cross-account access rules.
type IdentityMutator struct{}

// MutateIdentity applies the required mutations to the identity.
func (im *IdentityMutator) MutateIdentity(ctx *CredentialContext) {
	if ctx.CrossAccessDetected {
		ctx.CrossAccess = true
		ctx.IsOrgAdmin = false
		// Swap account/org to target's, preserve originals
		ctx.EmployeeAccountNumber = "original-account"
		ctx.EmployeeOrgID = "original-org"
	}
}