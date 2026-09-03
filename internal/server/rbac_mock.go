package server

import (
	"errors"
	"fmt"
)

// RBACService is a mock service to illustrate RBAC checks for cross-account access.
type RBACService struct{}

// VerifyCrossAccountRequest verifies if the cross-account request is allowed.
func (r *RBACService) VerifyCrossAccountRequest(accountNumber, orgID string) (bool, error) {
	// Simulated RBAC check logic
	if accountNumber == "allowed-account" || orgID == "allowed-org" {
		return true, nil
	}
	return false, errors.New("RBAC check failed")
}

// Example usage in code:
func exampleRBACIntegration() {
	rbacService := &RBACService{}
	allowed, err := rbacService.VerifyCrossAccountRequest("example-account", "example-org")
	if err != nil {
		fmt.Println("Access denied:", err)
	} else if allowed {
		fmt.Println("Access granted.")
	} else {
		fmt.Println("Access denied by RBAC.")
	}
}