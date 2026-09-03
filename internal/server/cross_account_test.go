package server

import (
	"testing"
)

func TestCrossAccountFlow(t *testing.T) {
	t.Run("detects cross-account cookies and mutates identity", func(t *testing.T) {
		// Setup
		cc := CredentialContext{
			Cookies: []*http.Cookie{
				{Name: "cross_access_account_number", Value: "123"},
			},
		}
		
		// Mock Services
		im := IdentityMutator{}
		rbac := RBACService{}

		// Imitate RBAC Check
		allowed, err := rbac.VerifyCrossAccountRequest("allowed-account", "")
		if err != nil || !allowed {
			t.Fatalf("RBAC check failed unexpectedly: %v", err)
		}

		// Mutate Identity
		im.MutateIdentity(&cc)

		// Assertions
		if !cc.CrossAccess {
			t.Error("expected cross account access to be true")
		}
		if cc.IsOrgAdmin {
			t.Error("expected is org admin to be false")
		}
		if cc.EmployeeAccountNumber != "original-account" {
			t.Error("expected original account number to be preserved")
		}
	})
}