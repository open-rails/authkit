package core

import (
	"reflect"
	"testing"
)

// AuthKit owns profiles.users.id: host applications must not be able to choose
// it through ImportUserInput.
func TestImportUserContractKeepsAuthKitInChargeOfUserID(t *testing.T) {
	if _, ok := reflect.TypeOf(ImportUserInput{}).FieldByName("ID"); ok {
		t.Fatalf("ImportUserInput must not let host applications choose profiles.users.id")
	}
}
