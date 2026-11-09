package smtp

import (
	"strings"
	"testing"

	"github.com/open-rails/authkit/iam"
)

func TestDeviceApprovalUsesItsOwnCopy(t *testing.T) {
	c, err := emailTemplate("Example", iam.EmailMessage{Kind: iam.MessageVerification, Purpose: iam.PurposeDeviceKeyEnrollment, Code: "482916"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Subject, "Approve a sign-in device") || strings.Contains(c.Text, "Use this code to sign in") {
		t.Fatal("device enrollment is described as a sign-in")
	}
	if !strings.Contains(c.HTML, "<h1") || !strings.Contains(c.Text, "request a new code") {
		t.Fatal("missing event heading or expiry recovery")
	}
}

func TestOptionalLinkDoesNotRejectACodeMessage(t *testing.T) {
	c, err := emailTemplate("Example", iam.EmailMessage{Kind: iam.MessageVerification, Code: "482916", Link: "/verify-registration?token=sample"})
	if err != nil || !strings.Contains(c.Text, "482916") {
		t.Fatalf("code message rejected: %v", err)
	}
}
