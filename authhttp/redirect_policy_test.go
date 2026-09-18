package authhttp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeReturnTo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "/"},
		{name: "normal path", in: "/subscribe", want: "/subscribe"},
		{name: "path query", in: "/subscribe?plan=pro&coupon=AK", want: "/subscribe?plan=pro&coupon=AK"},
		{name: "absolute", in: "https://evil.example/subscribe", want: "/"},
		{name: "scheme relative", in: "//evil.example/subscribe", want: "/"},
		{name: "scheme text", in: "javascript:alert(1)", want: "/"},
		{name: "backslash", in: `/\evil`, want: "/"},
		{name: "crlf", in: "/ok\r\nLocation:https://evil.example", want: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, sanitizeReturnTo(tt.in))
		})
	}
}
