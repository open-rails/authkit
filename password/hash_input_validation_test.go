package password

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPHCMalformedNeverAuthenticatesOrPanics(t *testing.T) {
	for _, encoded := range []string{
		"not-a-phc-string", "", "$argon2id$",
		"$argon2id$v=19$m=8,t=0,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8,t=1,p=0$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdA$",
	} {
		t.Run(encoded, func(t *testing.T) {
			var accepted bool
			var err error
			var panicValue any
			func() {
				defer func() { panicValue = recover() }()
				accepted, err = VerifyArgon2id(encoded, "arbitrary-password")
			}()
			t.Logf("accepted=%v err=%v panic=%v", accepted, err, panicValue)
			require.Nil(t, panicValue, fmt.Sprint(panicValue))
			require.False(t, accepted, "malformed PHC must not accept arbitrary password")
			require.Error(t, err)
		})
	}
}

func TestPHCParameterAndEncodingBounds(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	sum := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	encode := func(params string) string { return "$argon2id$v=19$" + params + "$" + salt + "$" + sum }
	for _, params := range []string{
		"m=65536,t=0,p=1", "m=65536,t=1,p=0", "m=65536,t=1,p=256", "m=65536,t=1,p=17",
		"m=4294967295,t=1,p=1", "m=262145,t=1,p=1", "m=262144,t=5,p=1", "m=65536,t=11,p=1", "m=8,t=1,p=2",
		"m=65536,t=1,p=1,extra=1", "m=65536,t=1,p=1 ", "m=65536,t=1,p=+1", "m=065536,t=1,p=1",
		"t=1,m=65536,p=1", "m=65536,m=65536,p=1", "m=65536,t=1,p=1junk",
	} {
		_, _, _, err := phcDecode(encode(params))
		require.ErrorIs(t, err, ErrInvalidHash, params)
	}
	for _, encoded := range []string{
		strings.Replace(encode("m=8,t=1,p=1"), "v=19", "v=16", 1),
		"prefix" + encode("m=8,t=1,p=1"),
		"$argon2id$v=19$m=8,t=1,p=1$$" + sum,
		"$argon2id$v=19$m=8,t=1,p=1$" + salt + "$",
		"$argon2id$v=19$m=8,t=1,p=1$" + salt + "=$" + sum,
		"$argon2id$v=19$m=8,t=1,p=1$" + salt + "\n$" + sum,
		"$argon2id$v=19$m=8,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(make([]byte, 65)) + "$" + sum,
		"$argon2id$v=19$m=8,t=1,p=1$" + salt + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 65)),
		strings.Repeat("$", 257),
	} {
		_, _, _, err := phcDecode(encoded)
		require.ErrorIs(t, err, ErrInvalidHash)
	}
	// Decode-only upper-bound proof: never allocate a maximum-cost KDF in a test.
	for _, params := range []string{"m=262144,t=4,p=16", "m=65536,t=4,p=1", "m=8,t=1,p=1"} {
		require.NoError(t, ValidateHash(encode(params), "argon2id"))
	}
}

func TestSupportedLegacyHashesRemainUsable(t *testing.T) {
	pass := "legacy-password-123"
	salt := []byte("legacy-test-salt!")
	p := Params{Time: 2, Memory: 32, Threads: 2, SaltLen: uint32(len(salt)), KeyLen: 24}
	sum := argon2.IDKey([]byte(pass), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	encoded := phcEncode(p, salt, sum)
	for _, other := range []string{encoded, "", "random"} {
		require.False(t, IsBcryptHash(other))
	}
	require.NoError(t, ValidateHash(encoded, "argon2id"))
	ok, err := VerifyArgon2id(encoded, pass)
	require.NoError(t, err)
	require.True(t, ok)
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	require.NoError(t, err)
	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		encoded := prefix + string(hash[4:])
		require.True(t, IsBcryptHash(encoded))
		require.NoError(t, ValidateHash(encoded, "bcrypt"))
		require.NoError(t, ValidateHash(encoded, ""))
		ok, err := VerifyBcrypt(encoded, pass)
		require.NoError(t, err)
		require.True(t, ok)
		ok, err = VerifyBcrypt(encoded, "wrong-password")
		require.NoError(t, err)
		require.False(t, ok)
	}
	for _, encoded := range []string{
		string(hash) + "suffix", string(hash[:59]), "$2x$" + string(hash[4:]),
		"$2a$31$" + string(hash[7:]), "$2a$03$" + string(hash[7:]), "$2a$+4$" + string(hash[7:]),
		string(hash[:59]) + "!",
	} {
		require.ErrorIs(t, ValidateHash(encoded, "bcrypt"), ErrInvalidHash)
	}
	require.ErrorIs(t, ValidateHash(encoded, "unknown"), ErrInvalidHash)
}

func FuzzPHCDecodeNeverPanics(f *testing.F) {
	f.Add("$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("$argon2id$v=99$m=4294967295,t=0,p=256$$")
	f.Fuzz(func(t *testing.T, encoded string) {
		// Parse only: accepted input must still satisfy the allocation/work budget.
		p, salt, sum, err := phcDecode(encoded)
		if err != nil {
			return
		}
		require.LessOrEqual(t, len(encoded), 256)
		require.True(t, p.Threads >= 1 && p.Threads <= 16)
		require.True(t, p.Time >= 1 && p.Time <= 10)
		require.True(t, p.Memory >= 8*uint32(p.Threads) && p.Memory <= 256*1024)
		require.LessOrEqual(t, uint64(p.Memory)*uint64(p.Time), uint64(1024*1024))
		require.True(t, len(salt) >= 8 && len(salt) <= 64)
		require.True(t, len(sum) >= 16 && len(sum) <= 64)
	})
}
