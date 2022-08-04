package argonize

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
//  DecodeHashGob()
// ----------------------------------------------------------------------------

func TestDecodeHashGob(t *testing.T) {
	hashedObj, err := DecodeHashGob(nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to gob decode the hash")
	require.Nil(t, hashedObj, "it should be nil on error")
}

// ----------------------------------------------------------------------------
//  DecodeHashStr()
// ----------------------------------------------------------------------------

// DecodeHashStrBadCase is a list of test cases for DecodeHashStr().
var DecodeHashStrBadCase = []struct {
	encodedHash string
	msgContain  string
	errMsg      string
}{
	{
		"argon2id;v=19;m=65536,t=3,p=1;c29tZS1hc3NldA==;c29tZS1hc3NldA==",
		"invalid hash format",
		"missing chunks should be an error",
	},
	{
		"$argon2id$v=myversion$m=65536,t=3,p=2$Woo1mErn1s7AHf96ewQ8Uw$D4TzIwGO4XD2buk96qAP+Ed2baMo/KbTRMqXX00wtsU",
		"failed to parse the version",
		"invalid version should be an error",
	},
	{
		"$argon2id$v=999$m=65536,t=3,p=2$Woo1mErn1s7AHf96ewQ8Uw$D4TzIwGO4XD2buk96qAP+Ed2baMo/KbTRMqXX00wtsU",
		"incompatible version of Argon2",
		"incompatible version should be an error",
	},
	{
		"$argon2id$v=19$m=65536,t=mytime,p=2$Woo1mErn1s7AHf96ewQ8Uw$D4TzIwGO4XD2buk96qAP+Ed2baMo/KbTRMqXX00wtsU",
		"missing parameters in the hash",
		"missing parameters or malformed should be an error",
	},
	{
		"$argon2id$v=19$m=65536,t=3,p=2$%%BADSALT%%$D4TzIwGO4XD2buk96qAP+Ed2baMo/KbTRMqXX00wtsU",
		"failed to decode salt value",
		"malformed salt should be an error",
	},
	{
		"$argon2id$v=19$m=65536,t=3,p=2$Woo1mErn1s7AHf96ewQ8Uw$D4TzIwGO4XD2buk96qAP+Ed2baMo/%%BADHASH%%",
		"failed to decode hash value",
		"malformed salt should be an error",
	},
}

func TestDecodeHashStr(t *testing.T) {
	for _, tt := range DecodeHashStrBadCase {
		hashedObj, err := DecodeHashStr(tt.encodedHash)

		require.Error(t, err, tt.errMsg)
		require.Contains(t, err.Error(), tt.msgContain, tt.errMsg)
		require.Nil(t, hashedObj, "it should be nil on error")
	}
}

// ----------------------------------------------------------------------------
//  Hash()
// ----------------------------------------------------------------------------

func TestHash(t *testing.T) {
	hashedObj, err := Hash(nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to hash the password")
	require.Contains(t, err.Error(), "the password is empty")
	require.Nil(t, hashedObj, "it should be nil on error")
}

// ----------------------------------------------------------------------------
//  Hashed.Gob()
// ----------------------------------------------------------------------------

func TestHashed_Gob(t *testing.T) {
	hashed := Hashed{}

	b, err := hashed.Gob()

	require.Error(t, err)
	require.Contains(t, err.Error(), "hash value is empty")
	require.Nil(t, b, "it should be nil on error")
}

// ----------------------------------------------------------------------------
//  NewSalt()
// ----------------------------------------------------------------------------

func TestNewSalt(t *testing.T) {
	// Backup and defer restore the random reader.
	oldRandRead := RandRead
	defer func() { RandRead = oldRandRead }()

	RandRead = func(b []byte) (n int, err error) {
		return 0, errors.New("forced error")
	}

	salt, err := NewSalt(16)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to generate salt",
		"it should contain where the error is caused")
	require.Contains(t, err.Error(), "forced error",
		"it should contain the cause of the error")
	require.Zero(t, salt, "it should be zero on error")
}
