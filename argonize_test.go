package argonize_test

import (
	"testing"

	"github.com/KEINOS/go-argonize"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
//  DecodeHashGob()
// ----------------------------------------------------------------------------

func TestDecodeHashGob(t *testing.T) {
	t.Parallel()

	hashedObj, err := argonize.DecodeHashGob(nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to gob decode the hash")
	require.Nil(t, hashedObj, "it should be nil on error")
}

// ----------------------------------------------------------------------------
//  DecodeHashStr()
// ----------------------------------------------------------------------------

// The _DecodeHashStrBadCases is a list of test cases for DecodeHashStr().
//
//nolint:gochecknoglobals
var _DecodeHashStrBadCases = []struct {
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
	{
		"$argon2id$v=19$m=65536,t=3,p=2$Woo$D4TzIwGO4XD2buk96qAP+Ed2baMo/KbTRMqXX00wtsU",
		"hash or salt length is too long or too short",
		"salt and hash that are out of range length should be an error",
	},
}

func TestDecodeHashStr(t *testing.T) {
	t.Parallel()

	for _, tt := range _DecodeHashStrBadCases {
		hashedObj, err := argonize.DecodeHashStr(tt.encodedHash)

		require.Error(t, err, tt.errMsg)
		require.Contains(t, err.Error(), tt.msgContain, tt.errMsg)
		require.Nil(t, hashedObj, "it should be nil on error")
	}
}

// ----------------------------------------------------------------------------
//  Hash()
// ----------------------------------------------------------------------------

func TestHash(t *testing.T) {
	t.Parallel()

	hashedObj, err := argonize.Hash(nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to hash the password")
	require.Contains(t, err.Error(), "the password is empty")
	require.Nil(t, hashedObj, "it should be nil on error")
}

// ----------------------------------------------------------------------------
//  HashCustom()
// ----------------------------------------------------------------------------

// Fix issue #46: use random value for salt if salt is nil.
func TestHashCustom_fix_issue46(t *testing.T) {
	t.Parallel()

	t.Run("salt is consistent", func(t *testing.T) {
		t.Parallel()

		salt := []byte("salt")
		params := argonize.NewParams()

		hashedObj1 := argonize.HashCustom([]byte("password"), salt, params)
		hashedObj2 := argonize.HashCustom([]byte("password"), salt, params)

		require.Equal(t, hashedObj1.String(), hashedObj2.String(),
			"the hash should be consistent with the same salt")
	})

	t.Run("salt is nil", func(t *testing.T) {
		t.Parallel()

		params := argonize.NewParams()

		hashedObj1 := argonize.HashCustom([]byte("password"), nil, params)
		hashedObj2 := argonize.HashCustom([]byte("password"), nil, params)

		require.NotEqual(t, hashedObj1.String(), hashedObj2.String(),
			"it should not be consistent with nil salt")
	})
}

// ----------------------------------------------------------------------------
//  Hashed.Gob()
// ----------------------------------------------------------------------------

func TestHashed_Gob(t *testing.T) {
	t.Parallel()

	hashed := new(argonize.Hashed)
	b, err := hashed.Gob()

	require.Error(t, err)
	require.Contains(t, err.Error(), "hash value is empty")
	require.Nil(t, b, "it should be nil on error")
}

// ----------------------------------------------------------------------------
//  Hashed.IsValidPassword()
// ----------------------------------------------------------------------------

func TestHash_IsValidPassword_compatibility(t *testing.T) {
	t.Parallel()

	// Hashed password generated via PHP's Argon2id function.
	//nolint:gosec // hardcoded credentials as an example
	savedPasswd := "$argon2id$v=19$m=65536,t=4,p=1$VzYzcEdxUTlaQ2E3b3Y4cw$oDUmWEt4fynfBCNMDK/EL6jgJB2yuhaP2TBW1DOsOeU"

	hashObj, err := argonize.DecodeHashStr(savedPasswd)
	require.NoError(t, err)

	// Validate the password against the hashed password.
	require.True(t, hashObj.IsValidPassword([]byte("2Melon1Banana")))
	require.False(t, hashObj.IsValidPassword([]byte("2Apple1Mango")))
}

// ----------------------------------------------------------------------------
//  NewSalt()
// ----------------------------------------------------------------------------

//nolint:paralleltest // disable parallel since it temporarily changes the RandRead function
func TestNewSalt(t *testing.T) {
	// Backup and defer restore the random reader.
	oldRandRead := argonize.RandRead
	defer func() { argonize.RandRead = oldRandRead }()

	argonize.RandRead = func(_ []byte) (int, error) {
		return 0, errors.New("forced error")
	}

	salt, err := argonize.NewSalt(16)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to generate salt",
		"it should contain where the error is caused")
	require.Contains(t, err.Error(), "forced error",
		"it should contain the cause of the error")
	require.Zero(t, salt, "it should be zero on error")
}

// ----------------------------------------------------------------------------
//  RandomBytes()
// ----------------------------------------------------------------------------

func TestRandomBytes_zero_length_arg(t *testing.T) {
	t.Parallel()

	randVal, err := argonize.RandomBytes(0)

	require.NoError(t, err, "zero length should not return an error")
	require.Empty(t, randVal, "zero length should return an empty slice")
}
