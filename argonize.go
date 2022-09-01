/*
Package argonize is a wrapper for the functions of the "golang.org/x/crypto/argon2"
package to facilitate the use of the Argon2id password hashing algorithm.

* This package is strongly influenced by an article by Alex Edwards (https://www.alexedwards.net/).
  - "How to Hash and Verify Passwords With Argon2 in Go"
  - https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
*/
package argonize

import (
	"crypto/rand"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// ----------------------------------------------------------------------------
//  Public Variables
// ----------------------------------------------------------------------------

// RandRead is a copy of `crypto.rand.Read` to ease testing.
// It is a helper function that calls Reader.Read using io.ReadFull.
// On return, n == len(b) if and only if err == nil.
//
//nolint:gochecknoglobals // export for test convenience
var RandRead = rand.Read

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

// Hash returns a Hashed object from the password using the Argon2id algorithm.
//
// Note that this function, by its nature, consumes memory and CPU.
func Hash(password []byte) (*Hashed, error) {
	param := NewParams()

	salt, err := NewSalt(param.SaltLength)
	if err == nil && password == nil {
		err = errors.New("the password is empty")
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to hash the password")
	}

	hashed := HashCustom(password, salt, param)

	return hashed, nil
}

// HashCustom returns a Hashed object from the password using the Argon2id algorithm.
//
// Similar to the Hash() function, but allows you to specify the algorithm parameters.
func HashCustom(password []byte, salt []byte, parameters *Params) *Hashed {
	hashedPass := argon2.IDKey(
		password,
		salt,
		parameters.Iterations,
		parameters.MemoryCost,
		parameters.Parallelism,
		parameters.KeyLength,
	)

	return &Hashed{
		Params: parameters,
		Salt:   salt,
		Hash:   hashedPass,
	}
}

// RandomBytes returns a random number of byte slice with the given length.
// It is a cryptographically secure random number generated from `crypto.rand`
// package.
//
// If it is determined that a cryptographically secure number cannot be generated,
// an error is returned. Also note that if lenOut is zero, an empty byte slice
// is returned with no error.
func RandomBytes(lenOut uint32) ([]byte, error) {
	bytesOut := make([]byte, lenOut)

	if _, err := RandRead(bytesOut); err != nil {
		return nil, errors.Wrap(err, "failed to read random bytes")
	}

	return bytesOut, nil
}
