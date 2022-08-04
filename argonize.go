/*
Package argonize is a wrapper for the functions of the "golang.org/x/crypto/argon2"
package to facilitate the use of the Argon2id password hashing algorithm.

- This package is strongly influenced by an article by [Alex Edwards](https://www.alexedwards.net/).
  - "[How to Hash and Verify Passwords With Argon2 in Go](https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go)"

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

// RandRead is a copy of rand.Read to ease testing.
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

// RandomBytes returns securely generated random bytes with the given length.
func RandomBytes(lenOut uint32) ([]byte, error) {
	b := make([]byte, lenOut)

	if _, err := RandRead(b); err != nil {
		return nil, errors.Wrap(err, "failed to read random bytes")
	}

	return b, nil
}
