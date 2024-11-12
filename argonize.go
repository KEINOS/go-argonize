/*
Package argonize is a wrapper for the functions of the "golang.org/x/crypto/argon2"
package to facilitate the use of the Argon2id password hashing algorithm.

* This package is strongly influenced by an article by Alex Edwards (https://www.alexedwards.net/).
  - "How to Hash and Verify Passwords With Argon2 in Go"
  - https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
*/
package argonize

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// ============================================================================
//  Public Variables
// ============================================================================

// RandRead is a copy of `crypto.rand.Read` to ease testing.
//
// It is a helper function that calls Reader.Read using io.ReadFull. The returned
// `n` and `err` values, `n` will be len of the input if `err` is nil.
//
//nolint:gochecknoglobals // export for test convenience
var RandRead = rand.Read

// ============================================================================
//  Functions
// ============================================================================

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
	if salt == nil {
		salt, _ = NewSalt(parameters.SaltLength)
	}

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

// ============================================================================
//  Type: Hashed
// ============================================================================

// Hashed holds the Argon2id hash value and its parameters.
type Hashed struct {
	Params *Params
	Salt   Salt
	Hash   []byte
}

// ----------------------------------------------------------------------------
//  Constructors of Hashed
// ----------------------------------------------------------------------------

const (
	maxInt32     = 2147483647
	lenDecChunks = 6 // Number of chunks in the encoded hash string.
)

// DecodeHashStr decodes an Argon2id formatted hash string into a Hashed object.
// Which is the value returned by Hashed.String() method.
//
// Note that the password remains hashed even if the object is decoded. Once hashed,
// the original password cannot be recovered in any case.
func DecodeHashStr(encodedHash string) (*Hashed, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != lenDecChunks {
		return nil, errors.New("invalid hash format")
	}

	var version int

	if _, err := fmt.Sscanf(vals[2],
		"v=%d", &version); err != nil {
		return nil, errors.Wrap(err, "failed to parse the version")
	}

	if version != argon2.Version {
		return nil, errors.New("incompatible version of Argon2")
	}

	params := NewParams()

	if _, err := fmt.Sscanf(vals[3],
		"m=%d,t=%d,p=%d", &params.MemoryCost, &params.Iterations, &params.Parallelism); err != nil {
		return nil, errors.Wrap(err, "missing parameters in the hash")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode salt value")
	}

	hash, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode hash value")
	}

	lenSalt := len(salt)
	lenHash := len(hash)

	// Salt length must be 8..(2^32 -1) bytes and hash length (tagLength)
	// must be 4..(2^32 -1) bytes.
	// Ref: https://en.wikipedia.org/wiki/Argon2#Algorithm
	const (
		minLenSalt = 8
		minLenHash = 4
	)

	if lenSalt < maxInt32 && lenHash < maxInt32 && lenSalt >= minLenSalt {
		params.SaltLength = uint32(lenSalt) //nolint:gosec // int overflow is checked above
		params.KeyLength = uint32(lenHash)  //nolint:gosec // int overflow is checked above

		return &Hashed{
			Params: params,
			Salt:   Salt(salt),
			Hash:   hash,
		}, nil
	}

	return nil, errors.New("hash or salt length is too long or too short")
}

// DecodeHashGob decodes gob-encoded byte slice into a Hashed object.
// The argument should be the value from Hashed.Gob() method.
//
// Note that the password remains hashed even if the object is decoded. Once hashed,
// the original password cannot be recovered in any case.
func DecodeHashGob(gobEncHash []byte) (*Hashed, error) {
	// Create a decoder and receive a value.
	dec := gob.NewDecoder(bytes.NewReader(gobEncHash))

	// Prepare the variable to store the decoded value.
	var hashedObj Hashed

	if err := dec.Decode(&hashedObj); err != nil {
		return nil, errors.Wrap(err, "failed to gob decode the hash")
	}

	return &hashedObj, nil
}

// ----------------------------------------------------------------------------
//  Methods of Hashed
// ----------------------------------------------------------------------------

// Gob returns the gob-encoded byte slice of the current Hashed object.
// This is useful when hashes are stored in the database in bytes.
func (h *Hashed) Gob() ([]byte, error) {
	var network bytes.Buffer // Stand-in for the network.

	enc := gob.NewEncoder(&network)

	err := enc.Encode(h)
	if err == nil && h.Hash == nil {
		err = errors.New("hash value is empty")
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to gob encode the hash")
	}

	return network.Bytes(), nil
}

// IsValidPassword returns true if the given password is valid.
//
// Note that the parameters must be the same as those used to generate the hash.
func (h *Hashed) IsValidPassword(password []byte) bool {
	// The same parameters are used to derive the key from the other password.
	otherHash := argon2.IDKey(
		password,
		h.Salt,
		h.Params.Iterations,
		h.Params.MemoryCost,
		h.Params.Parallelism,
		h.Params.KeyLength,
	)

	// Compare hashed passwords to ensure they are identical.
	// Note that the subtle.ConstantTimeCompare() function is used to prevent
	// timing attacks.
	return subtle.ConstantTimeCompare(h.Hash, otherHash) == 1
}

// String returns the encoded hash string using the standard encoded hash
// representation of the Argon2 algorithm.
//
// To decode to a Hashed object, use the DecodeHashStr() function.
func (h *Hashed) String() string {
	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(h.Salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(h.Hash)

	// Return a string using the standard encoded hash representation.
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.Params.MemoryCost,
		h.Params.Iterations,
		h.Params.Parallelism,
		b64Salt,
		b64Hash,
	)
}

// ============================================================================
//  Type: Params
// ============================================================================

// Params holds the parameters for the Argon2id algorithm.
type Params struct {
	// Iterations is the number of iterations or passes over the memory.
	// Defaults to 1 which is the sensible number from the Argon2's draft RFC
	// recommends[2].
	Iterations uint32
	// KeyLength is the length of the key used in Argon2.
	// Defaults to 32.
	KeyLength uint32
	// MemoryCost is the amount of memory used by the algorithm in KiB.
	// Defaults to 64 * 1024 KiB = 64 MiB. Which is the sensible number from
	// the Argon2's draft RFC recommends[2].
	MemoryCost uint32
	// SaltLength is the length of the salt used in Argon2.
	// Defaults to 16.
	SaltLength uint32
	// Parallelism is the number of threads or lanes used by the algorithm.
	// Defaults to 2.
	Parallelism uint8
}

const (
	// IterationsDefault is the default number of iterations of the parameter used by the Argon2id algorithm.
	IterationsDefault = uint32(1)
	// KeyLengthDefault is the default key length used in the Argon2id algorithm parameters.
	KeyLengthDefault = uint32(32)
	// MemoryCostDefault is the default amount of memory (KiB) used by the algorithm parameters.
	MemoryCostDefault = uint32(64 * 1024)
	// ParallelismDefault is the default number of threads used in the algorithm parameters.
	ParallelismDefault = uint8(2)
	// SaltLengthDefault is the default length of the salt used in the Argon2id algorithm parameters.
	SaltLengthDefault = uint32(16)
)

// ----------------------------------------------------------------------------
//  Constructor of Params
// ----------------------------------------------------------------------------

// NewParams returns a new Params object with default values.
func NewParams() *Params {
	p := new(Params)

	p.SetDefault()

	return p
}

// ----------------------------------------------------------------------------
//  Methods of Params
// ----------------------------------------------------------------------------

// SetDefault sets the fields to default values.
func (p *Params) SetDefault() {
	p.Iterations = IterationsDefault
	p.KeyLength = KeyLengthDefault
	p.MemoryCost = MemoryCostDefault
	p.SaltLength = SaltLengthDefault
	p.Parallelism = ParallelismDefault
}

// ============================================================================
//  Type: Salt
// ============================================================================

// Salt holds the salt value. You can add a pepper value to the salt through
// the AddPepper() method.
type Salt []byte

// ----------------------------------------------------------------------------
//  Constructor of Salt
// ----------------------------------------------------------------------------

// NewSalt returns a new Salt object with a random salt and given length.
func NewSalt(lenOut uint32) (Salt, error) {
	salt, err := RandomBytes(lenOut)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate salt")
	}

	return Salt(salt), nil
}

// ----------------------------------------------------------------------------
//  Methods of Salt
// ----------------------------------------------------------------------------

// AddPepper add/appends a pepper value to the salt.
func (s *Salt) AddPepper(pepper []byte) {
	*s = append(*s, pepper...)
}
