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
//  Constants
// ============================================================================
// Extracted to avoid magic-number linter warnings and to document intent.

const (
	// Maximum value for int32 to avoid overflow.
	maxInt32 = 2147483647
	// Number of chunks in the encoded hash string.
	lenDecChunks = 6
)

// FIRST RECOMMENDED (RFC 9106) parameter presets.
// Less iteration but more memory.
const (
	RFCFirstIterations  = 1
	RFCFirstKeyLength   = 32
	RFCFirstMemoryKiB   = 2 * 1024 * 1024 // 2 GiB in KiB
	RFCFirstSaltLength  = 16
	RFCFirstParallelism = 4
)

// SECOND RECOMMENDED (RFC 9106) parameter presets.
// Default. More iteration but less memory.
const (
	RFCSecondIterations  = 3
	RFCSecondKeyLength   = 32
	RFCSecondMemoryKiB   = 64 * 1024 // 64 MiB in KiB
	RFCSecondSaltLength  = 16
	RFCSecondParallelism = 4
)

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
//
// It is a cryptographically secure random number generated from `crypto.rand`
// package.
// If it is determined that a cryptographically secure number cannot be generated,
// an error is returned. Also note that if lenOut is zero, an empty byte slice
// is returned with no error.
func RandomBytes(lenOut uint32) ([]byte, error) {
	bytesOut := make([]byte, lenOut)

	_, err := RandRead(bytesOut)
	if err != nil {
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

	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse the version")
	}

	if version != argon2.Version {
		return nil, errors.New("incompatible version of Argon2")
	}

	params := NewParams()

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d",
		&params.MemoryCost, &params.Iterations, &params.Parallelism)
	if err != nil {
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

	// Check for integer overflow and minimum length (gosec)
	if lenSalt > maxInt32 || lenHash > maxInt32 || lenSalt < minLenSalt {
		return nil, errors.New("hash or salt length is too long or too short")
	}

	params.SaltLength = uint32(lenSalt)
	params.KeyLength = uint32(lenHash)

	return &Hashed{
		Params: params,
		Salt:   Salt(salt),
		Hash:   hash,
	}, nil
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

	err := dec.Decode(&hashedObj)
	if err != nil {
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
	// Default is 3 to follow RFC 9106 SECOND RECOMMENDED (t=3).
	Iterations uint32
	// KeyLength is the length of the key used in Argon2.
	// Defaults to 32.
	KeyLength uint32
	// MemoryCost is the amount of memory used by the algorithm in KiB.
	// Default is 64 MiB = 64 * 1024 KiB to follow RFC 9106 SECOND RECOMMENDED (m=64 MiB).
	MemoryCost uint32
	// SaltLength is the length of the salt used in Argon2.
	// Defaults to 16.
	SaltLength uint32
	// Parallelism is the number of threads or lanes used by the algorithm.
	// Default is 4 to follow RFC 9106 SECOND RECOMMENDED (p=4).
	Parallelism uint8
}

// ----------------------------------------------------------------------------
//  Presets (RFC 9106)
// ----------------------------------------------------------------------------

// RFC9106SecondRecommended contains a preset Params configured to follow
// the RFC 9106 "SECOND RECOMMENDED" settings for Argon2id.
//
// This preset is the default configuration.
//
// Fields:
//   - Iterations:  number of passes over the memory (t). Default: 3.
//   - KeyLength:   output tag length in bytes (key length). Default: 32 bytes (256 bits).
//   - MemoryCost:  memory size in KiB (m). Default: 64 MiB = 64 * 1024 KiB.
//   - SaltLength:  salt length in bytes. Default: 16 bytes (128 bits).
//   - Parallelism: number of lanes/threads (p). Default: 4.
//
// RFC9106SecondRecommended contains a preset Params configured to follow
// the RFC 9106 "SECOND RECOMMENDED" settings for Argon2id.
//
// The variable is exported on purpose to provide a reusable preset. Disable
// the gochecknoglobals linter for this intentional global.
//
//nolint:gochecknoglobals // exported preset is intentional
var RFC9106SecondRecommended = &Params{
	Iterations:  RFCSecondIterations,
	KeyLength:   RFCSecondKeyLength,
	MemoryCost:  RFCSecondMemoryKiB,
	SaltLength:  RFCSecondSaltLength,
	Parallelism: RFCSecondParallelism,
}

// RFC9106FirstRecommended contains a preset Params configured to follow
// the RFC 9106 "FIRST RECOMMENDED" settings for Argon2id.
//
// Per RFC 9106 Section 4 the FIRST RECOMMENDED option is:
//   - t = 1 (passes)
//   - p = 4 (lanes / parallelism)
//   - m = 2^21 kibibytes = 2 GiB = 2 * 1024 * 1024 KiB = 2,097,152 KiB
//   - salt length = 128 bits (16 bytes)
//   - tag/key length = 256 bits (32 bytes)
//
// RFC9106FirstRecommended contains a preset Params configured to follow
// the RFC 9106 "FIRST RECOMMENDED" settings for Argon2id.
//
// The variable is exported on purpose to provide a reusable preset. Disable
// the gochecknoglobals linter for this intentional global.
//
//nolint:gochecknoglobals // exported preset is intentional
var RFC9106FirstRecommended = &Params{
	Iterations:  RFCFirstIterations,
	KeyLength:   RFCFirstKeyLength,
	MemoryCost:  RFCFirstMemoryKiB, // 2 GiB in KiB
	SaltLength:  RFCFirstSaltLength,
	Parallelism: RFCFirstParallelism,
}

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
	// Set defaults from the RFC9106 second recommended preset.
	p.Iterations = RFC9106SecondRecommended.Iterations
	p.KeyLength = RFC9106SecondRecommended.KeyLength
	p.MemoryCost = RFC9106SecondRecommended.MemoryCost
	p.SaltLength = RFC9106SecondRecommended.SaltLength
	p.Parallelism = RFC9106SecondRecommended.Parallelism
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
//
// Note that if lenOut is zero, an empty byte slice is returned with no error.
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
