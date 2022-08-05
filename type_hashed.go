package argonize

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// ----------------------------------------------------------------------------
//  Type: Hashed
// ----------------------------------------------------------------------------

// Hashed holds the Argon2id hash value and its parameters.
type Hashed struct {
	Params *Params
	Salt   Salt
	Hash   []byte
}

// ----------------------------------------------------------------------------
//  Constructors
// ----------------------------------------------------------------------------

const lenDecChunks = 6 // Number of chunks in the encoded hash string.

// DecodeHashStr decodes an Argon2id formatted hash string into a Hashed object.
// Which is the value returned by Hashed.String() method.
func DecodeHashStr(encodedHash string) (*Hashed, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != lenDecChunks {
		return nil, errors.New("invalid hash format")
	}

	var version int

	if _, err := fmt.Sscanf(vals[2], "v=%d", &version); err != nil {
		return nil, errors.Wrap(err, "failed to parse the version")
	}

	if version != argon2.Version {
		return nil, errors.New("incompatible version of Argon2")
	}

	params := NewParams()

	if _, err := fmt.Sscanf(vals[3],
		"m=%d,t=%d,p=%d",
		&params.MemoryCost, &params.Iterations, &params.Parallelism,
	); err != nil {
		return nil, errors.Wrap(err, "missing parameters in the hash")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode salt value")
	}

	params.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode hash value")
	}

	params.KeyLength = uint32(len(hash))

	hashedObj := &Hashed{
		Params: params,
		Salt:   Salt(salt),
		Hash:   hash,
	}

	return hashedObj, nil
}

// DecodeHashGob decodes gob-encoded strings into Hashed objects.
// The argument should be the value from Hashed.Gob() method.
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
//  Methods
// ----------------------------------------------------------------------------

// Gob returns the gob encoded byte slice of the current Hashed object.
// This is useful when hashes are stored in the database in bytes.
func (h Hashed) Gob() ([]byte, error) {
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
func (h Hashed) String() string {
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
