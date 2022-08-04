package argonize

import "github.com/pkg/errors"

// ----------------------------------------------------------------------------
//  Type: Salt
// ----------------------------------------------------------------------------

// Salt holds the salt value. You can add a pepper value to the salt through
// the AddPepper() method.
type Salt []byte

// ----------------------------------------------------------------------------
//  Constructor
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
//  Methods
// ----------------------------------------------------------------------------

// AddPepper add/appends a pepper value to the salt.
func (s *Salt) AddPepper(pepper []byte) {
	*s = append(*s, pepper...)
}
