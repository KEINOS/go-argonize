/*
===============================================================================
This Go application takes a password and an optional salt as arguments and
outputs the hashed password using the Argon2id algorithm.

The parameters follow RFC 9106 SECOND RECOMMENDED:
  - t (passes) = 3
  - m (memory)  = 65536 KiB (64 MiB)
  - p (parallel) = 4
  - l (tag) = 32 bytes

===============================================================================
*/
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/KEINOS/go-argonize"
	"github.com/pkg/errors"
)

const (
	// minArgsForSalt is the minimum number of command line arguments required
	// so that the second argument can be interpreted as a user-provided salt.
	minArgsForSalt = 3
)

func main() {
	argLen := len(os.Args)
	if argLen == 1 {
		exitOnError(errors.New("missing args: Please provide a password to hash"))
	}

	param := argonize.NewParams() // Default parameters

	salt, err := argonize.NewSalt(param.SaltLength)
	exitOnError(errors.Wrap(err, "failed to generate salt"))

	password := strings.TrimSpace(os.Args[1])

	if argLen >= minArgsForSalt {
		salt = []byte(strings.TrimSpace(os.Args[2]))
	}

	// Password hashing
	hashedObj := argonize.HashCustom([]byte(password), salt, param)

	//nolint:forbidigo // allow use of fmt
	fmt.Println(hashedObj.String())
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
