/*
===============================================================================
This Go application takes a password and an optional salt as arguments and
outputs the hashed password using the Argon2id algorithm.

The parameters are: -t 1 -m 16 -p 2 -l 32
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

func main() {
	argLen := len(os.Args)
	if argLen == 1 {
		exitOnError(errors.New("missing args: Please provide a password to hash"))
	}

	param := argonize.NewParams() // Default parameters

	salt, err := argonize.NewSalt(param.SaltLength)
	exitOnError(errors.Wrap(err, "failed to generate salt"))

	password := strings.TrimSpace(os.Args[1])

	if argLen >= 3 {
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
