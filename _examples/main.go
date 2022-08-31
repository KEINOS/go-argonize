package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/KEINOS/go-argonize"
	"github.com/pkg/errors"
)

func main() {
	argIn := os.Args
	if len(argIn) == 1 {
		fmt.Fprintln(os.Stderr, "Please provide a password to hash")
		os.Exit(1)
	}

	password := strings.TrimSpace(strings.Join(argIn[1:], " "))

	// Password hashing
	hashedObj, err := argonize.Hash([]byte(password))
	if err != nil {
		fmt.Fprintln(os.Stderr, errors.Wrap(err, "failed to hash password"))
		os.Exit(1)
	}

	//nolint:forbidigo // allow use of fmt
	fmt.Println(hashedObj.String())
}
