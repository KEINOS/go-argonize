package argonize_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/KEINOS/go-argonize"
)

func Example() {
	// The password to be hashed.
	// Note that once hashed, passwords cannot be recovered and can only be
	// verified.
	password := []byte("my password")

	// Password hashing using the Argon2id algorithm.
	// The parameters use the settings recommended in the draft Argon2 RFC.
	// To customize the parameters, use the argonize.HashCustom() function.
	hashedObj, err := argonize.Hash(password)
	if err != nil {
		log.Fatal(err)
	}

	// Use the Hashed.String() function to obtain the hash to be stored in the
	// database as a string.
	//
	//   hashed := hashedObj.String()

	// Validate the password against the hashed password.
	if hashedObj.IsValidPassword([]byte("my password")) {
		fmt.Println("the password is valid")
	} else {
		fmt.Println("the password is invalid")
	}

	if hashedObj.IsValidPassword([]byte("wrong password")) {
		fmt.Println("the password is valid")
	} else {
		fmt.Println("the password is invalid")
	}

	// Output:
	// the password is valid
	// the password is invalid
}

func Example_custom_params() {
	password := []byte("my password")

	params := argonize.NewParams()
	fmt.Println("Default iterations:", params.Iterations)
	fmt.Println("Default key length:", params.KeyLength)
	fmt.Println("Default memory cost:", params.MemoryCost)
	fmt.Println("Default salt length:", params.SaltLength)
	fmt.Println("Default parallelism:", params.Parallelism)

	salt, err := argonize.NewSalt(params.SaltLength)
	if err != nil {
		log.Fatal(err)
	}

	salt.AddPepper([]byte("my pepper"))

	// Hash the password using the Argon2id algorithm with the custom parameters.
	hashedObj := argonize.HashCustom(password, salt, params)

	// Validate the password against the hashed password.
	if hashedObj.IsValidPassword([]byte("my password")) {
		fmt.Println("the password is valid")
	} else {
		fmt.Println("the password is invalid")
	}

	if hashedObj.IsValidPassword([]byte("wrong password")) {
		fmt.Println("the password is valid")
	} else {
		fmt.Println("the password is invalid")
	}

	// Output:
	// Default iterations: 1
	// Default key length: 32
	// Default memory cost: 65536
	// Default salt length: 16
	// Default parallelism: 2
	// the password is valid
	// the password is invalid
}

func Example_from_saved_password() {
	// Load the hashed password from a file, DB or etc.
	//nolint:gosec // hardcoded credentials as an example
	savedPasswd := "$argon2id$v=19$m=65536,t=1,p=2$iuIIXq4foOhcGUH1BjE08w$kA+XOAMls8hzWg3J1sYxkeuK/lkU4HDRBf0zchdyllY"

	// Decode the saved password to a Hashed object.
	// Note that once hashed, passwords cannot be recovered and can only be
	// verified.
	hashObj, err := argonize.DecodeHashStr(savedPasswd)
	if err != nil {
		log.Fatal(err)
	}

	// Validate the password against the hashed password.
	if hashObj.IsValidPassword([]byte("my password")) {
		fmt.Println("the password is valid")
	} else {
		fmt.Println("the password is invalid")
	}

	if hashObj.IsValidPassword([]byte("wrong password")) {
		fmt.Println("the password is valid")
	} else {
		fmt.Println("the password is invalid")
	}

	// Output:
	// the password is valid
	// the password is invalid
}

func Example_gob_encode_and_decode() {
	exitOnError := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}

	// The password to be hashed.
	password := []byte("my secret password")

	// Password hashing using the Argon2id algorithm with default parameters.
	hashedObj1, err := argonize.Hash(password)
	exitOnError(err)

	// Obtain the Hashed object as a gob encoded byte slice. Useful when hashes
	// are stored in the database in bytes. Also see the DecodeHashStr() example.
	gobEnc, err := hashedObj1.Gob()
	exitOnError(err)

	// Re-create the Hashed object from the gob encoded byte slice. Suppose the
	// gobEnc is the value stored in a database.
	hashedObj2, err := argonize.DecodeHashGob(gobEnc)
	exitOnError(err)

	// The recovered Hashed object works as a validator.
	if hashedObj2.IsValidPassword([]byte("my secret password")) {
		fmt.Println("the password is valid")
	} else {
		fmt.Println("the password is invalid")
	}

	if hashedObj2.IsValidPassword([]byte("my bad password")) {
		fmt.Println("the password is valid")
	} else {
		fmt.Println("the password is invalid")
	}

	// Output:
	// the password is valid
	// the password is invalid
}

// ----------------------------------------------------------------------------
//  DecodeHashStr()
// ----------------------------------------------------------------------------

func ExampleDecodeHashStr() {
	// The Argon2id hash string to be decoded.
	hashed := "$argon2id$v=19$m=65536,t=3,p=2$Woo1mErn1s7AHf96ewQ8Uw$D4TzIwGO4XD2buk96qAP+Ed2baMo/KbTRMqXX00wtsU"

	// Decode the standard encoded hash representation of the Argon2 algorithm
	// to a Hashed object.
	hashObj, err := argonize.DecodeHashStr(hashed)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Hash: %x\n", hashObj.Hash)
	fmt.Printf("Salt: %x\n", hashObj.Salt)
	fmt.Println("Params:")
	fmt.Println("- Iterations:", hashObj.Params.Iterations)
	fmt.Println("- Key length:", hashObj.Params.KeyLength)
	fmt.Println("- Memory cost:", hashObj.Params.MemoryCost)
	fmt.Println("- Salt length:", hashObj.Params.SaltLength)
	fmt.Println("- Parallelism:", hashObj.Params.Parallelism)

	// Print the hashed string representation of the Argon2id algorithm.
	// It should return the same string as the one passed to the DecodeHashStr()
	// function.
	fmt.Println("Stringer:", hashObj.String())

	// Output:
	// Hash: 0f84f323018ee170f66ee93deaa00ff847766da328fca6d344ca975f4d30b6c5
	// Salt: 5a8a35984ae7d6cec01dff7a7b043c53
	// Params:
	// - Iterations: 3
	// - Key length: 32
	// - Memory cost: 65536
	// - Salt length: 16
	// - Parallelism: 2
	// Stringer: $argon2id$v=19$m=65536,t=3,p=2$Woo1mErn1s7AHf96ewQ8Uw$D4TzIwGO4XD2buk96qAP+Ed2baMo/KbTRMqXX00wtsU
}

// ----------------------------------------------------------------------------
//  NewParams()
// ----------------------------------------------------------------------------

func ExampleNewParams() {
	params := argonize.NewParams()

	fmt.Println("Default iterations:", params.Iterations)
	fmt.Println("Default key length:", params.KeyLength)
	fmt.Println("Default memory cost:", params.MemoryCost)
	fmt.Println("Default salt length:", params.SaltLength)
	fmt.Println("Default parallelism:", params.Parallelism)

	// Output:
	// Default iterations: 1
	// Default key length: 32
	// Default memory cost: 65536
	// Default salt length: 16
	// Default parallelism: 2
}

// ----------------------------------------------------------------------------
//  RandomBytes()
// ----------------------------------------------------------------------------

//nolint:varnamelen // r1, r2 are short function name but leave as is here.
func ExampleRandomBytes() {
	r1, err := argonize.RandomBytes(32)
	if err != nil {
		log.Fatal(err)
	}

	r2, err := argonize.RandomBytes(32)
	if err != nil {
		log.Fatal(err)
	}

	if bytes.Equal(r1, r2) {
		log.Fatal("random bytes are not random")
	}

	fmt.Println("OK")

	// Output: OK
}

// ----------------------------------------------------------------------------
//  Salt.AddPepper()
// ----------------------------------------------------------------------------

func ExampleSalt_AddPepper() {
	salt, err := argonize.NewSalt(16)
	if err != nil {
		log.Fatal(err)
	}

	noPepper := salt[:]

	salt.AddPepper([]byte("pepper"))

	withPepper := salt[:]

	if bytes.Equal(noPepper, withPepper) {
		log.Fatal("salt and salt+pepper values should be different")
	}

	fmt.Println("OK")

	// Output: OK
}
