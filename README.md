# go-argonize

**Go package to facilitate the use of the [Argon2id](https://www.password-hashing.net/)** password hashing algorithm from the ["golang.org/x/crypto/argon2" package](https://pkg.go.dev/golang.org/x/crypto/argon2).

```go
go get "github.com/KEINOS/go-argon"
```

```go
func Example() {
    password := []byte("my password")

    hashedObj, err := argonize.Hash(password)
    if err != nil {
        log.Fatal(err)
    }

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
```

```go
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
```

## License, copyright and credits

- MIT, Copyright (c) 2022 KEINOS and the go-Argonize contributors.
- This Go package is strongly influenced by an article by [Alex Edwards](https://www.alexedwards.net/).
  - "[How to Hash and Verify Passwords With Argon2 in Go](https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go)"
