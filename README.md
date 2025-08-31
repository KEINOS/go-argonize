<!-- markdownlint-disable-file MD041 -->
# go-argonize

[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/KEINOS/go-argonize)](https://github.com/KEINOS/go-argonize/blob/main/go.mod#L3 "Supported versions")[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-argonize.svg)](https://pkg.go.dev/github.com/KEINOS/go-argonize/ "View document")

**Go package to facilitate the use of the [Argon2id](https://www.password-hashing.net/)** password hashing algorithm from the ["crypto/argon2" package](https://pkg.go.dev/golang.org/x/crypto/argon2). This package is tested compatibilities with PHP, Python and C implementations.

> [!NOTE]
> As of v1.6.0, the library defaults use the `RFC 9106 SECOND RECOMMENDED` parameters (Argon2id, t=3, m=64 MiB, p=4, salt=16 bytes, key=32 bytes).
>
> - For details see issue [#69](https://github.com/KEINOS/go-argonize/issues/69)

## Usage

```sh
# Install the module
go get "github.com/KEINOS/go-argonize"
```

```go
// Import the package
import "github.com/KEINOS/go-argonize"
```

### Basic Example

```go
func Example_basic() {
    // Your strong and unpredictable password
    password := []byte("my password")

    // Password-hash your password. By default it uses RFC 9106 SECOND RECOMMENDED
    // parameters.
    //
    // Note that even the same password `Hash` will produce different hashes due
    // to the cryptographically random SALT is used. If you need a static output,
    // use HashCustom.
    hashedObj, err := argonize.Hash(password)
    if err != nil {
        log.Fatal(err)
    }

    // View the hashed password
    fmt.Println("Passwd to save:", hashedObj.String())

    // Verify password (golden case)
    if hashedObj.IsValidPassword([]byte("my password")) {
        fmt.Println("the password is valid")
    } else {
        fmt.Println("the password is invalid")
    }

    // Verify password (wrong case)
    if hashedObj.IsValidPassword([]byte("wrong password")) {
        fmt.Println("the password is valid")
    } else {
        fmt.Println("the password is invalid")
    }
    //
    // Output:
    // Passwd to save: $argon2id$v=19$m=65536,t=3,p=4$ek6ZYdlRm2D5AsGV98TWKA$QAIDZEdIgwohrNX678mHc448LOmD7jGR4BGw/9YMMVU
    // the password is valid
    // the password is invalid
}
```

### Example to use a saved hashed password

```go
func Example_from_saved_password() {
    // Load the hashed password from a file, DB or etc.
    // Note that once hashed, passwords cannot be recovered and can only be
    // used to verify.
    savedPasswd := "$argon2id$v=19$m=65536,t=1,p=2$iuIIXq4foOhcGUH1BjE08w$kA+XOAMls8hzWg3J1sYxkeuK/lkU4HDRBf0zchdyllY"

    // Decode the saved password to an `argonize.Hashed` object.
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
    //
    // Output:
    // the password is valid
    // the password is invalid
}
```

### Example to use RFC 9106 FIRST RECOMMENDED preset

By default, the library uses the RFC 9106 SECOND RECOMMENDED parameters (`argonize.RFC9106SecondRecommended` preset).

This example uses the RFC 9106 FIRST RECOMMENDED preset for hashing. Which uses less iteration but requires more memory.

```go
func Example_hashcustom_firstrecommended() {
    // Your strong and unpredictable password
    password := []byte("my password")

    // Use the RFC 9106 FIRST RECOMMENDED preset for hashing.
    // Note that this preset requires more memory than the default
    // parameters.
    params := argonize.RFC9106FirstRecommended

    // Generate a salt with the preset's salt length.
    //
    // HashCustom requires a random salt to prevent rainbow table attacks and to
    // ensure that users with the same password cannot be distinguished.
    // For consistency during testing, use a fixed salt value.
    salt, err := argonize.NewSalt(params.SaltLength)
    if err != nil {
      log.Fatal(err)
    }

    // Hash using the preset parameters.
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
    //
    // Output:
    // the password is valid
    // the password is invalid
}
```

### Example with user-defined parameters

This example shows how to tweak parameters starting from defaults and use
`argonize.HashCustom` with user-defined `Params`.

```go
func Example_custom_user_defined_params() {
    password := []byte("my password")

    // Start from defaults and tweak values for this example.
    params := argonize.NewParams()
    params.Iterations = 2
    params.KeyLength = 32
    params.MemoryCost = 32 * 1024 // 32 MiB in KiB
    params.SaltLength = 16
    params.Parallelism = 2

    // HashCustom requires a random salt to prevent rainbow table attacks and to
    // ensure that users with the same password cannot be distinguished.
    salt, err := argonize.NewSalt(params.SaltLength)
    if err != nil {
      log.Fatal(err)
    }

    hashedObj := argonize.HashCustom(password, salt, params)

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
    //
    // Output:
    // the password is valid
    // the password is invalid
}
```

- [View more examples and advanced usages](https://pkg.go.dev/github.com/KEINOS/go-argonize#pkg-examples) @ pkg.go.dev

## FAQ

- Q: Can I recover the original password from the hashed password?
  - A: No. Note that once hashed, passwords cannot be recovered and can only be used to verify.

## Contributing

[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/KEINOS/go-argonize)](https://github.com/KEINOS/go-argonize/blob/main/go.mod#L3 "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-argonize.svg)](https://pkg.go.dev/github.com/KEINOS/go-argonize/ "View document")
[![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-argonize?color=lightblue&logo=github)](https://github.com/KEINOS/go-argonize/issues "opened issues")
[![PR](https://img.shields.io/github/issues-pr/KEINOS/go-argonize?color=lightblue&logo=github)](https://github.com/KEINOS/go-argonize/pulls "Pull Requests")

Any Pull-Request for improvement is welcome!

- Branch to PR: `main`
- [CI](https://github.com/KEINOS/go-argonize/actions)s on PR/Push:
  - [unit-tests](https://github.com/KEINOS/go-argonize/blob/main/.github/workflows/unit-tests.yml)
    - Inclues compatibility tests against PHP, Python and C implementations
  - [golangci-lint](https://github.com/KEINOS/go-argonize/blob/main/.github/workflows/golangci-lint.yml)
    - [GolangCI-Lint Configuration](https://github.com/KEINOS/go-argonize/blob/main/.golangci.yml)
  - [platform-tests](https://github.com/KEINOS/go-argonize/blob/main/.github/workflows/platform-tests.yml)
    - Tests on Win, macOS and Linux
  - [codeQL-analysis](https://github.com/KEINOS/go-argonize/blob/main/.github/workflows/codeQL-analysis.yml)
- [Our Security Policy](https://github.com/KEINOS/go-argonize/security/policy)

### Statuses

[![UnitTests](https://github.com/KEINOS/go-argonize/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/unit-tests.yml)
[![golangci-lint](https://github.com/KEINOS/go-argonize/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/golangci-lint.yml)
[![CodeQL-Analysis](https://github.com/KEINOS/go-argonize/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/codeQL-analysis.yml)
[![PlatformTests](https://github.com/KEINOS/go-argonize/actions/workflows/platform-tests.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/platform-tests.yml "Tests on Win, macOS and Linux")

[![codecov](https://codecov.io/gh/KEINOS/go-argonize/branch/main/graph/badge.svg?token=JVY7WUeUFz)](https://codecov.io/gh/KEINOS/go-argonize)
[![Go Report Card](https://goreportcard.com/badge/github.com/KEINOS/go-argonize)](https://goreportcard.com/report/github.com/KEINOS/go-argonize)

## License, copyright and credits

- MIT, Copyright (c) 2022 [KEINOS and the go-Argonize contributors](https://github.com/KEINOS/go-argonize/graphs/contributors).
- This Go package is strongly influenced by an article by [Alex Edwards](https://www.alexedwards.net/).
  - "[How to Hash and Verify Passwords With Argon2 in Go](https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go)"
