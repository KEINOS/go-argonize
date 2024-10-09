<!-- markdownlint-disable-file MD041 -->
# go-argonize

[![go1.22+](https://img.shields.io/badge/Go-1.22+-blue?logo=go)](https://github.com/KEINOS/go-argonize/blob/main/.github/workflows/unit-tests.yml#L81 "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-argonize.svg)](https://pkg.go.dev/github.com/KEINOS/go-argonize/ "View document")

**Go package to facilitate the use of the [Argon2id](https://www.password-hashing.net/)** password hashing algorithm from the ["crypto/argon2" package](https://pkg.go.dev/golang.org/x/crypto/argon2).

```go
go get "github.com/KEINOS/go-argonize"
```

```go
func Example() {
    // Your strong and unpredictable password
    password := []byte("my password")

    // Password hash your password
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

    // Output:
    // Passwd to save: $argon2id$v=19$m=65536,t=1,p=2$ek6ZYdlRm2D5AsGV98TWKA$QAIDZEdIgwohrNX678mHc448LOmD7jGR4BGw/9YMMVU
    // the password is valid
    // the password is invalid
}
```

- [View more examples and advanced usages](https://pkg.go.dev/github.com/KEINOS/go-argonize#pkg-examples) @ pkg.go.dev

## Contributing

[![go1.22+](https://img.shields.io/badge/Go-1.22+-blue?logo=go)](https://github.com/KEINOS/go-argonize/blob/main/.github/workflows/unit-tests.yml#L81 "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-argonize.svg)](https://pkg.go.dev/github.com/KEINOS/go-argonize/ "View document")
[![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-argonize?color=lightblue&logo=github)](https://github.com/KEINOS/go-argonize/issues "opened issues")
[![PR](https://img.shields.io/github/issues-pr/KEINOS/go-argonize?color=lightblue&logo=github)](https://github.com/KEINOS/go-argonize/pulls "Pull Requests")

Any Pull-Request for improvement is welcome!

- Branch to PR: `main`
- [CI](https://github.com/KEINOS/go-argonize/actions)s on PR/Push:
  - [unit-tests](https://github.com/KEINOS/go-argonize/blob/main/.github/workflows/unit-tests.yml)
    - Inclues compatibility tests against PHP and Python
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
