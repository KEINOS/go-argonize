# go-argonize

**Go package to facilitate the use of the [Argon2id](https://www.password-hashing.net/)** password hashing algorithm from the ["golang.org/x/crypto/argon2" package](https://pkg.go.dev/golang.org/x/crypto/argon2).

```go
go get "github.com/KEINOS/go-argonize"
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

- [View more examples and advanced usages](https://pkg.go.dev/github.com/KEINOS/go-argonize#pkg-examples) @ pkg.go.dev

## Statuses

[![codecov](https://codecov.io/gh/KEINOS/go-argonize/branch/main/graph/badge.svg?token=JVY7WUeUFz)](https://codecov.io/gh/KEINOS/go-argonize)
[![Go Report Card](https://goreportcard.com/badge/github.com/KEINOS/go-argonize)](https://goreportcard.com/report/github.com/KEINOS/go-argonize)

## Contributing

[![go1.18+](https://img.shields.io/badge/Go-1.18+-blue?logo=go)](https://github.com/KEINOS/go-argonize/actions/workflows/go-versions.yml "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-argonize.svg)](https://pkg.go.dev/github.com/KEINOS/go-argonize/ "View document")
[![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-argonize?color=lightblue&logo=github)](https://github.com/KEINOS/go-argonize/issues "opened issues")
[![PR](https://img.shields.io/github/issues-pr/KEINOS/go-argonize?color=lightblue&logo=github)](https://github.com/KEINOS/go-argonize/pulls "Pull Requests")

Any Pull-Request for improvement is welcome!

- Branch to PR: `main`

## License, copyright and credits

- MIT, Copyright (c) 2022 [KEINOS and the go-Argonize contributors](https://github.com/KEINOS/go-argonize/graphs/contributors).
- This Go package is strongly influenced by an article by [Alex Edwards](https://www.alexedwards.net/).
  - "[How to Hash and Verify Passwords With Argon2 in Go](https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go)"
