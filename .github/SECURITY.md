# Security Policy

## Fail Fast Policy

We update the `go.mod` version weekly to keep up with the latest security patches and updates. It may break the backward compatibility but we prefer to fail fast and fix it fast.

## Basic Tests

As a minimum security measure, we keep the following green as much as possible:

[![UnitTests](https://github.com/KEINOS/go-argonize/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/unit-tests.yml)
[![golangci-lint](https://github.com/KEINOS/go-argonize/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/golangci-lint.yml)
[![CodeQL-Analysis](https://github.com/KEINOS/go-argonize/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/codeQL-analysis.yml)
[![PlatformTests](https://github.com/KEINOS/go-argonize/actions/workflows/platform-tests.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/platform-tests.yml "Tests on Win, macOS and Linux")

[![codecov](https://codecov.io/gh/KEINOS/go-argonize/branch/main/graph/badge.svg?token=JVY7WUeUFz)](https://codecov.io/gh/KEINOS/go-argonize)
[![Go Report Card](https://goreportcard.com/badge/github.com/KEINOS/go-argonize)](https://goreportcard.com/report/github.com/KEINOS/go-argonize)

- Code coverage and quality (`go report`) does nothing to do with security. But keeping them high will help maintenance which will help security in the long run.

## Vulnerability Checks

| Version | Status | Note |
| :------ | :----- | :--- |
| Security advisories | [Enabled](https://github.com/KEINOS/go-argonize/security/advisories) | |
| Dependabot alerts | [Enabled](https://github.com/KEINOS/go-argonize/security/dependabot) | (Only for admins) |
| Code scanning alerts | [Enabled](https://github.com/KEINOS/go-argonize/security/code-scanning)<br>[![CodeQL-Analysis](https://github.com/KEINOS/go-argonize/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-argonize/actions/workflows/codeQL-analysis.yml) ||

## Reporting a Vulnerability, Bugs and etc.

- [Issues](https://github.com/KEINOS/go-argonize/issues)
  - [![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-argonize?color=lightblue&logo=github)](https://github.com/KEINOS/go-argonize/issues "opened issues")
  - Plase attach a simple test that replicates the issue.
