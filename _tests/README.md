# Compatibility Tests

This directory contains Docker-based compatibility tests for the `go-argonize` project.

We verify the Go implementation against other language implementations:

- Go vs PHP
- Go vs Python
- Go vs C (phc-winner-argon2)

## Test flow

1. Generate a password (tests may use a random value).
2. Produce an Argon2id encoded string with the Go `sample` binary.
3. Verify or compare that encoded string in the target language:
   - PHP/Python: verify the Go-produced encoded string using the language's Argon2 verification API.
   - C: generate an encoded string with phc-winner-argon2 CLI and compare the strings for equality.

## Important notes

- Default parameters: these tests use the RFC 9106 SECOND RECOMMENDED parameters by default:
  - Variant: Argon2id
  - Passes (t): 3
  - Memory (m): 65536 KiB (64 MiB)
  - Parallelism (p): 4
  - Salt length: 16 bytes
  - Tag length: 32 bytes

- phc-winner-argon2 CLI: the C `argon2` CLI uses `-m` as a base-2 exponent (memory = 2^m KiB). For 65536 KiB pass `-m 16`.

- Local builds: test images are configured to build `sample` from the local repository (via a temporary `replace` in `go.mod` during the image build). Rebuild images if containers appear to use an older binary.

- Memory: the C/Clang test requires around 64 MiB per hash; ensure CI hosts have enough RAM.

- Determinism: tests use random data by default. For reproducible CI debugging, add deterministic test cases.

## Usage

Run from the repository root:

```bash
# build test images
docker compose build

# run PHP compatibility test
docker compose --file ./.github/docker-compose.yml run --rm --remove-orphans php

# run Python compatibility test
docker compose --file ./.github/docker-compose.yml run --rm --remove-orphans python

# run C/Clang compatibility test
docker compose --file ./.github/docker-compose.yml run --rm --remove-orphans clang
```

## Troubleshooting

- If PHP/Python verification shows a different parameter set (e.g. t=1,p=2), rebuild images to ensure `sample` was built from local source:

```bash
docker compose --file ./.github/docker-compose.yml build --no-cache
```

- If the C test fails with `bad numeric input for -m`, confirm the CLI is invoked with `-m 16` for 64 MiB and that the container has sufficient memory.

```bash
docker compose --file ./.github/docker-compose.yml build --no-cache
```

- If the Clang test fails with `bad numeric input for -m` or memory errors, confirm the C invocation uses `-m 16` (2^16 KiB = 65536 KiB) and that the host/container has enough RAM.
