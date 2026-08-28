# Contributing Guide

## Prerequisites
- Go 1.26+
- `go vet ./...` with zero warnings
- All tests passing

## Development Workflow

```bash
# Clone
git clone https://github.com/varwof/gateway-core

# Build
go build ./...

# Test
go test -count=1 -race ./...

# Lint
go vet ./...
gofmt -s -l .
```

## Commit Message Format

```
<type>: <short description>

Types: feat / fix / docs / test / refactor / chore
```

## PR Requirements
1. New features must include tests
2. Configuration changes must update docs/ accordingly
3. OpenAPI changes must update openapi.yaml accordingly


## Contributor License Agreement

By submitting a pull request, you agree to sign the
[Individual CLA](https://github.com/varwof/.github/blob/main/CLA-INDIVIDUAL.md)
(or [Corporate CLA](https://github.com/varwof/.github/blob/main/CLA-CORPORATE.md)
for employer-sponsored contributions). The CLA Assistant bot will prompt
you to sign when you open your first pull request; signing once covers all
Varwof repositories.

By contributing, you agree that your contributions are licensed under the
Apache-2.0 license, as described in [LICENSE](LICENSE).
