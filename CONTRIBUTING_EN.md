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
