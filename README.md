# Beexter Backend

Backend monorepo for the Beexter platform.

## Repository layout

Each deployable service is an independent Go module and owns its own `go.mod` file.

```text
services/
  identity/
    go.mod
    cmd/api/
    internal/
```

The repository root intentionally has no `go.mod`. A local `go.work` may be created for multi-module development and is ignored by Git.

## Local development

```bash
go work init ./services/identity
make fmt
make test
make run
```

The identity service listens on `:8080` by default.

- `GET /health`: process liveness.
- `GET /ready`: dependency readiness. It returns `503` until PostgreSQL and Redis checks are wired.
