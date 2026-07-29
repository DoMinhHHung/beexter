# Beexter Identity Service

Identity Service cho nền tảng kết nối việc làm Beexter.

## Trạng thái hiện tại

Phase 0 bootstrap:

- Go HTTP server dùng standard library
- Structured logging với `log/slog`
- Graceful shutdown
- `GET /health` cho liveness
- `GET /ready` cho readiness
- Config qua environment variables
- Unit tests cơ bản

`/ready` hiện trả `503 Service Unavailable` có chủ đích cho đến khi PostgreSQL và Redis được wire vào readiness check.

## Yêu cầu

- Go 1.26.5

## Chạy local

```bash
cp .env.example .env
set -a && source .env && set +a
make run
```

Kiểm tra:

```bash
curl -i http://localhost:8080/health
curl -i http://localhost:8080/ready
```

## Quality checks

```bash
make check
make test-race
```

## Cấu trúc ban đầu

```text
cmd/api/                    application entrypoint
internal/config/            environment configuration
internal/transport/httpapi/ HTTP routing and handlers
```

Chưa tạo Domain, Application service hoặc Repository interface vì chưa có use case và database schema khóa để triển khai đúng boundary.
