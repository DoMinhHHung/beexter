#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

mapfile -d '' go_files < <(find ./cmd ./internal -type f -name '*.go' -print0)
unformatted="$(gofmt -l "${go_files[@]}")"
if [[ -n "${unformatted}" ]]; then
  echo "gofmt is required for:"
  printf '%s\n' "${unformatted}"
  exit 1
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git grep -nE \
      '(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|SMTP_APP_PASSWORD[[:space:]]*[:=][[:space:]]*"[^"$]+"|JWT_HS256_SECRET[[:space:]]*[:=][[:space:]]*"[^"$]+"|REFRESH_TOKEN_SECRET[[:space:]]*[:=][[:space:]]*"[^"$]+")' \
      -- '*.go'; then
    echo "possible hard-coded secret found"
    exit 1
  fi
fi

go test ./...
go test -race ./...
go vet ./...

echo "Integration tests run only when IDENTITY_INTEGRATION_TEST=1 is set."
go test -tags=integration -count=1 ./internal/integration

if command -v govulncheck >/dev/null 2>&1; then
  govulncheck ./...
else
  echo "govulncheck not installed; skipping vulnerability database scan"
fi
