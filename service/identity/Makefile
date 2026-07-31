MIGRATIONS_DIR := ./migrations
GO_FILES := $(shell find ./cmd ./internal -type f -name '*.go' -print)

.PHONY: \
	fmt \
	fmt-check \
	test \
	test-race \
	vet \
	integration-test \
	security-check \
	verify \
	migration-create \
	migrate-up \
	migrate-down-one \
	migrate-version

fmt:
	gofmt -w $(GO_FILES)

fmt-check:
	@unformatted="$$(gofmt -l $(GO_FILES))"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt is required for:"; \
		printf '%s\n' "$$unformatted"; \
		exit 1; \
	fi

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

integration-test:
	@echo "Integration tests require isolated PostgreSQL/Redis and IDENTITY_INTEGRATION_TEST=1"
	go test -tags=integration -count=1 ./internal/integration

security-check:
	./scripts/security-check.sh

verify: fmt-check test test-race vet

migration-create:
	@test -n "$(name)" || \
		(echo "usage: make migration-create name=<migration_name>"; exit 1)
	@migrate create \
		-ext sql \
		-dir $(MIGRATIONS_DIR) \
		-seq \
		-digits 6 \
		$(name)

migrate-up:
	@test -n "$(DATABASE_DIRECT_URL)" || \
		(echo "DATABASE_DIRECT_URL is required"; exit 1)
	@migrate \
		-path $(MIGRATIONS_DIR) \
		-database "$(DATABASE_DIRECT_URL)" \
		up

migrate-down-one:
	@test -n "$(DATABASE_DIRECT_URL)" || \
		(echo "DATABASE_DIRECT_URL is required"; exit 1)
	@migrate \
		-path $(MIGRATIONS_DIR) \
		-database "$(DATABASE_DIRECT_URL)" \
		down 1

migrate-version:
	@test -n "$(DATABASE_DIRECT_URL)" || \
		(echo "DATABASE_DIRECT_URL is required"; exit 1)
	@migrate \
		-path $(MIGRATIONS_DIR) \
		-database "$(DATABASE_DIRECT_URL)" \
		version
