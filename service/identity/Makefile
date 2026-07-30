MIGRATIONS_DIR := ./migrations

.PHONY: \
	migration-create \
	migrate-up \
	migrate-down-one \
	migrate-version

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