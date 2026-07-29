SERVICE ?= identity
SERVICE_DIR := services/$(SERVICE)

.PHONY: fmt vet test run

fmt:
	cd $(SERVICE_DIR) && gofmt -w .

vet:
	cd $(SERVICE_DIR) && go vet ./...

test:
	cd $(SERVICE_DIR) && go test ./...

run:
	cd $(SERVICE_DIR) && go run ./cmd/api
