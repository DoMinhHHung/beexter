.PHONY: run fmt vet test test-race check

run:
	go run ./cmd/api

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

check: fmt vet test
