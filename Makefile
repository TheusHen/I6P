.PHONY: all build test bench lint fmt clean

all: fmt lint test build

build:
	go build ./...

test:
	go test -v -race ./...

bench:
	go test -bench=. -benchmem ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

clean:
	go clean ./...

deps:
	go mod tidy
	go mod download

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

vulncheck:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

# Run examples
run-basic:
	go run ./examples/basic

run-bulk:
	go run ./examples/bulk

run-erasure:
	go run ./examples/erasure
