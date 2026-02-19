MODULE   := github.com/stribog-cloud/kubevigil
BIN      := bin/kubevigil
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE     ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS  := -X $(MODULE)/internal/version.Version=$(VERSION) \
            -X $(MODULE)/internal/version.Commit=$(COMMIT) \
            -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build test test-cover lint vet fmt cover vulncheck clean check

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/kubevigil

test:
	go test -race -count=1 ./...

test-cover:
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	golangci-lint run ./...

vet:
	go vet ./...

fmt:
	gofmt -w .
	goimports -w -local $(MODULE) .

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vulncheck:
	govulncheck ./...

clean:
	rm -rf bin/ coverage.out

check: vet lint test
	@echo "All quality gates passed."
