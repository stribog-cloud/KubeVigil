MODULE   := github.com/stribog-cloud/kubevigil
BIN      := bin/kubevigil
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE     ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS  := -X $(MODULE)/internal/version.Version=$(VERSION) \
            -X $(MODULE)/internal/version.Commit=$(COMMIT) \
            -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build test test-cover lint vet fmt cover vulncheck clean check setup-hooks graph-install graph graph-serve

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/kubevigil

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

## Setup local git hooks for pre-commit secrets scanning
setup-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks configured. Pre-commit will now scan for secrets via gitleaks."

# --- Code graph analysis (dev tool) ---
CODEGRAPH_VERSION ?= latest
CODEGRAPH_CACHE   := $(HOME)/.cache/go-code-graph

graph-install:
	go install github.com/brutski/go-code-graph/cmd/analyze@$(CODEGRAPH_VERSION)
	@if [ ! -d "$(CODEGRAPH_CACHE)" ]; then \
		echo "Cloning go-code-graph for web assets..."; \
		git clone --depth 1 https://github.com/brutski/go-code-graph.git $(CODEGRAPH_CACHE); \
	fi

graph:
	$(shell go env GOPATH)/bin/analyze -repo=. -output=code-graph.json -summary=true

graph-serve: graph
	@cp code-graph.json $(CODEGRAPH_CACHE)/
	@cp code-graph.json.summary $(CODEGRAPH_CACHE)/
	@echo "Opening visualization at http://localhost:8080/visualization"
	cd $(CODEGRAPH_CACHE) && $(shell go env GOPATH)/bin/server -graph=code-graph.json -port=8080
