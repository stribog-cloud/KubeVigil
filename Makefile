MODULE   := github.com/stribog-cloud/kubevigil
BIN      := bin/kubevigil
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE     ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COVER_PKGS := $(shell go list ./internal/... ./cmd/...)
COVERAGE_FLOOR := 96
GOPATH_BIN := $(shell go env GOPATH)/bin
GOVULNCHECK := $(GOPATH_BIN)/govulncheck

LDFLAGS  := -X $(MODULE)/internal/version.Version=$(VERSION) \
            -X $(MODULE)/internal/version.Commit=$(COMMIT) \
            -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build test test-cover lint vet format fmt cover coverage secrets vuln clean check all \
        hooks-install setup-hooks graph-install graph graph-serve \
        doc-gate doc-drift-gate doc-samples-test doc-a11y smoke

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/kubevigil

test:
	go test -race -count=1 $(COVER_PKGS)

test-cover:
	go test -race -count=1 -coverprofile=coverage.out $(COVER_PKGS)
	go tool cover -func=coverage.out

lint:
	golangci-lint run ./...

vet:
	go vet ./...

format: fmt
fmt:
	gofmt -w .
	goimports -w -local $(MODULE) .

cover: coverage
coverage:
	go test -race -count=1 -coverprofile=coverage.out $(COVER_PKGS)
	@pct=$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/,""); print $$3}'); \
	echo "Coverage: $${pct}% (floor: $(COVERAGE_FLOOR)%)"; \
	awk -v p="$$pct" -v f="$(COVERAGE_FLOOR)" 'BEGIN {exit !(p+0 >= f+0)}' || \
	(echo "ERROR: coverage $${pct}% below floor $(COVERAGE_FLOOR)%" && exit 1)

secrets:
	gitleaks detect --source . --config .gitleaks.toml --redact -v

vuln:
	@test -x "$(GOVULNCHECK)" || go install golang.org/x/vuln/cmd/govulncheck@latest
	"$(GOVULNCHECK)" ./...

smoke: build
	$(BIN) version
	$(BIN) list checks >/dev/null

clean:
	rm -rf bin/ coverage.out

check: vet lint test coverage secrets vuln build smoke

all: format lint vet test coverage secrets vuln build smoke

hooks-install setup-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks configured. Pre-commit runs gitleaks on staged changes."

doc-gate:
	@./scripts/doc-gate.sh

doc-drift-gate:
	@./scripts/doc-drift-gate.sh

doc-samples-test:
	@./scripts/doc-samples-test.sh

doc-a11y:
	@./scripts/doc-a11y.sh

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