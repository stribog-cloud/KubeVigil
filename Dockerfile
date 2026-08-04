# Stage 1: Build static binary
FROM golang:1.25.12 AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w \
      -X github.com/stribog-cloud/kubevigil/internal/version.Version=${VERSION} \
      -X github.com/stribog-cloud/kubevigil/internal/version.Commit=${COMMIT} \
      -X github.com/stribog-cloud/kubevigil/internal/version.Date=${DATE}" \
    -o /kubevigil ./cmd/kubevigil

# Stage 2: Minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="kubevigil"
LABEL org.opencontainers.image.description="Kubernetes Security Posture Management CLI"
LABEL org.opencontainers.image.source="https://github.com/stribog-cloud/KubeVigil"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Stribog"

COPY --from=builder /kubevigil /kubevigil

USER 65532:65532

ENTRYPOINT ["/kubevigil"]
