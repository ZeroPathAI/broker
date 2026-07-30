# syntax=docker/dockerfile:1

# ----------------------------------------------------------------------------
# Build stage: compile a fully static, CGO-free binary.
# ----------------------------------------------------------------------------
FROM golang:1.22-alpine AS build
WORKDIR /src

# Resolve modules first so this layer is cached across source-only changes.
# (go mod download creates/populates go.sum from go.mod if it is not committed.)
COPY go.mod ./
RUN go mod download

# Build. CGO_ENABLED=0 removes the libc dependency so the result runs on the
# distroless "static" base. -trimpath + -ldflags strip local paths and symbols.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/broker .

# Fail the build if anything static/vet-level is wrong (CI also runs these).
RUN go vet ./... && go test ./...

# ----------------------------------------------------------------------------
# Runtime stage: distroless static, non-root, no shell, no package manager.
# ----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# Run as the distroless "nonroot" user (uid 65532). The broker needs NO elevated
# capabilities: it only makes OUTBOUND connections and binds an unprivileged
# proxy port (>= 1024), so NET_ADMIN / NET_RAW are never required. Deploy with
# a read-only root FS and `securityContext.capabilities.drop: [ALL]`.
USER 65532:65532

COPY --from=build /out/broker /usr/local/bin/broker

# Default forward-proxy listen port (override via BROKER_FORWARD_PROXY_LISTEN).
EXPOSE 3128

ENTRYPOINT ["/usr/local/bin/broker"]
