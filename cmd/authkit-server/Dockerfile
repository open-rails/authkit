# Builder image tracks the go directive in go.mod (>= 1.26.5, required for the
# crypto/x509 GO-2026-5037 fix). Keep these in lockstep.
FROM golang:1.26.5 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/authkit-server ./cmd/authkit-server
# Pre-create the key-persistence dir owned by the non-root runtime UID so the
# server can write dev signing keys without running as root. A fresh named volume
# mounted at /.runtime/authkit inherits this ownership on first use.
RUN mkdir -p /out/runtime/authkit

FROM scratch

WORKDIR /
COPY --from=build /out/authkit-server /authkit-server
COPY --from=build --chown=65532:65532 /out/runtime /.runtime

# Key persistence (dev): mount a volume at `/.runtime/authkit` inside the container.
# Run as a non-root UID/GID (65532, the conventional "nonroot" id) — in dev the
# server auto-generates signing keys under /.runtime/authkit, owned by this UID above.
USER 65532:65532
ENV AUTHKIT_LISTEN_ADDR=:8080
EXPOSE 8080

ENTRYPOINT ["/authkit-server"]
