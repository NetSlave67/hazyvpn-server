# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION:-dev}" \
    -o /out/hazyvpn-server ./cmd/hazyvpn-server

FROM alpine:3.22
RUN apk add --no-cache \
    iproute2 \
    wireguard-tools \
    nftables \
    ca-certificates
COPY --from=builder /out/hazyvpn-server /usr/local/bin/hazyvpn-server

# Only the data dir is a real Docker-managed volume (it holds state that
# must survive container recreation: the SQLite DB and master key).
# /etc/hazyvpn-server is NOT declared here deliberately — it only ever holds
# a single operator-supplied, read-only config.yaml bind-mounted in by
# docker-compose.yml. Declaring it as a VOLUME too made Docker manage it as
# an anonymous volume, which raced with that file bind-mount on container
# recreation and intermittently left config.yaml bind-mounted as a
# directory instead of a file (seen in production: "not a directory: Are
# you trying to mount a directory onto a file?").
VOLUME ["/var/lib/hazyvpn-server"]
ENV HAZYVPN_DATA_DIR=/var/lib/hazyvpn-server
ENTRYPOINT ["/usr/local/bin/hazyvpn-server"]
# The container's own process just reconciles tenants and idles — the TUI
# is a separate `docker exec -it hazyvpn-server hazyvpn-server` invocation,
# so quitting it can never take the running tenants down with it.
CMD ["daemon"]
