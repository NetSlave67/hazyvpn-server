# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION:-docker}" \
    -o /out/hazyvpn-server ./cmd/hazyvpn-server

FROM alpine:3.22
RUN apk add --no-cache \
    iproute2 \
    wireguard-tools \
    nftables \
    ca-certificates
COPY --from=builder /out/hazyvpn-server /usr/local/bin/hazyvpn-server

VOLUME ["/var/lib/hazyvpn-server", "/etc/hazyvpn-server"]
ENV HAZYVPN_DATA_DIR=/var/lib/hazyvpn-server
ENTRYPOINT ["/usr/local/bin/hazyvpn-server"]
# The container's own process just reconciles tenants and idles — the TUI
# is a separate `docker exec -it hazyvpn-server hazyvpn-server` invocation,
# so quitting it can never take the running tenants down with it.
CMD ["daemon"]
