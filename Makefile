VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet docker-up docker-down clean

build:
	GOTOOLCHAIN=auto go build -ldflags "$(LDFLAGS)" -o hazyvpn-server ./cmd/hazyvpn-server

test:
	GOTOOLCHAIN=auto go test ./...

vet:
	GOTOOLCHAIN=auto go vet ./...

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	rm -f hazyvpn-server
