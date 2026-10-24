set shell := ["bash", "-euo", "pipefail", "-c"]

# List available recipes
default:
    @just --list

# Build a static, stripped binary
build:
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o router .

# Build a normal debug binary
build-debug:
    go build -o router .

# Run the router with extra arguments: just run -b proton -c us/san-jose
run *args:
    go run . {{args}}

# Run unit tests
test:
    go test -count=1 ./...

# Run tests with the race detector
race:
    go test -race -count=1 ./...

# Run go vet
vet:
    go vet ./...

# Format all Go files
fmt:
    gofmt -w .

# Fail if any Go file needs formatting
fmt-check:
    @test -z "$(gofmt -l .)" || { echo "unformatted files:"; gofmt -l .; exit 1; }

# Fast local checks
check: fmt-check vet test

# Full CI-equivalent checks
ci: check race build

# Install the binary into GOBIN/GOPATH/bin
install:
    go install -trimpath -ldflags="-s -w" .

# Remove the local binary
clean:
    rm -f router
