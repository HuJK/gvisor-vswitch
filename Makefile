# CGO is always off: every dependency is pure Go, and a static binary is
# required for Android (no glibc/bionic linkage). Don't drop CGO_ENABLED=0 —
# with cgo enabled the stdlib net/os.user packages silently link libc.
export CGO_ENABLED = 0

LDFLAGS := -s -w
BUILDDIR := build

.PHONY: build build-android build-linux-amd64 test vet check-static

build:
	go build -o $(BUILDDIR)/gvswitch ./cmd/gvswitch

# Android (pKVM host) target: static linux/arm64 binary, no libc.
build-android:
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/gvswitch-android-arm64 ./cmd/gvswitch
	$(MAKE) check-static BIN=$(BUILDDIR)/gvswitch-android-arm64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/gvswitch-linux-amd64 ./cmd/gvswitch
	$(MAKE) check-static BIN=$(BUILDDIR)/gvswitch-linux-amd64

# Fails if the produced binary picked up dynamic linkage.
check-static:
	@file "$(BIN)" | grep -q "statically linked" || { echo "ERROR: $(BIN) is not statically linked"; exit 1; }
	@echo "$(BIN): statically linked OK"

vet:
	go vet ./internal/... ./cmd/...

test:
	go test ./internal/... -race -count=1
