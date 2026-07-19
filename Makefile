# Frozen project identity (set at creation from IDEA.md - never changes even if git remote changes)
INTERNAL_NAME := caswhois
PROJECTORG    := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)/[^/]+(\.git)?$$|\1|' || basename "$$(dirname "$$(pwd)")")

# Infer PROJECTNAME from git remote or directory path (NEVER hardcode)
PROJECTNAME := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)(\.git)?$$|\1|' || basename "$$(pwd)")

# Version: env var > release.txt > default
VERSION ?= $(shell cat release.txt 2>/dev/null || echo "devel")

# Build info - use TZ env var or system timezone
# Format: "December 4, 2025 at 13:05:13"
BUILD_DATE := $(shell date +"%B %-d, %Y at %H:%M:%S")
COMMIT_ID := $(shell git rev-parse --short HEAD 2>/dev/null || echo "N/A")

# Official site URL (OPTIONAL - never guess or assume)
# Sources (in order of precedence):
#   1. File: site.txt in project root (single line, URL only)
#   2. Environment variable: OFFICIALSITE=https://example.com
#   3. Empty (self-hosted projects - users must use --server flag)
# NEVER infer from project name, domain, or any other source
OFFICIALSITE := $(shell [ -f site.txt ] && cat site.txt || echo "${OFFICIALSITE:-}")

# Linker flags to embed build info
LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.CommitID=$(COMMIT_ID)' \
	-X 'main.BuildDate=$(BUILD_DATE)' \
	-X 'main.OfficialSite=$(OFFICIALSITE)'

# Directories
BINDIR := binaries
RELDIR := releases

# Go directories (persistent across builds)
# GO_CACHE maps host module cache to casjaysdev/go image's GOPATH/pkg/mod
# GO_BUILD maps to casjaysdev/go image's build cache
GO_CACHE ?= $(HOME)/go/pkg/mod
GO_BUILD ?= $(HOME)/.cache/go-build/$(PROJECTNAME)

# Build targets
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64

# Docker - Set REGISTRY based on your platform (ghcr.io, registry.gitlab.com, git.example.com)
REGISTRY ?= ghcr.io/$(PROJECTORG)/$(INTERNAL_NAME)
GO_DOCKER := docker run --rm \
	--name $(PROJECTNAME)-$$(tr -dc 'a-z0-9' </dev/urandom | head -c8) \
	-v $(PWD):/app \
	-v $(GO_CACHE):/usr/local/share/go/pkg/mod \
	-v $(GO_BUILD):/usr/local/share/go/cache \
	-w /app \
	-e CGO_ENABLED=0 \
	-e GOFLAGS=-buildvcs=false \
	casjaysdev/go:latest

.PHONY: build local release docker test dev lint clean i18n-validate

# =============================================================================
# BUILD - Build all platforms + local binary (via Docker with cached modules)
# =============================================================================
build: clean
	@mkdir -p $(BINDIR) $(GO_CACHE) $(GO_BUILD)
	@echo "Building version $(VERSION)..."

	# Tidy and download modules
	@echo "Tidying and downloading Go modules..."
	@$(GO_DOCKER) go mod tidy
	@$(GO_DOCKER) go mod download

	# Build for local OS/ARCH
	@echo "Building local binary..."
	@$(GO_DOCKER) sh -c "GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) \
		go build -buildvcs=false -trimpath -ldflags \"$(LDFLAGS)\" -o $(BINDIR)/$(INTERNAL_NAME) ./src"

	# Build server for all platforms
	@for platform in $(PLATFORMS); do \
		OS=$${platform%/*}; \
		ARCH=$${platform#*/}; \
		OUTPUT=$(BINDIR)/$(INTERNAL_NAME)-$$OS-$$ARCH; \
		[ "$$OS" = "windows" ] && OUTPUT=$$OUTPUT.exe; \
		echo "Building server $$OS/$$ARCH..."; \
		$(GO_DOCKER) sh -c "GOOS=$$OS GOARCH=$$ARCH \
			go build -buildvcs=false -trimpath -ldflags \"$(LDFLAGS)\" \
			-o $$OUTPUT ./src" || exit 1; \
	done

	# Build CLI for all platforms (if exists)
	@if [ -d "src/client" ]; then \
		for platform in $(PLATFORMS); do \
			OS=$${platform%/*}; \
			ARCH=$${platform#*/}; \
			OUTPUT=$(BINDIR)/$(INTERNAL_NAME)-cli-$$OS-$$ARCH; \
			[ "$$OS" = "windows" ] && OUTPUT=$$OUTPUT.exe; \
			echo "Building CLI $$OS/$$ARCH..."; \
			$(GO_DOCKER) sh -c "GOOS=$$OS GOARCH=$$ARCH \
				go build -buildvcs=false -trimpath -ldflags \"$(LDFLAGS)\" \
				-o $$OUTPUT ./src/client" || exit 1; \
		done; \
	fi

	@echo "Build complete: $(BINDIR)/"

# =============================================================================
# LOCAL - Build local binaries only (fast development builds)
# =============================================================================
local: clean
	@mkdir -p $(BINDIR) $(GO_CACHE) $(GO_BUILD)
	@echo "Building local binaries version $(VERSION)..."

	# Tidy and download modules
	@echo "Tidying and downloading Go modules..."
	@$(GO_DOCKER) go mod tidy
	@$(GO_DOCKER) go mod download

	# Build server binary
	@echo "Building $(INTERNAL_NAME)..."
	@$(GO_DOCKER) sh -c "GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) \
		go build -buildvcs=false -trimpath -ldflags \"$(LDFLAGS)\" -o $(BINDIR)/$(INTERNAL_NAME) ./src"

	# Build CLI binary (if exists)
	@if [ -d "src/client" ]; then \
		echo "Building $(INTERNAL_NAME)-cli..."; \
		$(GO_DOCKER) sh -c "GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) \
			go build -buildvcs=false -trimpath -ldflags \"$(LDFLAGS)\" -o $(BINDIR)/$(INTERNAL_NAME)-cli ./src/client"; \
	fi

	@echo "Local build complete: $(BINDIR)/"

# =============================================================================
# RELEASE - Manual local release (stable only)
# =============================================================================
release: build
	@mkdir -p $(RELDIR)
	@echo "Preparing release $(VERSION)..."

	# Create version.txt
	@echo "$(VERSION)" > $(RELDIR)/version.txt

	# Copy binaries to releases (strip if needed)
	@for f in $(BINDIR)/$(INTERNAL_NAME)-*; do \
		[ -f "$$f" ] || continue; \
		strip "$$f" 2>/dev/null || true; \
		cp "$$f" $(RELDIR)/; \
	done

	# Create source archive (exclude VCS and build artifacts)
	@tar --exclude='.git' --exclude='.github' --exclude='.gitea' \
		--exclude='binaries' --exclude='releases' --exclude='*.tar.gz' \
		-czf $(RELDIR)/$(INTERNAL_NAME)-$(VERSION)-source.tar.gz .

	# Delete existing release/tag if exists
	@gh release delete $(VERSION) --yes 2>/dev/null || true
	@git tag -d $(VERSION) 2>/dev/null || true
	@git push origin :refs/tags/$(VERSION) 2>/dev/null || true

	# Create new release (stable)
	@gh release create $(VERSION) $(RELDIR)/* \
		--title "$(INTERNAL_NAME) $(VERSION)" \
		--notes "Release $(VERSION)" \
		--latest

	@echo "Release complete: $(VERSION)"

# =============================================================================
# DOCKER - Build the production container image locally (current arch)
# =============================================================================
# Uses multi-stage Dockerfile - Go compilation happens inside Docker.
# Local build only; multi-arch push to the registry is handled by release.yml
# (AI.md PART 25 / PART 27). Set REGISTRY to override the image tag.
docker:
	@echo "Building Docker image $(VERSION)..."

	# Ensure buildx is available
	@docker buildx version > /dev/null 2>&1 || (echo "docker buildx required" && exit 1)

	# Create/use builder
	@docker buildx create --name $(INTERNAL_NAME)-builder --use 2>/dev/null || \
		docker buildx use $(INTERNAL_NAME)-builder

	# Build for the local arch and load into the local Docker image store
	# (multi-stage Dockerfile handles Go compilation)
	@docker buildx build \
		-f docker/Dockerfile \
		--build-arg VERSION="$(VERSION)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg COMMIT_ID="$(COMMIT_ID)" \
		-t $(REGISTRY):$(VERSION) \
		-t $(REGISTRY):latest \
		--load \
		.

	@echo "Docker build complete: $(REGISTRY):$(VERSION)"

# =============================================================================
# TEST - Run all tests with coverage enforcement (via Docker)
# =============================================================================
test:
	@echo "Running tests with coverage..."
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@$(GO_DOCKER) sh -c " \
		mkdir -p \"/tmp/$(PROJECTORG)\" && \
		COVDIR=\$$(mktemp -d \"/tmp/$(PROJECTORG)/$(INTERNAL_NAME)-XXXXXX\") && \
		go mod download && \
		go test -cover -coverprofile=\$$COVDIR/coverage.out ./... && \
		COVERAGE=\$$(go tool cover -func=\$$COVDIR/coverage.out | grep total | awk '{print \$$3}' | sed 's/%//') && \
		echo \"Coverage: \$$COVERAGE%\" && \
		if [ \$$(echo \"\$$COVERAGE < 60\" | bc -l) -eq 1 ]; then \
			echo \"ERROR: Coverage is \$$COVERAGE%, must be >= 60%\"; exit 1; \
		fi && \
		echo \"Tests complete - coverage >= 60% ✓\""
	@$(MAKE) i18n-validate

# =============================================================================
# I18N-VALIDATE - Verify every locale has the same key set as en.json
# =============================================================================
i18n-validate:
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@echo "Validating translation files..."
	@$(GO_DOCKER) go run ./src/tools/i18n-validate src/common/i18n/locales

# =============================================================================
# DEV - Quick build for local development/testing (to random temp dir)
# =============================================================================
# Fast: local platform only, no ldflags, random temp dir for isolation
# Builds server + CLI (if they exist)
dev:
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@$(GO_DOCKER) go mod tidy
	@mkdir -p "$${TMPDIR:-/tmp}/$(PROJECTORG)" && \
		BUILD_DIR=$$(mktemp -d "$${TMPDIR:-/tmp}/$(PROJECTORG)/$(INTERNAL_NAME)-XXXXXX") && \
		echo "Quick dev build to $$BUILD_DIR..." && \
		$(GO_DOCKER) go build -buildvcs=false -o $$BUILD_DIR/$(INTERNAL_NAME) ./src && \
		echo "Built: $$BUILD_DIR/$(INTERNAL_NAME)" && \
		if [ -d "src/client" ]; then \
			$(GO_DOCKER) go build -buildvcs=false -o $$BUILD_DIR/$(INTERNAL_NAME)-cli ./src/client && \
			echo "Built: $$BUILD_DIR/$(INTERNAL_NAME)-cli"; \
		fi && \
		echo "Test:  docker run --rm --name $(INTERNAL_NAME)-test -v $$BUILD_DIR:/app alpine:latest /app/$(INTERNAL_NAME) --help"

# =============================================================================
# LINT - Run staticcheck and golangci-lint inside Docker (AI.md PART 25)
# =============================================================================
lint:
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@echo "Running linters..."
	@$(GO_DOCKER) sh -c "go vet ./... && staticcheck ./... 2>/dev/null || true"

# =============================================================================
# CLEAN - Remove build artifacts
# =============================================================================
clean:
	@rm -rf $(BINDIR) $(RELDIR)
