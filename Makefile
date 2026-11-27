PROJECT_NAME := $(shell sed -n 's/^project_name:[[:space:]]*//p' IDEA.md 2>/dev/null | head -n1 | tr -d '[:space:]')
ifeq ($(PROJECT_NAME),)
PROJECT_NAME := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)\.git$$|\1|; s|.*/([^/]+)$$|\1|' || basename "$(PWD)")
endif
PROJECT_ORG := $(shell sed -n 's/^project_org:[[:space:]]*//p' IDEA.md 2>/dev/null | head -n1 | tr -d '[:space:]')
ifeq ($(PROJECT_ORG),)
PROJECT_ORG := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*[:/]([^/]+)/[^/]+(\.git)?$$|\1|' || basename "$(shell dirname "$(PWD)")")
endif
INTERNAL_NAME := $(shell sed -n 's/^internal_name:[[:space:]]*//p' IDEA.md 2>/dev/null | head -n1 | tr -d '[:space:]')
ifeq ($(INTERNAL_NAME),)
INTERNAL_NAME := $(PROJECT_NAME)
endif

VERSION ?= $(shell v=; [ ! -r release.txt ] || v=$$(tr -d '[:space:]' < release.txt); if [ -n "$$v" ]; then printf '%s' "$$v"; else git rev-parse --short=7 HEAD 2>/dev/null || echo devel; fi)
ifeq ($(strip $(VERSION)),)
VERSION := $(shell v=; [ ! -r release.txt ] || v=$$(tr -d '[:space:]' < release.txt); if [ -n "$$v" ]; then printf '%s' "$$v"; else git rev-parse --short=7 HEAD 2>/dev/null || echo devel; fi)
endif
COMMIT_ID := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo N/A)
BUILD_EPOCH := $(shell date -u +%s)
BUILD_DATE := $(shell date -u -d @$(BUILD_EPOCH) +%Y-%m-%dT%H:%M:%SZ)
OFFICIAL_SITE := $(shell if [ -s site.txt ]; then cat site.txt; else printf '%s' "$(OFFICIAL_SITE)"; fi)

BINDIR := binaries
RELDIR := releases
GO_CACHE ?= $(HOME)/go/pkg/mod
GO_BUILD ?= $(HOME)/.cache/go-build/$(PROJECT_NAME)
REGISTRY ?= ghcr.io/$(PROJECT_ORG)/$(INTERNAL_NAME)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64
DOCKER_MEM ?= 4g
DOCKER_CPUS ?= 2
DOCKER_CPU_SHARES ?= 256
DOCKER_TIMEOUT ?= 3600
INCUS_MODE ?= all
LDFLAGS := -s -w -X 'main.Version=$(VERSION)' -X 'main.CommitID=$(COMMIT_ID)' -X 'main.BuildEpoch=$(BUILD_EPOCH)' -X 'main.OfficialSite=$(OFFICIAL_SITE)'
GO_DOCKER_RUN := timeout -k 30 $(DOCKER_TIMEOUT) docker run --rm --no-healthcheck \
	--name $(PROJECT_NAME)-$$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-8) \
	--memory=$(DOCKER_MEM) --cpus=$(DOCKER_CPUS) --cpu-shares=$(DOCKER_CPU_SHARES) \
	-v "$(PWD)":/app -v "$(abspath $(BINDIR))":/output -v "$(GO_CACHE)":/usr/local/share/go/pkg/mod \
	-v "$(GO_BUILD)":/usr/local/share/go/cache -w /app \
	-e CGO_ENABLED=0 -e "GOFLAGS=-buildvcs=false -mod=mod"
GO_DOCKER := $(GO_DOCKER_RUN) casjaysdev/go:latest

.PHONY: build local release release-check beta docker test dev clean

build: clean
	@mkdir -p "$(BINDIR)" "$(GO_CACHE)" "$(GO_BUILD)"
	@$(GO_DOCKER) sh -c 'set -eu; go mod tidy; go mod download; \
	  go build -trimpath -ldflags "$(LDFLAGS)" -o /output/$(INTERNAL_NAME) ./src; \
	  for platform in $(PLATFORMS); do \
	    GOOS=$${platform%/*}; GOARCH=$${platform#*/}; ext=; \
	    [ "$$GOOS" = windows ] && ext=.exe || true; \
	    GOOS=$$GOOS GOARCH=$$GOARCH go build -trimpath -ldflags "$(LDFLAGS)" -o /output/$(INTERNAL_NAME)-$$GOOS-$$GOARCH$$ext ./src; \
	    if [ -d src/client ]; then GOOS=$$GOOS GOARCH=$$GOARCH go build -trimpath -ldflags "$(LDFLAGS)" -o /output/$(INTERNAL_NAME)-cli-$$GOOS-$$GOARCH$$ext ./src/client; fi; \
	  done'

local: clean
	@mkdir -p "$(BINDIR)" "$(GO_CACHE)" "$(GO_BUILD)"
	@$(GO_DOCKER) sh -c 'set -eu; go mod tidy; go mod download; \
	  go build -trimpath -ldflags "$(LDFLAGS)" -o /output/$(INTERNAL_NAME) ./src; \
	  if [ -d src/client ]; then go build -trimpath -ldflags "$(LDFLAGS)" -o /output/$(INTERNAL_NAME)-cli ./src/client; fi'

release: release-check
	@$(MAKE) build
	@mkdir -p "$(RELDIR)"
	@cp "$(BINDIR)"/$(INTERNAL_NAME)-* "$(RELDIR)/"
	@printf '%s\n' "$(VERSION)" > "$(RELDIR)/version.txt"
	@tar --exclude='.git' --exclude='.github' --exclude='.gitea' --exclude='.forgejo' --exclude='binaries' --exclude='releases' -czf "$(RELDIR)/$(INTERNAL_NAME)-$(VERSION)-source.tar.gz" .
	@cd "$(RELDIR)" && sha256sum * > sha256.txt && sha512sum * > sha512.txt
	@gh release create "v$(VERSION)" "$(RELDIR)"/* --title "$(INTERNAL_NAME) $(VERSION)" --notes "Release $(VERSION)" --latest

release-check:
	@printf '%s\n' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "ERROR: make release requires a stable X.Y.Z version in release.txt" >&2; exit 1; }

beta:
	@[ "$(shell git branch --show-current)" = main ] || { echo "beta: run it on main" >&2; exit 1; }
	@[ -z "$(shell git status --porcelain)" ] || { echo "beta: the working tree is not clean" >&2; exit 1; }
	@TAG=$$(date -u +%Y%m%d%H%M%S)-beta; git tag "$$TAG" && git push origin "refs/tags/$$TAG" && echo "Pushed $$TAG"

docker:
	@docker buildx version >/dev/null 2>&1 || { echo "docker buildx is required" >&2; exit 1; }
	@docker buildx create --name multiarch-builder --use 2>/dev/null || docker buildx use multiarch-builder
	@docker buildx build --file docker/Dockerfile \
	  --build-arg VERSION="$(VERSION)" --build-arg BUILD_DATE="$(BUILD_DATE)" \
	  --build-arg BUILD_EPOCH="$(BUILD_EPOCH)" --build-arg COMMIT_ID="$(COMMIT_ID)" \
	  --build-arg OFFICIAL_SITE="$(OFFICIAL_SITE)" --tag "$(REGISTRY):$(VERSION)" \
	  --tag "$(REGISTRY):latest" --load .
	@bash tests/docker.sh --image-check "$(REGISTRY):$(VERSION)"

test:
	@mkdir -p "$(GO_CACHE)" "$(GO_BUILD)"
	@$(GO_DOCKER) sh -c 'set -eu; \
	  mkdir -p "$${TMPDIR:-/tmp}/$(PROJECT_ORG)"; COVDIR=$$(mktemp -d "$${TMPDIR:-/tmp}/$(PROJECT_ORG)/$(INTERNAL_NAME)-XXXXXX"); trap "rm -rf $$COVDIR" EXIT; export TMPDIR=$$COVDIR; \
	  go mod tidy; go mod download; \
	  go fmt ./...; \
	  go vet ./...; staticcheck ./...; govulncheck ./...; \
	  shellcheck tests/*.sh; shfmt -d -i 2 tests/*.sh; \
	  bash scripts/verify-licenses.sh; \
	  mkdir -p "$$COVDIR/data"; \
	  go test -cover ./... -args -test.gocoverdir="$$COVDIR/data"; \
	  go tool covdata textfmt -i="$$COVDIR/data" -o="$$COVDIR/coverage.out"; \
	  COVERAGE=$$(go tool cover -func=$$COVDIR/coverage.out | awk "/^total:/ {gsub(/%/, \"\", \$$NF); print \$$NF}"); \
	  awk -v coverage="$$COVERAGE" "BEGIN { exit !(coverage >= 60) }" || { echo "Coverage $$COVERAGE% is below 60%" >&2; exit 1; }; \
	  go run ./src/tools/i18n-validate src/common/i18n/locales; \
	  echo "Coverage: $$COVERAGE% (minimum 60%)"'
	@bash tests/run_tests.sh
	@if [ "$(INTEGRATION)" = "1" ]; then bash tests/incus.sh "$(INCUS_MODE)"; fi

dev:
	@mkdir -p "$${TMPDIR:-/tmp}/$(PROJECT_ORG)" "$(GO_CACHE)" "$(GO_BUILD)"
	@BUILD_DIR=$$(mktemp -d "$${TMPDIR:-/tmp}/$(PROJECT_ORG)/$(INTERNAL_NAME)-XXXXXX"); \
	  timeout -k 30 $(DOCKER_TIMEOUT) docker run --rm --no-healthcheck --name $(PROJECT_NAME)-$$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-8) \
	    --memory=$(DOCKER_MEM) --cpus=$(DOCKER_CPUS) --cpu-shares=$(DOCKER_CPU_SHARES) \
	    -v "$(PWD)":/app -v "$$BUILD_DIR":/output -v "$(GO_CACHE)":/usr/local/share/go/pkg/mod \
	    -v "$(GO_BUILD)":/usr/local/share/go/cache -w /app -e CGO_ENABLED=0 -e "GOFLAGS=-buildvcs=false -mod=mod" \
	    casjaysdev/go:latest sh -c 'go mod tidy && go mod download && go build -o /output/$(INTERNAL_NAME) ./src && if [ -d src/client ]; then go build -o /output/$(INTERNAL_NAME)-cli ./src/client; fi'; \
	  echo "Built binaries in $$BUILD_DIR; run them in Docker or Incus."

clean:
	@rm -rf -- "$(BINDIR)" "$(RELDIR)"
