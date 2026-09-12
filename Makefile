BINARY := wappacvelyze
PKG    := ./cmd/wappacvelyze

.PHONY: build install test vet fmt clean extension

build:            ## Build ./wappacvelyze in the repo root
	go build -o $(BINARY) $(PKG)

install:          ## Install into $(go env GOPATH)/bin (or GOBIN)
	go install $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -f $(BINARY)

extension:        ## Build the browser extension into extension/dist and dist-firefox
	cd extension && npm ci --no-audit --no-fund && npm run build
