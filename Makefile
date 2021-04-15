.PHONY: proto
proto:
	protoc -I. --go_out=paths=source_relative:. ./proto/grappapb/*.proto
	protoc -I. --proto_path="./proto" --plugin=protoc-gen-debug=/go/bin/protoc-gen-debug --debug_out="./internal/generator/testdata/:." ./internal/generator/testdata/*.proto

.PHONY: test
test: proto
	go test -v ./...

.PHONY: cover
cover: proto
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

.PHONY: install
install: test
	go install ./cmd/protoc-gen-grappa
	