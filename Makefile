all: build

build:
	go generate ./...
	go build -o . ./cmd/...

image:
	podman build -f container/Containerfile -t attezt .

.PHONY: image build
