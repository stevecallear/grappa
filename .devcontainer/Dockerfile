# see: https://github.com/microsoft/vscode-dev-containers/blob/v0.137.0/containers/go/.devcontainer/base.Dockerfile
ARG VARIANT=1
FROM mcr.microsoft.com/vscode/devcontainers/go:dev-${VARIANT}

ARG PROTOC_VERSION=3.15.6

# protoc binary
RUN curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip && \
    unzip -o protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local bin/protoc && \
    chmod a+rwx /usr/local/bin/protoc && \
    unzip -o protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local include/* && \
    chmod -R a+rwx /usr/local/include/google

# protoc-gen-go
RUN go get -u google.golang.org/protobuf/cmd/protoc-gen-go \
        google.golang.org/grpc && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go \
        google.golang.org/grpc/cmd/protoc-gen-go-grpc

# protoc-gen-debug
RUN go get -u github.com/lyft/protoc-gen-star/protoc-gen-debug && \
    go install github.com/lyft/protoc-gen-star/protoc-gen-debug