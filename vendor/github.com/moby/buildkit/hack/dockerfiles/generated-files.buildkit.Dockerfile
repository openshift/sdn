# syntax=tonistiigi/dockerfile:runmount20180828

# protoc is dynamically linked to glibc to can't use golang:1.10-alpine
FROM golang:1.11 AS gobuild-base
ARG PROTOC_VERSION=3.1.0
ARG GOGO_VERSION=master
RUN apt-get update && apt-get install -y \
 git \
 unzip \
 && true
RUN wget -q https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip && unzip protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local

RUN go get -d github.com/gogo/protobuf/protoc-gen-gogofaster \
  && cd /go/src/github.com/gogo/protobuf \
        && git checkout -q $GOGO_VERSION \
        && go install ./protoc-gen-gogo ./protoc-gen-gogofaster ./protoc-gen-gogoslick

WORKDIR /go/src/github.com/moby/buildkit

# Generate into a subdirectory because if it is in the root then the
# extraction with `docker export` ends up putting `.dockerenv`, `dev`,
# `sys` and `proc` into the source directory. With this we can use
# `tar --strip-components=1 generated-files` on the output of `docker
# export`.
FROM gobuild-base AS generated
RUN mkdir /generated-files
RUN --mount=target=/tmp/src \
	cp -r /tmp/src/. . && \
	git add -A && \
	go generate ./... && \
	git ls-files -m --others -- **/*.pb.go | tar -cf - --files-from - | tar -C /generated-files -xf -

FROM scratch AS update
COPY --from=generated generated-files /

FROM gobuild-base AS validate
RUN --mount=target=/tmp/src \
	cp -r /tmp/src/. . && \
	go generate ./... && git diff && ./hack/validate-generated-files check
