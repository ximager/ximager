ARG GOLANG_VERSION=1.21.3-alpine3.18

FROM golang:${GOLANG_VERSION} as builder

COPY . /go/src/github.com/go-sigma/sigma

WORKDIR /go/src/github.com/go-sigma/sigma

RUN set -eux && \
  apk add --no-cache make bash ncurses build-base git git-lfs

RUN make build-builder

FROM moby/buildkit:v0.12.2-rootless

USER root
RUN set -eux && \
  apk add --no-cache git-lfs && \
  mkdir -p /code/ && \
  chown -R 1000:1000 /opt/ && \
  chown -R 1000:1000 /code/

COPY --from=builder /go/src/github.com/go-sigma/sigma/bin/sigma-builder /usr/local/bin/sigma-builder

WORKDIR /code

USER 1000:1000
