ARG GOLANG_VERSION=1.21.5-alpine3.18
ARG BUILDKIT_VERSION=v0.12.4-rootless
ARG ALPINE_VERSION=3.18

FROM alpine:${ALPINE_VERSION} as cosign

ARG COSIGN_VERSION=v2.2.2
ARG TARGETOS TARGETARCH

RUN set -eux && \
  sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
  apk add --no-cache wget && \
  wget -O /tmp/cosign https://github.com/sigstore/cosign/releases/download/"${COSIGN_VERSION}"/cosign-"${TARGETOS}"-"${TARGETARCH}" && \
  chmod +x /tmp/cosign

FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION} as builder

RUN set -eux && \
  sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
  apk add --no-cache make bash ncurses build-base git openssl

COPY . /go/src/github.com/go-sigma/sigma
WORKDIR /go/src/github.com/go-sigma/sigma

ARG TARGETOS TARGETARCH

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build GOOS=$TARGETOS GOARCH=$TARGETARCH make build-builder

FROM moby/buildkit:${BUILDKIT_VERSION}

USER root
RUN set -eux && \
  sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
  apk add --no-cache git-lfs && \
  mkdir -p /code/ && \
  chown -R 1000:1000 /opt/ && \
  chown -R 1000:1000 /code/

COPY --from=cosign /tmp/cosign /usr/local/bin/cosign
COPY --from=builder /go/src/github.com/go-sigma/sigma/bin/sigma-builder /usr/local/bin/sigma-builder

WORKDIR /code

USER 1000:1000
