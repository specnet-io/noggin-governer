# Static Go binary on scratch: ~10 MB image, no shell, runs as an unprivileged user.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4-alpine3.23 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/noggin-governer . \
 && mkdir -p /out/data

FROM scratch
ARG VERSION=dev
LABEL org.opencontainers.image.title="noggin-governer" \
      org.opencontainers.image.description="Adds administrative controls to noggin based workflows." \
      org.opencontainers.image.source="https://github.com/specnet-io/noggin-governer" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/noggin-governer /noggin-governer
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV GOVERNER_DATA_DIR=/data
EXPOSE 8080 8081
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD ["/noggin-governer", "healthcheck"]
ENTRYPOINT ["/noggin-governer"]
