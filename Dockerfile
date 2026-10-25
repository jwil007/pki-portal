# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/pki-portal ./cmd/pki-portal

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pki-portal /pki-portal
ENV PORTAL_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/pki-portal"]
