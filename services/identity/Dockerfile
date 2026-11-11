FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG IDENTITY_SOURCE_SHA=development
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN test "$(go env GOVERSION)" = go1.27.4 && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X github.com/evilsysadmin/shadowops-infra/services/identity/runtime.BuildSHA=$IDENTITY_SOURCE_SHA" \
    -o /out/identity ./cmd/service-staging
# Inspect the actual stripped cross-compiled executable before it enters scratch.
RUN set -eu; \
    test "$(go version /out/identity)" = "/out/identity: go1.27.4"; \
    go version -m /out/identity | grep -Fqx "$(printf '\tbuild\tGOOS=%s' "$TARGETOS")"; \
    go version -m /out/identity | grep -Fqx "$(printf '\tbuild\tGOARCH=%s' "$TARGETARCH")"

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/identity /app/identity
USER 65532:65532
EXPOSE 9443
ENV IDENTITY_STAGING_CONFIG_FILE=/run/secrets/identity-staging.json
ENTRYPOINT ["/app/identity"]
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=3 CMD ["/app/identity", "healthcheck"]
