# Use buildx for multi-platform builds
# Build stage
FROM --platform=$BUILDPLATFORM golang:1.22.2-alpine AS builder
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomqs"

RUN apk add --no-cache make git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build for multiple architectures
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -o sbomqs .

# Final stage
FROM scratch
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomqs"
LABEL org.opencontainers.image.description="Quality metrics for your sboms"
LABEL org.opencontainers.image.licenses=Apache-2.0

# Copy our static executable
COPY --from=builder /app/sbomqs /app/sbomqs

ENTRYPOINT ["/app/sbomqs"]
