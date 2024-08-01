FROM golang:1.22.2-alpine AS builder
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomqs"

RUN apk add --no-cache make git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o sbomqs-amd64 .

# Multi-stage build for arm64
FROM golang:1.22.2-alpine AS builder-arm64
RUN apk add --no-cache make git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -o sbomqs-arm64 .

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomqs"
LABEL org.opencontainers.image.description="Quality metrics for your sboms"
LABEL org.opencontainers.image.licenses=Apache-2.0

# Copy our static executable
COPY --from=builder /app/sbomqs-amd64 /app/sbomqs-amd64
COPY --from=builder-arm64 /app/sbomqs-arm64 /app/sbomqs-arm64



# Disable version check
ENV INTERLYNK_DISABLE_VERSION_CHECK=true

ENTRYPOINT [ "/app/sbomqs-amd64" ]
