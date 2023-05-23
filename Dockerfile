FROM golang:1.20-alpine AS builder
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomqs"

RUN apk add --no-cache make
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make ; make build 

FROM scratch 
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomqs"
COPY --from=builder /app/build/sbomqs /app/sbomqs
ENV INTERLYNK_DISABLE_VERSION_CHECK=true

ENTRYPOINT [ "/app/sbomqs", "score", "-j", "/app/inputfile"]