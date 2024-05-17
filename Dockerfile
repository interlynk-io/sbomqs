FROM golang:1.22.2-alpine AS builder
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomqs"

RUN apk add --no-cache make git bash grep
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN make ; make build

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomqs"
LABEL org.opencontainers.image.description="Quality metrics for your sboms"
LABEL org.opencontainers.image.licenses=Apache-2.0

# Copy the certs from the builder image
COPY --from=builder /bin/bash /bin/bash
COPY --from=builder /bin/grep /bin/grep
COPY --from=builder /lib /lib
COPY --from=builder /usr /usr


# Copy our static executable
COPY --from=builder /app/build/sbomqs /app/sbomqs

# Disable version check
ENV INTERLYNK_DISABLE_VERSION_CHECK=true

ENTRYPOINT [ "/app/sbomqs" ]
