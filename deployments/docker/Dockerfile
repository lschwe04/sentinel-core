# Build Stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Statisch kompilieren
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o sentinel-core cmd/server/main.go

# Final Stage (Minimal scratch image)
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /app/sentinel-core /sentinel-core
COPY certs/ /certs/
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/sentinel-core"]
