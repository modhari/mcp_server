FROM golang:1.23 AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/ecmp-trace ./cmd/server

FROM gcr.io/distroless/base-debian12
COPY --from=builder /bin/ecmp-trace /ecmp-trace
EXPOSE 8081
ENTRYPOINT ["/ecmp-trace"]
