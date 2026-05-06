FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /http-server .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /http-server /app/http-server
COPY static/ /app/static/
RUN mkdir -p /data /certs
EXPOSE 80 443 8080
ENTRYPOINT ["/app/http-server"]
