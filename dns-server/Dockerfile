FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /dns-server .

FROM scratch
COPY --from=builder /dns-server /dns-server
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/dns-server"]
