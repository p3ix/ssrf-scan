FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /smtp-ldap-listener .

FROM scratch
COPY --from=builder /smtp-ldap-listener /smtp-ldap-listener
EXPOSE 21/tcp 25/tcp 389/tcp 587/tcp 636/tcp
ENTRYPOINT ["/smtp-ldap-listener"]
