FROM golang:1.25 AS builder

WORKDIR /opt/app/

COPY go.* .
COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-extldflags '-static'" -o portal main.go

FROM alpine
WORKDIR /opt/app/

COPY --from=builder /opt/app/portal .
COPY templates templates

RUN apk update \
    && apk add --no-cache ca-certificates openssl curl \
    && update-ca-certificates
EXPOSE 8080
ENTRYPOINT [ "/opt/app/portal" ]