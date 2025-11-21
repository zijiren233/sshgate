FROM golang:1.25.2-alpine AS builder

WORKDIR /sshgate

COPY ./ /sshgate

RUN go build -trimpath -ldflags "-s -w" -o sshgate

FROM alpine:latest

RUN mkdir -p /sshgate

WORKDIR /sshgate

RUN apk add --no-cache tzdata && \
    rm -rf /var/cache/apk/*

COPY --from=builder /sshgate/sshgate /usr/local/bin/sshgate

ENV PUID=0 PGID=0 UMASK=022

EXPOSE 2222

ENTRYPOINT ["sshgate"]
