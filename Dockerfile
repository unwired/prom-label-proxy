FROM golang:1.21.6-alpine AS golang
WORKDIR /go/src/github.com/unwired/prom-label-proxy
COPY . .
ENV CGO_ENABLED=0
ENV GOPATH="/go/src/github.com/unwired"

RUN go test -timeout 30s -v ./...

ENTRYPOINT  [ "/bin/prom-label-proxy" ]
