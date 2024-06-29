FROM golang:1.22.4

WORKDIR /app

COPY . ./

RUN make build

CMD ["/tmp/bin/web"]
