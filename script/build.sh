#!/bin/sh
export DATE=$(date +%Y%m%d)
go build -a -ldflags "-X main.buildTag=${DATE} -extldflags '-static' -s -w"
upx --best httap

# if [ -f /.dockerenv ]; then
#   go test -a ./...
# else
#   go test -a -exec sudo ./...
# fi
