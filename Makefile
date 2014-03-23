TARGET = httptap

all:
	go build

clean:
	go clean

test:
	go test ./...

.PHONY: all clean test
