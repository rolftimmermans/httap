TARGET = httptap

all:
	go build

clean:
	rm $(TARGET)

test:
	go test ./...

.PHONY: all clean test
