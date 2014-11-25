TARGET = httap
LIBPCAP = vendor/libpcap
DATE = $(shell date +%Y%m%d)

all: export CGO_CFLAGS  = -I$(realpath $(LIBPCAP))
all: export CGO_LDFLAGS = -L$(realpath $(LIBPCAP))
all: $(LIBPCAP)/libpcap.a
	go get github.com/jessevdk/go-flags
	go get code.google.com/p/gopacket
	go build -a -ldflags "-X main.buildTag $(DATE)"

clean:
	go clean
	make -C $(LIBPCAP) clean

distclean:
	go clean
	rm -rf $(LIBPCAP)

test:
	@sudo echo -n
	go fmt ./...
	go test -parallel 20 -exec sudo ./...

$(LIBPCAP)/libpcap.a: $(LIBPCAP)/configure
	cd $(LIBPCAP) && ./configure --disable-shared --quiet
	make -C $(LIBPCAP) all --quiet

$(LIBPCAP)/configure:
	git clone https://github.com/the-tcpdump-group/libpcap.git $(LIBPCAP) --quiet
	cd $(LIBPCAP) && git checkout libpcap-1.5.3 --quiet

.PHONY: all clean distclean test
