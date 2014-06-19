TARGET = httap
LIBPCAP = vendor/libpcap

all: export CGO_CFLAGS  = -I$(realpath $(LIBPCAP))
all: export CGO_LDFLAGS = -L$(realpath $(LIBPCAP))
all: $(LIBPCAP)/libpcap.a
	go build -a

clean:
	go clean
	make -C $(LIBPCAP) clean

distclean:
	go clean
	rm -rf $(LIBPCAP)

test:
	@sudo echo -n
	go test -parallel 20 -exec sudo ./...

$(LIBPCAP)/libpcap.a: $(LIBPCAP)/configure
	cd $(LIBPCAP) && ./configure --disable-shared --quiet
	make -C $(LIBPCAP) all --quiet

$(LIBPCAP)/configure:
	git clone https://github.com/the-tcpdump-group/libpcap.git $(LIBPCAP) --quiet
	git -C $(LIBPCAP) checkout libpcap-1.5.3 --quiet

.PHONY: all clean distclean test
