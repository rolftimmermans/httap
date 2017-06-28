FROM golang
MAINTAINER Rolf Timmermans <rolftimmermans@voormedia.com>

RUN apt-get update && \
 DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apt-utils && \
 DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends flex bison && \
 DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends upx && \
 rm -rf /var/lib/apt/lists/*

WORKDIR /vendor

RUN git clone \
 --quiet \
 --depth 1 \
 --branch libpcap-1.8.1 \
 -c advice.detachedHead=false \
 https://github.com/the-tcpdump-group/libpcap.git libpcap && \
 cd libpcap && ./configure --disable-shared --quiet && \
 make all --quiet

ENV CGO_CFLAGS=-I/vendor/libpcap \
 CGO_LDFLAGS=-L/vendor/libpcap

RUN go get github.com/stretchr/testify/assert && \
 go get github.com/abursavich/ipsupport && \
 go get github.com/jessevdk/go-flags && \
 go get github.com/google/gopacket

WORKDIR /src/httap

COPY script/build.sh /
ENTRYPOINT ["/build.sh"]
