package httap

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
)

type Wiretap struct {
	Sources      AddrList
	Destinations AddrList
	Interfaces   []string
	Headers      map[string]string
	Log          *log.Logger
	Verbose      bool
	Bufsize      int32
	Timeout      time.Duration
	Transport    http.Transport
}

type Options struct {
	Sources      []string `short:"s" long:"src"     description:"Source(s) to wiretap HTTP traffic from" value-name:"HOST[:PORT]" default:"*:80" default-mask:"*:80 by default"`
	Destinations []string `short:"d" long:"dst"     description:"Destination(s) to forward copy of HTTP traffic to" value-name:"HOST[:PORT]" required:"true"`
	Headers      []string `short:"H" long:"header"  description:"Set or replace request header in duplicated traffic" value-name:"LINE"`
	Verbose      bool     `short:"v" long:"verbose" description:"Show extra information, including all request headers"`
}

func NewWiretap(opts Options) *Wiretap {
	sources, err := ResolveAddrPatterns(opts.Sources)
	if err != nil {
		panic(err)
	}

	destinations, err := ResolveAddrList(opts.Destinations)
	if err != nil {
		panic(err)
	}

	headers := make(map[string]string)
	for _, header := range opts.Headers {
		parts := strings.SplitN(header, ":", 2)
		headers[strings.ToLower(parts[0])] = strings.TrimLeft(parts[1], " ")
	}

	return &Wiretap{
		Sources:      sources,
		Destinations: destinations,
		Interfaces:   FindInterfaces(),
		Headers:      headers,
		Log:          log.New(os.Stdout, "", log.LstdFlags),
		Verbose:      opts.Verbose,
		Bufsize:      65535,
		Timeout:      10 * time.Millisecond,
		Transport:    http.Transport{MaxIdleConnsPerHost: 6},
	}
}

func PcapVersion() string {
	return pcap.Version()
}

func (tap *Wiretap) Start() {
	pool := tcpassembly.NewStreamPool(tap)
	assembler := tcpassembly.NewAssembler(pool)

	packets := tap.packets()
	ticker := time.Tick(time.Minute)

	if tap.Verbose {
		fmt.Fprintf(os.Stderr, "Listening on interfaces %s\n", strings.Join(tap.Interfaces, ", "))
	}

	fmt.Fprintf(os.Stderr, "Wiretapping HTTP traffic to %s and forwarding to %s...\n", tap.Sources, tap.Destinations)

	for {
		select {
		case packet := <-packets:
			assembler.Assemble(
				packet.NetworkLayer().NetworkFlow(),
				packet.TransportLayer().(*layers.TCP))
		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
		}
	}
}

func (tap *Wiretap) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	stream := NewStream(tap, netFlow, tcpFlow)
	go stream.Consume()
	return stream
}

func (tap *Wiretap) packets() chan gopacket.Packet {
	channel := make(chan gopacket.Packet, 100)
	filter := tap.Sources.Filter()

	for _, intf := range tap.Interfaces {
		handle, err := pcap.OpenLive(intf, tap.Bufsize, tap.Sources.RequiresPromisc(), tap.Timeout)
		if err != nil {
			panic(err)
		}

		if err := handle.SetBPFFilter(filter); err != nil {
			panic(err)
		}

		go tap.capture(handle, channel)
	}

	return channel
}

func (tap *Wiretap) capture(handle *pcap.Handle, channel chan gopacket.Packet) {
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.DecodeOptions = gopacket.NoCopy

	for {
		packet, err := src.NextPacket()
		if err == io.EOF {
			return
		} else if err == nil {
			channel <- packet
		}
	}
}
