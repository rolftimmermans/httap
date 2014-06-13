package httpfwd

import (
	"bufio"
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
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
)

type Forwarder struct {
	Sources      AddrList
	Destinations AddrList
	Interfaces   []string
	Headers      map[string]string
	Log          *log.Logger
	Verbose      bool
	Bufsize      int32
	Timeout      time.Duration
	transport    http.Transport
}

type Options struct {
	Sources      []string `short:"s" long:"src"     description:"Source(s) to wiretap HTTP traffic from" value-name:"HOST[:PORT]" default:"*:80" default-mask:"*:80 by default"`
	Destinations []string `short:"d" long:"dst"     description:"Destination(s) to forward copy of HTTP traffic to" value-name:"HOST[:PORT]" required:"true"`
	Headers      []string `short:"H" long:"header"  description:"Set or replace request header in duplicated traffic" value-name:"LINE"`
	Verbose      bool     `short:"v" long:"verbose" description:"Show extra information, including all request headers"`
}

func NewForwarder(opts Options) *Forwarder {
	sources, err := ResolveAddrPatterns(opts.Sources)
	if err != nil {
		panic(err)
	}

	destinations, err := ResolveAddrPatterns(opts.Destinations)
	if err != nil {
		panic(err)
	}

	headers := make(map[string]string)
	for _, header := range opts.Headers {
		parts := strings.SplitN(header, ":", 2)
		headers[strings.ToLower(parts[0])] = strings.TrimLeft(parts[1], " ")
	}

	return &Forwarder{
		Sources:      sources,
		Destinations: destinations,
		Interfaces:   FindInterfaces(),
		Headers:      headers,
		Log:          log.New(os.Stdout, "", log.LstdFlags),
		Verbose:      opts.Verbose,
		Bufsize:      65535,
		Timeout:      10 * time.Millisecond,
		transport: http.Transport{
			MaxIdleConnsPerHost: 6,
		},
	}
}

func PcapVersion() string {
	return pcap.Version()
}

func (fwd *Forwarder) Start() {
	pool := tcpassembly.NewStreamPool(fwd)
	assembler := tcpassembly.NewAssembler(pool)
	ticker := time.Tick(time.Minute)
	packets := fwd.packets()

	if fwd.Verbose {
		fmt.Fprintf(os.Stderr, "Listening on interfaces %s\n", strings.Join(fwd.Interfaces, ", "))
	}

	fmt.Fprintf(os.Stderr, "Wiretapping HTTP traffic to %s and forwarding to %s...\n", fwd.Sources, fwd.Destinations)

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

func (fwd *Forwarder) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	reader := tcpreader.NewReaderStream()
	go fwd.handleStream(&netFlow, &reader)
	return &reader
}

func (fwd *Forwarder) packets() chan gopacket.Packet {
	channel := make(chan gopacket.Packet, 1000)
	for _, intf := range fwd.Interfaces {
		go fwd.packetsToChannel(fwd.newSource(intf, fwd.Sources.Filter()), channel)
	}
	return channel
}

func (fwd *Forwarder) newSource(intf string, filter string) *gopacket.PacketSource {
	handle, err := pcap.OpenLive(intf, fwd.Bufsize, fwd.Sources.RequiresPromisc(), fwd.Timeout)
	if err != nil {
		panic(err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.DecodeOptions = gopacket.NoCopy

	return source
}

func (fwd *Forwarder) packetsToChannel(source *gopacket.PacketSource, channel chan gopacket.Packet) {
	for {
		packet, err := source.NextPacket()
		if err == io.EOF {
			close(channel)
			return
		} else if err == nil {
			channel <- packet
		}
	}
}

func (fwd *Forwarder) handleStream(netFlow *gopacket.Flow, stream *tcpreader.ReaderStream) {
	buf := bufio.NewReader(stream)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			fwd.Log.Println("Error:", err)
		} else {
			go fwd.forwardRequest(netFlow, req)
		}
	}
}

func (fwd *Forwarder) forwardRequest(netFlow *gopacket.Flow, req *http.Request) {
	req.URL.Scheme = "http"
	req.URL.Host = req.Host

	originalPeer := netFlow.Src().String()
	originalURL := req.URL.String()

	for key, value := range fwd.Headers {
		if value == "" {
			req.Header.Del(key)
			if key == "user-agent" {
				/* "Use the defaultUserAgent unless the Header contains one,
				   which may be blank to not send the header." */
				req.Header.Set(key, "")
			}
		} else {
			req.Header.Set(key, value)
			if key == "host" {
				req.Host = value
			}
		}
	}

	for _, dst := range fwd.Destinations {
		copy := copyRequest(req)
		copy.URL.Host = dst.String()
		go fwd.sendRequest(copy, originalPeer, originalURL)
	}
}

func (fwd *Forwarder) sendRequest(req *http.Request, originalPeer, originalURL string) {
	res, err := fwd.transport.RoundTrip(req)
	if err != nil {
		fwd.Log.Println("Error:", err)
	} else {
		/* "The client must close the response body when finished with it." */
		defer res.Body.Close()
		fwd.Log.Printf("%s %s %s (%s) %d\n", originalPeer, req.Method, originalURL, req.URL.Host, res.StatusCode)
		if fwd.Verbose {
			req.Body = nil
			req.Write(os.Stdout)
		}
	}
}

func copyRequest(req *http.Request) *http.Request {
	url := *req.URL
	copy := *req
	copy.URL = &url
	return &copy
}
