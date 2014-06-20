package httap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
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
	Transport    http.Transport
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

	destinations, err := ResolveAddrList(opts.Destinations)
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
		Transport:    http.Transport{MaxIdleConnsPerHost: 6},
	}
}

func PcapVersion() string {
	return pcap.Version()
}

func (fwd *Forwarder) Start() {
	pool := tcpassembly.NewStreamPool(fwd)
	assembler := tcpassembly.NewAssembler(pool)

	packets := fwd.wiretap()
	ticker := time.Tick(time.Minute)

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
	stream := tcpreader.NewReaderStream()

	go func() {
		buf := bufio.NewReader(&stream)

		for {
			req, err := http.ReadRequest(buf)
			if err == io.EOF {
				return
			} else if err != nil {
				fwd.Log.Println("Error:", err)
			} else {
				body := new(bytes.Buffer)
				if _, err := io.Copy(body, req.Body); err != nil {
					fwd.Log.Println("Error:", err)
				}
				go fwd.forwardRequest(&netFlow, req, body)
			}
		}
	}()

	return &stream
}

func (fwd *Forwarder) wiretap() chan gopacket.Packet {
	channel := make(chan gopacket.Packet, 100)
	filter := fwd.Sources.Filter()

	for _, intf := range fwd.Interfaces {
		handle, err := pcap.OpenLive(intf, fwd.Bufsize, fwd.Sources.RequiresPromisc(), fwd.Timeout)
		if err != nil {
			panic(err)
		}

		if err := handle.SetBPFFilter(filter); err != nil {
			panic(err)
		}

		go func(handle *pcap.Handle) {
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
		}(handle)
	}

	return channel
}

func (fwd *Forwarder) forwardRequest(netFlow *gopacket.Flow, req *http.Request, body *bytes.Buffer) {
	req.URL.Scheme = "http"
	req.URL.Host = req.Host

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
		dst := *dst

		/* If the destination IP is unset, use the original destination IP. */
		if dst.IP == nil {
			dst.IP = net.ParseIP(netFlow.Dst().String())
		}

		copy := copyRequest(req)
		copy.URL.Host = dst.String()
		copy.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		go fwd.sendRequest(copy, netFlow.Src().String(), req.URL.String())
	}
}

func (fwd *Forwarder) sendRequest(req *http.Request, origSrc, origURL string) {
	res, err := fwd.Transport.RoundTrip(req)
	if err != nil {
		fwd.Log.Println("Error:", err)
	} else {
		/* "The client must close the response body when finished with it." */
		defer res.Body.Close()
		fwd.Log.Printf("%s %s %s (%s) %d\n", origSrc, req.Method, origURL, req.URL.Host, res.StatusCode)
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
