package httpfwd

import (
	"bufio"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Forwarder struct {
	Destination string
	ForwarderOptions

	transport http.Transport
	bufsize   int32
	timeout   time.Duration

	req *log.Logger
	err *log.Logger
}

type ForwarderOptions struct {
	Port        int
	ReplaceHost bool
	Verbose     bool
}

func NewForwarder(dst string, opt ForwarderOptions) *Forwarder {
	fwd := &Forwarder{
		Destination:      dst,
		ForwarderOptions: opt,

		bufsize: 65535,
		timeout: 10 * time.Millisecond,

		req: log.New(os.Stdout, "", log.Ltime|log.Ldate),
		err: log.New(os.Stderr, "", log.Ltime|log.Ldate),
	}

	fwd.transport.MaxIdleConnsPerHost = 6

	return fwd
}

func PcapVersion() string {
	return pcap.Version()
}

func (fwd *Forwarder) Start() {
	pool := tcpassembly.NewStreamPool(fwd)
	assembler := tcpassembly.NewAssembler(pool)

	packets := fwd.packets()
	ticker := time.Tick(time.Minute)

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

func (fwd *Forwarder) newSource(intfName string, filter string) *gopacket.PacketSource {
	handle, err := pcap.OpenLive(intfName, fwd.bufsize, false, fwd.timeout)
	if err != nil {
		fwd.err.Fatalln("Fatal error:", err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		fwd.err.Fatalln("Fatal error:", err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.DecodeOptions = gopacket.NoCopy

	return source
}

func (fwd *Forwarder) packets() chan gopacket.Packet {
	intfs, err := pcap.FindAllDevs()
	if err != nil {
		fwd.err.Fatalln("Fatal error:", err)
	} else if len(intfs) == 0 {
		fwd.err.Fatalln("Fatal error:", "No interfaces found, are you root?")
	}

	filter := fwd.buildFilter(intfs)
	intfNames := fwd.interfaceNames(intfs)

	fwd.err.Printf("Wiretapping on port %d, forwarding to %s\n", fwd.Port, fwd.Destination)

	if fwd.Verbose {
		fwd.err.Printf("Listening on interfaces: %s\n", strings.Join(intfNames, ", "))
		fwd.err.Printf("Using pcap filter: \"%s\"\n", filter)
	}

	channel := make(chan gopacket.Packet, 1000)
	for _, intfName := range intfNames {
		go fwd.packetsToChannel(fwd.newSource(intfName, filter), channel)
	}
	return channel
}

func (fwd *Forwarder) buildFilter(intfs []pcap.Interface) string {
	filter := fmt.Sprintf("tcp dst port %d and (", fwd.Port)
	i := 0
	for _, intf := range intfs {
		for _, addr := range intf.Addresses {
			if i > 0 {
				filter += " or "
			}
			filter += fmt.Sprintf("dst host %s", addr.IP)
			i++
		}
	}
	filter += ")"

	return filter
}

func (fwd *Forwarder) interfaceNames(intfs []pcap.Interface) []string {
	var names []string

	for _, intf := range intfs {
		if len(intf.Addresses) > 0 {
			names = append(names, intf.Name)
		}
	}

	return names
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
			fwd.err.Println("Error:", err)
		} else {
			go fwd.forwardRequest(netFlow, req)
		}
	}
}

func (fwd *Forwarder) forwardRequest(netFlow *gopacket.Flow, req *http.Request) {
	/* Make the HTTP transporter happy by supplying scheme and host. */
	req.URL.Scheme = "http"
	req.URL.Host = canonicalAddr(fwd.Destination)

	/* Copy the URL to set the host from the HTTP headers. */
	url := *req.URL
	url.Host = req.Host

	if fwd.ReplaceHost {
		req.Host = fwd.Destination
	}

	res, err := fwd.transport.RoundTrip(req)
	if err != nil {
		fwd.err.Println("Error:", err)
	} else {
		/* "The client must close the response body when finished with it." */
		defer res.Body.Close()
		fwd.req.Printf("%s %s %s %d\n", netFlow.Src(), req.Method, &url, res.StatusCode)
		if fwd.Verbose {
			req.Body = nil
			req.Write(os.Stdout)
		}
	}

}

func hasPort(s string) bool {
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

func canonicalAddr(addr string) string {
	if !hasPort(addr) {
		return addr + ":80"
	}
	return addr
}
