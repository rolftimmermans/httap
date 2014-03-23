package httpfwd

import (
    "fmt"
    "time"
    "io"
    "bufio"
    "net"
    "net/http"
    "log"
    "os"
    "strings"
    "code.google.com/p/gopacket"
    "code.google.com/p/gopacket/layers"
    "code.google.com/p/gopacket/pcap"
    "code.google.com/p/gopacket/tcpassembly"
    "code.google.com/p/gopacket/tcpassembly/tcpreader"
)

type Forwarder struct {
    Destination string
    ForwarderOptions

    transport http.Transport
    bufsize int32
    timeout time.Duration

    req *log.Logger
    err *log.Logger
}

type ForwarderOptions struct {
    Interfaces []string
    Port int
    ReplaceHost bool
    Verbose bool
}

func NewForwarder(dst string, opt ForwarderOptions) (*Forwarder) {
    fwd := &Forwarder {
        Destination: dst,
        ForwarderOptions: opt,

        bufsize: 65535,
        timeout: 10 * time.Millisecond,

        req: log.New(os.Stdout, "", log.Ltime | log.Ldate),
        err: log.New(os.Stderr, "", log.Ltime | log.Ldate),
    }

    fwd.transport.MaxIdleConnsPerHost = 6

    return fwd
}

func PcapVersion() (string) {
    return pcap.Version()
}

func (fwd *Forwarder) Start() {
    pool := tcpassembly.NewStreamPool(fwd)
    assembler := tcpassembly.NewAssembler(pool)

    packets := fwd.packets()
    ticker := time.Tick(time.Minute)

    for {
        select {
        case packet := <- packets:
            assembler.Assemble(
                packet.NetworkLayer().NetworkFlow(),
                packet.TransportLayer().(*layers.TCP))
        case <- ticker:
            assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
        }
    }
}

func (fwd *Forwarder) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
    reader := tcpreader.NewReaderStream()
    go fwd.handleStream(&netFlow, &reader)
    return &reader
}

func (fwd *Forwarder) newSource(intf string, filter string) (*gopacket.PacketSource) {
    handle, err := pcap.OpenLive(intf, fwd.bufsize, false, fwd.timeout)
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

func (fwd *Forwarder) packets() (chan gopacket.Packet) {
    filt := fwd.buildFilter()
    intfs := fwd.retrieveInterfaces()

    fwd.err.Printf("Wiretapping on port %d, forwarding to %s\n", fwd.Port, fwd.Destination)

    if fwd.Verbose {
        fwd.err.Printf("Listening on interfaces: %s\n", strings.Join(intfs, ", "))
        fwd.err.Printf("Using pcap filter: \"%s\"\n", filt)
    }

    channel := make(chan gopacket.Packet, 1000)
    for _, intf := range intfs {
        go fwd.packetsToChannel(fwd.newSource(intf, filt), channel)
    }
    return channel
}

func (fwd *Forwarder) buildFilter() (string) {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        fwd.err.Fatalln("Fatal error:", err)
    }

    filt := fmt.Sprintf("tcp dst port %d and (", fwd.Port)
    for i, addr := range addrs {
        if i > 0 {
            filt += " or "
        }
        filt += fmt.Sprintf("dst host %s", addr.(*net.IPNet).IP)
    }
    filt += ")"

    return filt
}

func (fwd* Forwarder) retrieveInterfaces() ([]string) {
    var names []string

    intfs, err := net.Interfaces()
    if err != nil {
        fwd.err.Fatalln("Fatal error:", err)
    }

    for _, intf := range intfs {
        addrs, err := intf.Addrs()
        if err != nil {
            fwd.err.Fatalln("Fatal error:", err)
        }

        if net.FlagUp & intf.Flags == net.FlagUp && len(addrs) > 0 {
            names = append(names, intf.Name)
        }
    }

    return names
}

func (fwd *Forwarder) packetsToChannel(source *gopacket.PacketSource, channel chan gopacket.Packet) {
    for {
        packet, err := source.NextPacket()
        switch err {
        default:
            fwd.err.Fatalln("Fatal error:", "Cannot activate wiretap")
        case io.EOF:
            close(channel)
            return
        case nil:
            channel <- packet
        case pcap.NextErrorTimeoutExpired:
        case pcap.NextErrorReadError:
            /* Ignore nonfatal read errors. */
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
