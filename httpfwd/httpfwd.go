package httpfwd

import (
    "fmt"
    "time"
    "io"
    "bufio"
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
    Interface string
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
    handle := fwd.newHandle()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packetSource.DecodeOptions = gopacket.NoCopy

    pool := tcpassembly.NewStreamPool(fwd)
    assembler := tcpassembly.NewAssembler(pool)

    fwd.err.Printf("Wiretapping %s on port %d, forwarding to %s...\n",
        fwd.Interface, fwd.Port, fwd.Destination)

    for {
        packet, err := packetSource.NextPacket()
        switch err {
        default:
            fwd.err.Fatalf("Fatal error: Cannot activate wiretap on %s\n", fwd.Interface)
        case io.EOF: break
        case pcap.NextErrorTimeoutExpired: continue
        case pcap.NextErrorReadError:
            fwd.err.Println("Error:", "Cannot read packets")
        case nil:
            assembler.Assemble(
                packet.NetworkLayer().NetworkFlow(),
                packet.TransportLayer().(*layers.TCP))
        }
    }
}

func (fwd *Forwarder) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
    reader := tcpreader.NewReaderStream()
    go fwd.handleStream(&netFlow, &reader)
    return &reader
}

func (fwd *Forwarder) newHandle() (*pcap.Handle) {
    handle, err := pcap.OpenLive(fwd.Interface, fwd.bufsize, false, fwd.timeout)
    if err != nil {
        panic(err)
    }

    filt := fmt.Sprintf("tcp dst port %d", fwd.Port)
    if err := handle.SetBPFFilter(filt); err != nil {
        panic(err)
    }

    return handle
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
