package httpfwd

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/tcpassembly"
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
	"net"
	"net/http"
)

type testReaderFactory struct {
	Forwarder
	tcpreader.ReaderStream
}

func (fwd *testReaderFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	reader := fwd.ReaderStream
	go fwd.handleStream(&netFlow, &reader)
	return &reader
}

func TestNewForwarder(t *testing.T) {
	fwd := NewForwarder("lo0", ForwarderOptions{})

	assert.NotNil(t, fwd)

	assert.Equal(t, fwd.bufsize, 65535)
	assert.Equal(t, fwd.timeout, time.Second/100)

	assert.NotNil(t, fwd.req)
	assert.NotNil(t, fwd.err)
}

func TestPcapVersion(t *testing.T) {
	assert.Contains(t, PcapVersion(), "libpcap version")
}

func TestHandleStream(t *testing.T) {
	netFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.IP{1, 2, 3, 4}),
		layers.NewIPEndpoint(net.IP{5, 6, 7, 8}))

	readerFactory := &testReaderFactory{
		Forwarder:    *NewForwarder("lo0", ForwarderOptions{}),
		ReaderStream: tcpreader.NewReaderStream(),
	}

	pool := tcpassembly.NewStreamPool(readerFactory)
	assembler := tcpassembly.NewAssembler(pool)

	assembler.Assemble(netFlow, &layers.TCP{
		SrcPort:   1,
		DstPort:   2,
		SYN:       true,
		Seq:       1000,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
	})
}
