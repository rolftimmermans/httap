package httpfwd

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

type requestInfo struct {
	*http.Request
	consumedBody []byte
}

func TestNewForwarderOptions(t *testing.T) {
	fwd := NewForwarder(Options{})

	assert.NotNil(t, fwd)

	assert.Equal(t, fwd.Bufsize, 65535)
	assert.Equal(t, fwd.Timeout, time.Second/100)

	assert.NotNil(t, fwd.Log)
}

func TestPcapVersion(t *testing.T) {
	assert.Contains(t, PcapVersion(), "libpcap version")
}

func TestStartWiretap(t *testing.T) {
	orig, copy := performHttpWiretap(Options{}, nil)

	assert.Equal(t, copy.URL.String(), orig.URL.String())
	assert.Equal(t, copy.Header, orig.Header)
	assert.Equal(t, copy.Host, orig.Host)
}

func TestStartWiretapReplacesHost(t *testing.T) {
	orig, copy := performHttpWiretap(Options{Headers: []string{"Host: example.com"}}, nil)

	assert.Equal(t, copy.URL.String(), orig.URL.String())
	assert.Equal(t, copy.Header, orig.Header)
	assert.Equal(t, copy.Host, "example.com")
}

func TestStartWiretapForwardsBody(t *testing.T) {
	orig, copy := performHttpWiretap(Options{}, func(host string) {
		http.Post(host, "text/plain", strings.NewReader("FOO BAR BAZ"))
	})

	assert.Equal(t, copy.URL.String(), orig.URL.String())
	assert.Equal(t, copy.Header, orig.Header)
	assert.Equal(t, string(copy.consumedBody), "FOO BAR BAZ")
}

/* Note: HTTP client does not support 100 continue/delayed body submission yet. */
func TestStartWiretapForwardsBodyAfterHttpContinue(t *testing.T) {
	orig, copy := performHttpWiretap(Options{}, func(host string) {
		client := &http.Client{}
		req, _ := http.NewRequest("POST", host, strings.NewReader("FOO BAR BAZ"))
		req.Header.Set("Expect", "100-continue")
		client.Do(req)
	})

	assert.Equal(t, copy.URL.String(), orig.URL.String())
	assert.Equal(t, copy.Header, orig.Header)
	assert.Equal(t, string(copy.consumedBody), "FOO BAR BAZ")
}

func createHttpChannel() (string, chan requestInfo) {
	channel := make(chan requestInfo)

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	handler := func(writer http.ResponseWriter, req *http.Request) {
		body, _ := ioutil.ReadAll(req.Body)
		channel <- requestInfo{req, body}
		defer listener.Close()
	}

	go http.Serve(listener, http.HandlerFunc(handler))

	return listener.Addr().String(), channel
}

func performHttpWiretap(opts Options, callback func(string)) (requestInfo, requestInfo) {
	if callback == nil {
		callback = func(host string) {
			http.Get(host)
		}
	}

	tstHost, tstReqs := createHttpChannel()
	prdHost, prdReqs := createHttpChannel()

	opts.Sources = []string{prdHost}
	opts.Destinations = []string{tstHost}
	forwarder := NewForwarder(opts)

	go forwarder.Start()

	/* Sleep to allow forwarder to start up before issuing request. */
	time.Sleep(50 * time.Millisecond)
	go callback("http://" + prdHost)

	orig := <-prdReqs
	copy := <-tstReqs

	return orig, copy
}
