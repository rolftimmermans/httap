package httap

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

func TestNewWiretapOptions(t *testing.T) {
	tap := NewWiretap(Options{})

	assert.NotNil(t, tap)

	assert.Equal(t, tap.BufSize, 65535)
	assert.Equal(t, tap.Timeout, time.Second/100)

	assert.NotNil(t, tap.Log)
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

func TestStartWiretapMultipliesRequest(t *testing.T) {
	orig, copies := performMultipliedHttpWiretap(Options{Multiply: 2.0}, nil)

	assert.Equal(t, copies[0].URL.String(), orig.URL.String())
	assert.Equal(t, copies[0].Header, orig.Header)
	assert.Equal(t, copies[0].Host, orig.Host)

	assert.Equal(t, copies[1].URL.String(), orig.URL.String())
	assert.Equal(t, copies[1].Header, orig.Header)
	assert.Equal(t, copies[1].Host, orig.Host)
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

func TestStartWiretapFiltersHttpVerb(t *testing.T) {
	orig, copy := performHttpWiretap(Options{Methods: []string{"GET"}}, func(host string) {
		http.Post(host, "text/plain", strings.NewReader(""))
		http.Get(host)
	})

	assert.Equal(t, copy.URL.String(), orig.URL.String())
	assert.Equal(t, copy.Host, orig.Host)
	assert.Equal(t, copy.Method, "GET")
}

func createHttpChannel(n int) (string, chan requestInfo) {
	channel := make(chan requestInfo)

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	i := 0
	handler := func(writer http.ResponseWriter, req *http.Request) {
		body, _ := ioutil.ReadAll(req.Body)
		channel <- requestInfo{req, body}
		i++
		if i == n {
			defer listener.Close()
		}
	}

	go http.Serve(listener, http.HandlerFunc(handler))

	return listener.Addr().String(), channel
}

func performMultipliedHttpWiretap(opts Options, callback func(string)) (requestInfo, []requestInfo) {
	n := int(opts.Multiply)
	if n == 0 {
		n = 1
	}

	if callback == nil {
		callback = func(host string) {
			http.Get(host)
		}
	}

	tstHost, tstReqs := createHttpChannel(n)
	prdHost, prdReqs := createHttpChannel(1)

	opts.Sources = []string{prdHost}
	opts.Destinations = []string{tstHost}
	wiretap := NewWiretap(opts)
	wiretap.RepeatDelay = 0

	go wiretap.Start()

	/* Sleep to allow wiretap to start up before issuing request. */
	time.Sleep(50 * time.Millisecond)
	go callback("http://" + prdHost)

	orig := <-prdReqs
	copy := make([]requestInfo, n)
	for i := 0; i < n; i++ {
		copy[i] = <-tstReqs
	}

	return orig, copy
}

func performHttpWiretap(opts Options, callback func(string)) (requestInfo, requestInfo) {
	orig, copy := performMultipliedHttpWiretap(opts, callback)
	return orig, copy[0]
}
