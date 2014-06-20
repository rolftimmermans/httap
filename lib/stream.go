package httap

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
)

type Stream struct {
	tcpreader.ReaderStream
	tap  *Wiretap
	flow gopacket.Flow
}

func NewStream(tap *Wiretap, netFlow, tcpFlow gopacket.Flow) *Stream {
	return &Stream{
		ReaderStream: tcpreader.NewReaderStream(),
		tap:          tap,
		flow:         netFlow,
	}
}

func (st *Stream) Consume() {
	buf := bufio.NewReader(st)

	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			st.tap.Log.Println("Error:", err)
		} else {
			st.forward(req)
		}
	}
}

func (st *Stream) forward(req *http.Request) {
	req.URL.Scheme = "http"
	req.URL.Host = req.Host

	body := new(bytes.Buffer)
	if _, err := io.Copy(body, req.Body); err != nil {
		st.tap.Log.Println("Error:", err)
	}

	for key, value := range st.tap.Headers {
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

	for _, dst := range st.tap.Destinations {
		go st.send(st.copy(req, body, dst), req.URL.String())
	}
}

func (st *Stream) send(req *http.Request, url string) {
	res, err := st.tap.Transport.RoundTrip(req)
	if err != nil {
		st.tap.Log.Println("Error:", err)
	} else {
		/* "The client must close the response body when finished with it." */
		defer res.Body.Close()
		st.tap.Log.Printf("%s %s %s (%s) %d\n", st.flow.Src().String(), req.Method, url, req.URL.Host, res.StatusCode)
		if st.tap.Verbose {
			req.Body = nil
			req.Write(os.Stdout)
		}
	}
}

func (st *Stream) copy(req *http.Request, body *bytes.Buffer, dst *net.TCPAddr) *http.Request {
	host := *dst

	/* If the destination IP is unset, use the original destination IP. */
	if host.IP == nil {
		host.IP = net.ParseIP(st.flow.Dst().String())
	}

	url := *req.URL
	copy := *req
	copy.URL = &url
	copy.URL.Host = host.String()
	copy.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

	return &copy
}
