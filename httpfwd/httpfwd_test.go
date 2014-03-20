package httpfwd

import (
    "time"
    "testing"
)

func TestNewForwarder(t *testing.T) {
    fwd := NewForwarder("lo0", ForwarderOptions{})

    if fwd == nil {
        t.Error("Forwarder is nil")
    }

    if fwd.bufsize != 65535 {
        t.Error("Bufsize is incorrect")
    }

    if fwd.timeout != time.Second / 100 {
        t.Error("Timeout is incorrect")
    }

    if fwd.req == nil {
        t.Error("Request logger is not set")
    }

    if fwd.err == nil {
        t.Error("Error logger is not set")
    }
}
