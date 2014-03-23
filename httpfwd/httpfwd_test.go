package httpfwd

import (
    "time"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestNewForwarder(t *testing.T) {
    fwd := NewForwarder("lo0", ForwarderOptions{})

    assert.NotNil(t, fwd)
    assert.Equal(t, 65535, fwd.bufsize)
    assert.Equal(t, time.Second / 100, fwd.timeout)
    assert.NotNil(t, fwd.req)
    assert.NotNil(t, fwd.err)
}
