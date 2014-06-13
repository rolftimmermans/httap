package httpfwd

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"net"
)

func TestAddrFilter(t *testing.T) {
	addrs := []*net.TCPAddr{
		&net.TCPAddr{IP: net.IPv6loopback, Port: 80},
		&net.TCPAddr{IP: net.IPv6loopback, Port: 443},
	}
	assert.Equal(t, addrFilter(addrs), "(dst host ::1 and tcp dst port 80) or (dst host ::1 and tcp dst port 443)")
}

func TestAddrList(t *testing.T) {
	addrs := []*net.TCPAddr{
		&net.TCPAddr{IP: net.IPv6loopback, Port: 80},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80},
	}
	assert.Equal(t, addrList(addrs), "127.0.0.1:80, [::1]:80")
}
func TestResolveAddrPatternsDomains(t *testing.T) {
	var addrs []*net.TCPAddr

	addrs, _ = resolveAddrPatterns([]string{"localhost"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80})

	addrs, _ = resolveAddrPatterns([]string{"localhost:https"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})

	addrs, _ = resolveAddrPatterns([]string{"localhost:64123"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 64123})
}

func TestResolveAddrPatternsIPv4(t *testing.T) {
	var addrs []*net.TCPAddr

	addrs, _ = resolveAddrPatterns([]string{"127.0.0.1"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80})

	addrs, _ = resolveAddrPatterns([]string{"127.0.0.1:https"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})

	addrs, _ = resolveAddrPatterns([]string{"127.0.0.1:64123"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 64123})
}

func TestResolveAddrPatternsIPv6(t *testing.T) {
	var addrs []*net.TCPAddr

	addrs, _ = resolveAddrPatterns([]string{"[::1]"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv6loopback, Port: 80})

	addrs, _ = resolveAddrPatterns([]string{"[::1]:https"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv6loopback, Port: 443})

	addrs, _ = resolveAddrPatterns([]string{"[::1]:64123"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv6loopback, Port: 64123})
}

func TestResolveAddrPatternsMultiple(t *testing.T) {
	var addrs []*net.TCPAddr

	addrs, _ = resolveAddrPatterns([]string{"localhost:64123", "[::1]:12301"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 64123})
	assert.Equal(t, *(addrs[1]), net.TCPAddr{IP: net.IPv6loopback, Port: 12301})

	addrs, _ = resolveAddrPatterns([]string{"[::1]:http", "[::1]:80"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv6loopback, Port: 80})
	assert.Equal(t, len(addrs), 1)
}

func TestResolveAddrPatternsWildcard(t *testing.T) {
	var addrs []*net.TCPAddr

	addrs, _ = resolveAddrPatterns([]string{"*"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv6loopback, Port: 80})
	assert.Equal(t, *(addrs[1]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80})

	addrs, _ = resolveAddrPatterns([]string{"*:80"})
	assert.Equal(t, *(addrs[0]), net.TCPAddr{IP: net.IPv6loopback, Port: 80})
	assert.Equal(t, *(addrs[1]), net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80})
}
