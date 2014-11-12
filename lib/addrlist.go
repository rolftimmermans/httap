package httap

import (
	"fmt"
	"net"
	"reflect"
	"strings"
)

type AddrList []*net.TCPAddr

type AddrError struct {
	str string
	err error
}

func FindInterfaces() (intfsWithAddress []string) {
	intfs, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, intf := range intfs {
		addrs, err := intf.Addrs()

		/* VMWare interfaces are not supported by libpcap. */
		if err == nil && len(addrs) > 0 && !strings.HasPrefix(intf.Name, "vmnet") {
			intfsWithAddress = append(intfsWithAddress, intf.Name)
		}
	}
	return
}

func ResolveAddrList(strs []string) (AddrList, error) {
	return resolveAddrListOrPatterns(strs, false)
}

func ResolveAddrPatterns(strs []string) (AddrList, error) {
	return resolveAddrListOrPatterns(strs, true)
}

func resolveAddrListOrPatterns(strs []string, expand bool) (addrs AddrList, err error) {
	var str string

	defer func() {
		if r := recover(); r != nil {
			err = &AddrError{str, r.(error)}
		}
	}()

	for _, str = range strs {
		host, port := splitAddr(str)

		if expand && host == "" {
			ips, err := net.InterfaceAddrs()
			if err != nil {
				panic(err)
			}

			for _, ip := range ips {
				addrs = addrs.AddResolved(ip.(*net.IPNet).IP.String(), port)
			}
		} else {
			addrs = addrs.AddResolved(host, port)
		}
	}

	return
}

func (addrs AddrList) AddResolved(host, port string) AddrList {
	resolved, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		panic(err)
	}

	for _, item := range addrs {
		if reflect.DeepEqual(resolved, item) {
			return addrs
		}
	}
	return append(addrs, resolved)
}

func (addrs AddrList) String() string {
	var ipv4Addrs, ipv6Addrs []string
	for _, addr := range addrs {
		if p4 := addr.IP.To4(); len(p4) == net.IPv4len {
			ipv4Addrs = append(ipv4Addrs, addr.String())
		} else {
			ipv6Addrs = append(ipv6Addrs, addr.String())
		}
	}
	return strings.Join(append(ipv4Addrs, ipv6Addrs...), ", ")
}

func (addrs AddrList) Filter() string {
	var parts []string
	for _, addr := range addrs {
		parts = append(parts, fmt.Sprintf("(dst host %s and tcp dst port %d)", addr.IP, addr.Port))
	}
	return strings.Join(parts, " or ")
}

func (addrs AddrList) RequiresPromisc() bool {
	ips, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}

Addrs:
	for _, addr := range addrs {
		for _, ip := range ips {
			if reflect.DeepEqual(addr.IP, ip.(*net.IPNet).IP) {
				continue Addrs
			}
		}
		return true
	}
	return false
}

func (e *AddrError) Error() string {
	return fmt.Sprintf("cannot resolve %s (%s)", e.str, e.err)
}

func splitAddr(addr string) (string, string) {
	if !hasPort(addr) {
		addr = addr + ":80"
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}

	if host == "*" {
		host = ""
	}
	return host, port
}

func hasPort(addr string) bool {
	return strings.LastIndex(addr, ":") > strings.LastIndex(addr, "]")
}
