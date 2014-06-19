package httpfwd

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

func FindInterfaces() []string {
	var intfsWithAddress []string

	intfs, err := net.Interfaces()
	if err != nil {
		return []string{}
	}

	for _, intf := range intfs {
		addrs, err := intf.Addrs()
		if err == nil && len(addrs) > 0 {
			intfsWithAddress = append(intfsWithAddress, intf.Name)
		}
	}

	return intfsWithAddress
}

func ResolveAddrList(strs []string) (AddrList, error) {
	return resolveAddrListOrPatterns(strs, false)
}

func ResolveAddrPatterns(strs []string) (AddrList, error) {
	return resolveAddrListOrPatterns(strs, true)
}

func resolveAddrListOrPatterns(strs []string, expand bool) (AddrList, error) {
	var addrs AddrList

	for _, str := range strs {
		if !hasPort(str) {
			str = str + ":80"
		}

		host, port, err := net.SplitHostPort(str)
		if err != nil {
			return nil, &AddrError{str, err}
		}

		if host == "*" {
			host = ""
		}

		if expand && host == "" {
			ips, err := net.InterfaceAddrs()
			if err != nil {
				return nil, &AddrError{str, err}
			}

			for _, ip := range ips {
				addr, err := resolveAddr(ip.(*net.IPNet).IP.String(), port)
				if err != nil {
					return nil, &AddrError{str, err}
				}
				addrs = addrs.Add(addr)
			}
		} else {
			addr, err := resolveAddr(host, port)
			if err != nil {
				return nil, &AddrError{str, err}
			}
			addrs = addrs.Add(addr)
		}
	}

	return addrs, nil
}

func (addrs AddrList) Add(new *net.TCPAddr) AddrList {
	for _, item := range addrs {
		if reflect.DeepEqual(new, item) {
			return addrs
		}
	}
	return append(addrs, new)
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

func hasPort(s string) bool {
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

func resolveAddr(host, port string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
}
