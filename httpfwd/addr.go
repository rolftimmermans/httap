package httpfwd

import (
	"fmt"
	"net"
	"reflect"
	"strings"
)

type addrError struct {
	str string
	err error
}

func (e *addrError) Error() string {
	return fmt.Sprintf("cannot resolve %s (%s)", e.str, e.err)
}

func findInterfaces() []string {
	var intfsWithAddress []string

	intfs, err := net.Interfaces() //pcap.FindAllDevs()
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

func addrFilter(addrs []*net.TCPAddr) string {
	var filter string
	for i, addr := range addrs {
		if i > 0 {
			filter += " or "
		}
		filter += fmt.Sprintf("(dst host %s and tcp dst port %d)", addr.IP, addr.Port)
	}
	return filter
}

func addrList(addrs []*net.TCPAddr) string {
	var ipv4Addrs, ipv6Addrs []string
	for _, addr := range addrs {
		if p4 := addr.IP.To4(); len(p4) == net.IPv4len {
			ipv4Addrs = append(ipv4Addrs, addr.String())
		} else {
			ipv6Addrs = append(ipv6Addrs, addr.String())
		}
	}
	return strList(append(ipv4Addrs, ipv6Addrs...))
}

func strList(strs []string) string {
	return strings.Join(strs, ", ")
}

func resolveAddrPatterns(strs []string) ([]*net.TCPAddr, error) {
	var addrs []*net.TCPAddr

	for _, str := range strs {
		if !hasPort(str) {
			str = str + ":80"
		}

		host, port, err := net.SplitHostPort(str)
		if err != nil {
			return nil, &addrError{str, err}
		}

		if host == "*" {
			ips, err := net.InterfaceAddrs()
			if err != nil {
				return nil, &addrError{str, err}
			}

			for _, ip := range ips {
				addr, err := resolveAddr(ip.(*net.IPNet).IP.String(), port)
				if err != nil {
					return nil, &addrError{str, err}
				}
				addrs = appendUnique(addrs, addr)
			}
		} else {
			addr, err := resolveAddr(host, port)
			if err != nil {
				return nil, &addrError{str, err}
			}
			addrs = appendUnique(addrs, addr)
		}
	}

	return addrs, nil
}

func hasPort(s string) bool {
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

func appendUnique(list []*net.TCPAddr, new *net.TCPAddr) []*net.TCPAddr {
	for _, item := range list {
		if reflect.DeepEqual(new, item) {
			return list
		}
	}
	return append(list, new)
}

func resolveAddr(host, port string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
}
