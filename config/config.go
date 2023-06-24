package config

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)


var (
	v4Mappedv6Prefix = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}
	upperIPv4        = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 255, 255, 255, 255}
	upperIPv6        = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type netWithRange struct {
	First   *net.IP
	Last    *net.IP
	Network *net.IPNet
}

func IPAddressesIPnet(ipnet *net.IPNet) (ips []string) {
	for ip := range IpAddresses(ipnet) {
		ips = append(ips, ip)
	}
	return ips
}
func IpAddresses(ipnet *net.IPNet) (ips chan string) {
	ips = make(chan string)
	go func() {
		defer close(ips)

		netWithRange := ipNetToRange(*ipnet)
		for ip := *netWithRange.First; !ip.Equal(*netWithRange.Last); ip = GetNextIP(ip) {
			ips <- ip.String()
		}


		ips <- netWithRange.Last.String()
	}()
	return ips
}
func ipNetToRange(ipNet net.IPNet) netWithRange {
	firstIP := make(net.IP, len(ipNet.IP))
	lastIP := make(net.IP, len(ipNet.IP))

	copy(firstIP, ipNet.IP)
	copy(lastIP, ipNet.IP)

	firstIP = firstIP.Mask(ipNet.Mask)
	lastIP = lastIP.Mask(ipNet.Mask)

	if firstIP.To4() != nil {
		firstIP = append(v4Mappedv6Prefix, firstIP...)
		lastIP = append(v4Mappedv6Prefix, lastIP...)
	}

	lastIPMask := make(net.IPMask, len(ipNet.Mask))
	copy(lastIPMask, ipNet.Mask)
	for i := range lastIPMask {
		lastIPMask[len(lastIPMask)-i-1] = ^lastIPMask[len(lastIPMask)-i-1]
		lastIP[net.IPv6len-i-1] |= lastIPMask[len(lastIPMask)-i-1]
	}

	return netWithRange{First: &firstIP, Last: &lastIP, Network: &ipNet}
}

func GetNextIP(ip net.IP) net.IP {
	if ip.Equal(upperIPv4) || ip.Equal(upperIPv6) {
		return ip
	}

	nextIP := make(net.IP, len(ip))
	switch len(ip) {
	case net.IPv4len:
		ipU32 := binary.BigEndian.Uint32(ip)
		ipU32++
		binary.BigEndian.PutUint32(nextIP, ipU32)
		return nextIP
	case net.IPv6len:
		ipU64 := binary.BigEndian.Uint64(ip[net.IPv6len/2:])
		ipU64++
		binary.BigEndian.PutUint64(nextIP[net.IPv6len/2:], ipU64)
		if ipU64 == 0 {
			ipU64 = binary.BigEndian.Uint64(ip[:net.IPv6len/2])
			ipU64++
			binary.BigEndian.PutUint64(nextIP[:net.IPv6len/2], ipU64)
		} else {
			copy(nextIP[:net.IPv6len/2], ip[:net.IPv6len/2])
		}
		return nextIP
	default:
		return ip
	}
}

func ConvertIpFormatA(ip string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(ip)
	if err != nil {
		return nil, err
	}
	temp := IPAddressesIPnet(ipnet)
	return temp, err
}

func ConvertPort(ports *string) []string {
	parts := strings.Split(*ports, ",")
	var parsePort []string
	for _, part1 := range parts {
		if strings.Contains(part1, "-") {
			rangeParts := strings.Split(part1, "-")
			start, _ := strconv.Atoi(rangeParts[0])
			end, _ := strconv.Atoi(rangeParts[1])
			//fmt.Println(rangeParts[0])
			for i := start; i <= end; i++ {
				parsePort = append(parsePort, strconv.Itoa(i))
			}
		} else {
			part2, _ := strconv.Atoi(part1)
			parsePort = append(parsePort, strconv.Itoa(part2))
		}
	}
	//fmt.Println(parsePort)
	return parsePort
	//解析 80,135-139端口参数的
}

