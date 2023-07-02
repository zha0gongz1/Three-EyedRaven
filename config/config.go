package config

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"regexp"
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

func ConvertIpFormatB(ipd string) ([]string, string) {
	var ipArr []string
	switch {
	case strings.Contains(ipd, "/8"):
		{
			realIP := ipd[:len(ipd)-2]
			testIP := net.ParseIP(realIP)
			if testIP == nil {
				return nil, "parse ips has an error"
			}
			ipArr = parseIP8(ipd)
			return ipArr, ""
		}
	case strings.Contains(ipd, "/16"):
		{
			realIP := ipd[:len(ipd)-3]
			testIP := net.ParseIP(realIP)
			if testIP == nil {
				return nil, "parse ips has an error"
			}
			ipArr = parseIP16(ipd)
			return ipArr, ""

		}
	case strings.Contains(ipd, "/24"):
		{
			ips, err := ConvertIpFormatA(ipd)
			if err != nil {
				return nil, ""
			}
			return ips, ""
		}
	default:
		if net.ParseIP(ipd) != nil {
			fmt.Println("ipd：", ipd)

		} else {
			return nil, "parse ips has an error"
		}
	}
	return nil, ""
}

func parseIP8(ip string) []string {
	IPrange := strings.Split(ip, ".")[0]
	var AllIP []string
	for a := 0; a <= 255; a++ {
		for b := 0; b <= 255; b++ {
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 1))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 2))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 4))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(6, 55)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(56, 100)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(101, 150)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(151, 200)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(201, 253)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 254))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 255))
		}
	}
	return AllIP
}

func parseIP16(ip string) []string {
	re := regexp.MustCompile(`^(\d{1,3}\.\d{1,3})`)
	realIP := re.FindStringSubmatch(ip)

	var AllIP []string
	for a := 0; a <= 255; a++ {
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, 1))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, 2))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, 4))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, RandInt(6, 55)))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, RandInt(56, 100)))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, RandInt(101, 150)))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, RandInt(151, 200)))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, RandInt(201, 253)))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, 254))
		AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d", realIP[1], a, 255))
	}
	return AllIP
}

func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}
