package plugins

import (
	parseIP "Three-EyedRaven/config"
	"bytes"
	"fmt"
	"golang.org/x/net/icmp"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

func aliveFunc(ipd *string, thread *int, res *[]string) {
	if strings.Contains(*ipd, "/") {
		if strings.Contains(*ipd, "/24") {
			ips, err := parseIP.ConvertIpFormatA(*ipd)
			if err != nil {
				fmt.Println("parse ips has an error")
				return
			}
			SubAliveFunc(&ips, thread, res)
		} else {
			ips, e := parseIP.ConvertIpFormatB(*ipd)
			if e != "" {
				fmt.Println("parse ips has an error")
				return
			}
			//fmt.Println(ips)
			checkCIDRAlive(&ips, thread, res)
		}
	} else {
		var temp []string
		temp = append(temp, *ipd)
		SubAliveFunc(&temp, thread, res)
	}
}

func SubAliveFunc(ips *[]string, thread *int, res *[]string) {
	conn, err := icmp.ListenPacket("ip4:icmp", "127.0.0.1")
	conn.Close()
	ch := make(chan struct{}, *thread)
	if err != nil {
		fmt.Println("[*]Not permission to perform ICMP detection, is performing ping... ")
		var wg sync.WaitGroup
		for _, ip := range *ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				ch <- struct{}{}
				defer func() { <-ch }()
				if isPing(ip) {
					fmt.Printf("[+]%s is alive\n", ip)
					//logger.AliveLog(ip)
					*res = append(*res, ip)
				}
			}(ip)
		}
		wg.Wait()
	} else {
		var wg sync.WaitGroup
		for _, ip := range *ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				ch <- struct{}{}
				defer func() { <-ch }()
				if isICMP(ip) {
					fmt.Printf("[+]%s is alive\n", ip)
					*res = append(*res, ip)
				}
			}(ip)
		}
		wg.Wait()
	}
}

func checkCIDRAlive(ipd *[]string, thread *int, res *[]string) {
	SubAliveFunc(ipd, thread, res)
	if *res != nil {
		AddIPCheck(res, thread)
	} else {
		return
	}
}

func AddIPCheck(ips *[]string, thread *int) {
	var ip_temp, res_temp []string
	cClassIPs := make(map[string]string)
	for _, ipAddress := range *ips {
		parts := strings.Split(ipAddress, ".")
		if len(parts) == 4 {
			cClass := strings.Join(parts[:3], ".")
			if _, ok := cClassIPs[cClass]; !ok {
				cClassIPs[cClass] = ipAddress
			}
		}
	}
	for prefix, _ := range cClassIPs {
		for i := 0; i <= 255; i++ {
			ip := fmt.Sprintf("%s.%d", prefix, i)
			found := false
			for _, v := range *ips {
				if v == ip {
					found = true
					break
				}
			}
			if !found {
				ip_temp = append(ip_temp, ip)
			}

		}
	}
	//fmt.Println("Add Complete IP:", ip_temp)
	SubAliveFunc(&ip_temp, thread, &res_temp)
	if res_temp != nil {
		*ips = append(*ips, res_temp...)
	}
}

func isICMP(ip string) bool {
	conn, err := net.DialTimeout("ip4:icmp", ip, time.Second*4)
	if err != nil {
		return false
	}
	defer func() {
		_ = conn.Close()
	}()
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return false
	}
	msg := packet(ip)
	if _, err := conn.Write(msg); err != nil {
		return false
	}
	var receive = make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}
	return true
}

func isPing(ip string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
	case "linux":
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" >/dev/null && echo true || echo false")
	case "darwin":
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1 "+ip+" >/dev/null && echo true || echo false")
	default:
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1"+ip+" >/dev/null && echo true || echo false")
	}

	res := bytes.Buffer{}
	cmd.Stdout = &res
	err := cmd.Start()
	if err != nil {
		return false
	}

	if err = cmd.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(res.String(), "true") {
			return true
		} else {
			return false
		}
	}
}

func packet(host string) []byte {
	var msg = make([]byte, 40)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = host[0], host[1]
	msg[6], msg[7] = byte(1>>8), byte(1&255)
	msg[2] = byte(checksum(msg[0:40]) >> 8)
	msg[3] = byte(checksum(msg[0:40]) & 255)
	return msg
}

func checksum(msg []byte) uint16 {
	var sum = 0
	var length = len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}
