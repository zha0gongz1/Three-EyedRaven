package plugins

import (
	logger "Three-EyedRaven/config"
	parse "Three-EyedRaven/config"
	portdic "Three-EyedRaven/config"
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	sendData1 = []byte{
		0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb,
		0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
		0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
		0x00, 0x00,
	}
	sendData2 = []byte{
		0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
	}
	NegotiateSMBv1Mesg1 = []byte{
		0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
		0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
		0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
		0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
		0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
		0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
		0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}
	NegotiateSMBv1Mesg2 = []byte{
		0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
		0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
		0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
		0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
		0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
		0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
		0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x32, 0x00,
		0x20, 0x00, 0x52, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x57, 0x00, 0x69, 0x00,
		0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00,
		0x32, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	NetBIOS_ITEM_TYPE = map[string]string{
		"\x01\x00": "NetBiosComputerName",
		"\x02\x00": "NetBiosDomainName",
		"\x03\x00": "ComputerName",
		"\x04\x00": "DomainName",
		"\x05\x00": "DNS tree name",
		"\x07\x00": "Time stamp",
	}
)

type HostPort struct {
	Host string
	Port string
}

func DetectFunc(ipd *string, noPing, NoWebDetect *bool, port *string, thread *int) {
	fmt.Println("[*]Executing detect module...")
	fmt.Printf("Host:%s, Ports:%s, No ping:%v, No web:%v, Threads:%d\n", *ipd, *port, *noPing, *NoWebDetect, *thread)

	var (
		aliveRes []string
		hostPort []string
		err      error
		TagetBanners []string
	)
	if *noPing {
		aliveRes, err = parse.ConvertIpFormatA(*ipd)
		if err != nil {
			fmt.Println("parse ips has an error")
			return
		}
	} else {
		aliveFunc(ipd, thread, &aliveRes)
		logger.AliveLog(&aliveRes)
	}
	switch {
	case !strings.Contains(*port, ",") && !strings.Contains(*port, "-") && *port != "":
		fmt.Println("[*]Scaning one port...")
		hostPort = detectPort2(&aliveRes, port, thread)
		break
	case strings.Contains(*port, ",") || strings.Contains(*port, "-"):
		fmt.Println("[*]Loading the specified port scanning method...")
		hostPort = detectPort2(&aliveRes, port, thread)
		break
	default:
		fmt.Println("[*]Loading default port dictionary top1000...")
		hostPort = detectPort(&aliveRes, thread)
		break
	}
	logger.PortLog(&hostPort)
	fmt.Println("[*]Identifying port service...")
	if len(hostPort) > 0 {
		TagetBanners = GetProbes(&hostPort, thread)
	}
	for _, taget := range TagetBanners {
		//fmt.Println(taget)
		logger.PrintInfo(taget)
	}
	var netInfoTemp string
	for _, tmp := range hostPort {
		if strings.Contains(tmp, ":139") {
			netInfoTemp += netbiosDetect(tmp)
		} else if strings.Contains(tmp, ":135") {
			err := netInterface(tmp, &netInfoTemp)
			if err != nil {
				logger.ErrLog(fmt.Sprintf("Cant connect to %s port,%v", tmp, err))
			}
		}
	}
	logger.PrintNetinfo(&netInfoTemp)

	if *NoWebDetect == false {
		fmt.Println("[*]Executing web detection module...")
		var httpValue, httpsValue, Value []string
		for _, tmp := range hostPort {
			if !strings.Contains(tmp, ":135") && !strings.Contains(tmp, ":137") && !strings.Contains(tmp, ":445") && !strings.Contains(tmp, ":139") {
				httpValue = append(httpValue, fmt.Sprintf("http://%s", tmp))
				httpsValue = append(httpsValue, fmt.Sprintf("https://%s", tmp))

				Value = append(httpValue, httpsValue...)
			}
		}
		httpdScan(Value, thread)
	}
}

func portCheck(hosts []string, port string, res chan []string) {

	//if len(port) > 5 { //遍历端口字典找寻服务
	//
	//} else {
	var openHosts []string
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", host+":"+port, time.Second*3)
			if err != nil {
				//fmt.Println(host, p, "Close")
				return
			}
			fmt.Println("[+]"+host+":"+port, "is Open")
			_ = conn.Close()
			openHosts = append(openHosts, host)
		}(host)
	}
	wg.Wait()
	res <- openHosts
	//}
}

func whatIsServ(ipd []string, thread *int) ServResult {
	portdict := strings.Split(portdic.DefaultPorts, ",")
	var result ServResult
	var wg sync.WaitGroup
	sem := make(chan struct{}, *thread*2)

	for _, port := range portdict {
		for _, target := range ipd {
			wg.Add(1)
			go func(port, target string) {
				sem <- struct{}{}
				defer func() {
					<-sem
					wg.Done()
				}()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", target, port), 5*time.Second)
				if err != nil {
					//fmt.Println("Unable to connect to host:", err)
					logger.ErrLog(fmt.Sprintf("Cant connect to host,%v", err))
					return
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))

				scanner := bufio.NewScanner(conn)
				if scanner.Scan() {
					banner := scanner.Text()
					switch {
					case banner[:3] == "SSH":
						{
							result.SSH = append(result.SSH, fmt.Sprintf("%s:%s", target, port))
						}
					case strings.HasPrefix(banner, "220") || strings.Contains(banner, "FTP"):
						{
							result.FTP = append(result.FTP, fmt.Sprintf("%s:%s", target, port))
						}
					default:
						return
					}

				} else {
					logger.ErrLog(fmt.Sprintf("Cant read connect banner,`%v", scanner.Err()))
					return
				}
			}(port, target)
		}
	}

	wg.Wait()
	return result
}

func detectPort(ipd *[]string, thread *int) []string {
	var wg sync.WaitGroup
	var aliveRes = *ipd
	sem := make(chan struct{}, *thread*2)
	portdict := strings.Split(portdic.DefaultPorts, ",")
	temp := []HostPort{}
	//batchSize := 100
	for i := 0; i < len(portdict); i += 100 {
		portBatch := portdict[i:min(i+100, len(portdict))]
		wg.Add(1)
		sem <- struct{}{}
		go func(portBatch, aliveRes []string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			for _, port := range portBatch {
				for _, host := range aliveRes {
					portScan(host, port, &temp)
				}
			}
		}(portBatch, aliveRes)
	}
	wg.Wait()
	var openValue []string
	for _, openHostPorts := range temp {
		openValue = append(openValue, fmt.Sprintf("%s:%s", openHostPorts.Host, openHostPorts.Port))
	}
	return openValue
}

func detectPort2(ipd *[]string, port *string, thread *int) []string {
	var wg sync.WaitGroup
	sem := make(chan struct{}, *thread)
	temp := []HostPort{}
	if strings.Contains(*port, ",") || strings.Contains(*port, "-") {
		parsePort := parse.ConvertPort(port)
		for _, oneport := range parsePort {
			wg.Add(len(*ipd))
			for _, aliveIP := range *ipd {
				go portScan2(&wg, sem, aliveIP, oneport, &temp)
			}
		}
		wg.Wait()
	} else {
		wg.Add(len(*ipd))
		for _, aliveIP := range *ipd {
			go portScan2(&wg, sem, aliveIP, *port, &temp)
		}
		wg.Wait()
	}
	var openValue []string
	for _, openHostPorts := range temp {
		openValue = append(openValue, fmt.Sprintf("%s:%s", openHostPorts.Host, openHostPorts.Port))
	}
	return openValue
}

func portScan(hostname string, port string, openHostPorts *[]HostPort) {
	timeout := time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", hostname, port), timeout*3)
	if err != nil {
		return
	}
	conn.Close()
	*openHostPorts = append(*openHostPorts, HostPort{hostname, port})
}

func portScan2(wg *sync.WaitGroup, sem chan struct{}, hostname string, port string, openHostPorts *[]HostPort) {
	defer wg.Done()
	sem <- struct{}{}
	timeout := time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", hostname, port), timeout*3)
	if err != nil {
		<-sem
		return
	}
	conn.Close()
	*openHostPorts = append(*openHostPorts, HostPort{hostname, port})
	<-sem

}

func readBytes(conn net.Conn) (result []byte, err error) {
	size := 4096
	buf := make([]byte, size)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < size {
			break
		}
	}
	if len(result) > 0 {
		err = nil
	}
	return result, err
}

func netbiosEncode(name string) (output []byte) {
	var names []int
	src := fmt.Sprintf("%-16s", name)
	for _, a := range src {
		char_ord := int(a)
		high_4_bits := char_ord >> 4
		low_4_bits := char_ord & 0x0f
		names = append(names, high_4_bits, low_4_bits)
	}
	for _, one := range names {
		out := (one + 0x41)
		output = append(output, byte(out))
	}
	return
}

func netbiosDetect(host string) string {
	var temp3 string
	ok, pcName := getNBNM(host, &temp3)
	if ok {
		var payload0 []byte
		name := netbiosEncode(pcName)
		//name := netbiosEncode("whoami-PC")
		payload0 = append(payload0, []byte("\x81\x00\x00D ")...)
		payload0 = append(payload0, name...)
		payload0 = append(payload0, []byte("\x00 EOENEBFACACACACACACACACACACACACA\x00")...)

		//conn, err := net.DialTimeout("udp", fmt.Sprintf("%v:%v", host, port), 5)
		conn, err := net.Dial("tcp", host)
		if err != nil {
			fmt.Println(err)
		}
		if len(payload0) > 0 {
			_, err1 := conn.Write(payload0)
			if err1 != nil {
				return ""
			}
			_, err1 = readBytes(conn)
			if err1 != nil {
				return ""
			}
		}

		_, err = conn.Write(NegotiateSMBv1Mesg1)
		if err != nil {
			return ""
		}
		_, err = readBytes(conn)
		if err != nil {
			return ""
		}

		_, err = conn.Write(NegotiateSMBv1Mesg2)
		if err != nil {
			return ""
		}
		var ret []byte
		ret, err = readBytes(conn)
		if err != nil {
			return ""
		}
		//fmt.Println(ret)
		tmpstring := parseNTLM(ret)
		temp3 += tmpstring
		return temp3
	}
	return ""
}

func bytetoint(text byte) (int, error) {
	num1 := fmt.Sprintf("%v", text)
	num, err := strconv.Atoi(num1)
	return num, err
}

func parseNTLM(ret []byte) string {
	var err error
	var tmp string
	if len(ret) < 47 {
		//err = netbioserr
		fmt.Println(err)
		return ""
	}
	var num1, num2 int
	num1, err = bytetoint(ret[43:44][0])
	if err != nil {
		return ""
	}
	num2, err = bytetoint(ret[44:45][0])
	if err != nil {
		return ""
	}
	length := num1 + num2*256
	//fmt.Println(length)
	if len(ret) < 48+length {
		return ""
	}
	os_version := ret[47+length:]
	tmp1 := bytes.ReplaceAll(os_version, []byte{0x00, 0x00}, []byte{124})
	tmp1 = bytes.ReplaceAll(tmp1, []byte{0x00}, []byte{})
	ostext := string(tmp1[:len(tmp1)-1])
	ss := strings.Split(ostext, "|")
	tmp += fmt.Sprintf("OS:%s\n", ss[0])
	start := bytes.Index(ret, []byte("NTLMSSP"))
	if len(ret) < start+45 {
		return ""
	}
	num1, err = bytetoint(ret[start+40 : start+41][0])
	if err != nil {
		return ""
	}
	num2, err = bytetoint(ret[start+41 : start+42][0])
	if err != nil {
		return ""
	}
	length = num1 + num2*256
	num1, err = bytetoint(ret[start+44 : start+45][0])
	if err != nil {
		return ""
	}
	offset, err := bytetoint(ret[start+44 : start+45][0])
	if err != nil || len(ret) < start+offset+length {
		return ""
	}
	var msg string
	index := start + offset
	for index < start+offset+length {
		item_type := ret[index : index+2]
		num1, err = bytetoint(ret[index+2 : index+3][0])
		if err != nil {
			continue
		}
		num2, err = bytetoint(ret[index+3 : index+4][0])
		if err != nil {
			continue
		}
		item_length := num1 + num2*256
		item_content := bytes.ReplaceAll(ret[index+4:index+4+item_length], []byte{0x00}, []byte{})
		index += 4 + item_length
		if string(item_type) == "\x07\x00" {
			//Time stamp, 不需要输出
		} else if NetBIOS_ITEM_TYPE[string(item_type)] != "" {
			msg += fmt.Sprintf("%s: %s\n", NetBIOS_ITEM_TYPE[string(item_type)], string(item_content))
		} else if string(item_type) == "\x00\x00" {
			break
		}
	}
	tmp += fmt.Sprintf("%s\n", msg)
	return tmp
}

func getNBNM(host string, tmpinfo *string) (bool, string) {
	index := strings.Index(host, ":")
	host = host[:index]
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%v:137", host), 7)
	if err != nil {
		return false, ""
	}
	msg := []byte{
		0x0, 0x00, 0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x43, 0x4b, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x0, 0x0, 0x21, 0x0, 0x1,
	}
	_, err = conn.Write(msg)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return false, ""
	}
	reply := make([]byte, 256)
	err = conn.SetDeadline(time.Now().Add(5))
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return false, ""
	}
	_, _ = conn.Read(reply)
	if conn != nil {
		_ = conn.Close()
	}

	var buffer [256]byte
	if bytes.Equal(reply[:], buffer[:]) {
		return false, ""
	}

	var n int
	NumberFoNames, _ := strconv.Atoi(convert([]byte{reply[56:57][0]}[:]))
	var flagGroup string
	var flagUnique string
	var flagDC string

	for i := 0; i < NumberFoNames; i++ {
		data := reply[n+57+18*i : n+57+18*i+18]
		if string(data[16:17]) == "\x84" || string(data[16:17]) == "\xC4" {
			if string(data[15:16]) == "\x1C" {
				flagDC = "Domain Controllers"
			}
			if string(data[15:16]) == "\x00" {
				flagGroup = nbnsByteToStringParse(data[0:16])
			}
			if string(data[14:16]) == "\x02\x01" {
				flagGroup = nbnsByteToStringParse(data[0:16])
			}
		} else if string(data[16:17]) == "\x04" || string(data[16:17]) == "\x44" || string(data[16:17]) == "\x64" {
			if string(data[15:16]) == "\x1C" {
				flagDC = "Domain Controllers"
			}
			if string(data[15:16]) == "\x00" {
				flagUnique = nbnsByteToStringParse(data[0:16])
			}
			if string(data[15:16]) == "\x20" {
				flagUnique = nbnsByteToStringParse(data[0:16])
			}
		}
	}
	if flagGroup == "" && flagUnique == "" {
		return false, ""
	}

	result := make(map[string]interface{})
	result["banner.string"] = flagGroup + "\\" + flagUnique
	//fmt.Println(flagGroup) //ROOTKIT

	result["identify.string"] = fmt.Sprintf("[%s]", flagDC)
	//fmt.Println(reflect.TypeOf(result["banner.string"]))
	if len(flagDC) != 0 {
		result["identify.bool"] = true
	} else {
		result["identify.bool"] = false
	}
	if result["identify.bool"] == true {
		*tmpinfo += fmt.Sprintf("[%s] %v\n", fmt.Sprintf("%v:137", host), result["banner.string"])
	} else {

		*tmpinfo += fmt.Sprintf("[%s] %v\n", fmt.Sprintf("%v:137", host), result["banner.string"])
	}
	return true, flagUnique
}

func convert(b []byte) string {
	s := make([]string, len(b))
	for i := range b {
		s[i] = strconv.Itoa(int(b[i]))
	}
	return strings.Join(s, "")
}

func nbnsByteToStringParse(p []byte) string {
	var w []string
	var res string
	for i := 0; i < len(p); i++ {
		if p[i] > 32 && p[i] < 127 {
			w = append(w, string(p[i]))
			continue
		}
	}
	res = strings.Join(w, "")
	return res
}

func netInterface(ip string, temp2 *string) error {
	conn, err := net.DialTimeout("tcp", ip, time.Second*5)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second * 5))
	conn.Write(sendData1)
	recvData := make([]byte, 1024)
	if n, err := conn.Read(recvData); err != nil || n != 60 {
		return err
	}

	conn.Write(sendData2)
	n, err := conn.Read(recvData)
	if err != nil || n == 0 {
		//fmt.Println(err)
		return err
	}
	recvStr := string(recvData[:n])

	if len(recvStr) > 42 {
		recvStr_v2 := recvStr[42:]
		packet_v2_end := strings.Index(recvStr_v2, "\x09\x00\xff\xff\x00\x00")
		packet_v2 := recvStr_v2[:packet_v2_end]
		hostname_list := strings.Split(packet_v2, "\x00\x00")
		if len(hostname_list) > 1 {
			for _, value := range hostname_list {
				if strings.Trim(value, " ") != "" {
					*temp2 += fmt.Sprintf("%s\n", strings.Replace(value, string([]byte{0x00}), "", -1))
				}
			}
			return nil
		}
	}
	return nil
}
