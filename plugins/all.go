package plugins

import (
	logger "Three-EyedRaven/config"
	portdic "Three-EyedRaven/config"
	parseIP "Three-EyedRaven/config"
	"fmt"
	"net"
	"strings"
	"sync"
)

func AllFunc(ipd, ports *string, noPing, noWeb, noBrute *bool, thread *int) {
	fmt.Println("[*]Executing all module...")
	fmt.Printf("[+]Host:%s, Ports:%s, No ping:%v, No web:%v, No blasting:%v, Threads:%d\n", *ipd, *ports, *noPing, *noWeb, *noBrute, *thread)
	var (
		aliveRes  []string
		e         string
		strTemp   string
		openValue []string
		wg1       sync.WaitGroup
		sem       = make(chan struct{}, *thread) 
	)
	if *noPing {
		var noPingIPs []string
		noPingIPs, e = parseIP.ConvertIpFormatB(*ipd)
		if len(e) != 0 {
			return
		}
		temp := []HostPort{}
		fmt.Println("[*]Loading default basic ports dict...")
		portOper(&wg1, noPingIPs, sem, &temp)
		for _, openHostPorts := range temp {
			openValue = append(openValue, fmt.Sprintf("%s:%s", openHostPorts.Host, openHostPorts.Port))
		}
		//fmt.Println("初步探测结果：", openValue)
		ipIF := net.ParseIP(*ipd)
		if openValue != nil && ipIF == nil{
			temp2 := []HostPort{} 
			otherIP := AddPortCheck(&openValue, thread)
			portOper(&wg1, otherIP, sem, &temp2)
			for _, openHostPorts := range temp2 {
				openValue = append(openValue, fmt.Sprintf("%s:%s", openHostPorts.Host, openHostPorts.Port))
			}
			//fmt.Println("最终探测结果：", openValue)
		} else if ipIF != nil {
			//fmt.Println(ipIF)
		} else {
			return
		}
	} else {
		aliveFunc(ipd, thread, &aliveRes)
		logger.AliveLog(&aliveRes)
		temp := []HostPort{}
		fmt.Println("[*]Loading default basic ports dict...")
		portOper(&wg1, aliveRes, sem, &temp)
		for _, openHostPorts := range temp {
			openValue = append(openValue, fmt.Sprintf("%s:%s", openHostPorts.Host, openHostPorts.Port))
		}		
	}

	logger.PortLog(&openValue)

	for _, tmp := range openValue {
		if strings.Contains(tmp, ":139") {
			strTemp += netbiosDetect(tmp)
		} else if strings.Contains(tmp, ":135") {
			err := netInterface(tmp, &strTemp)
			if err != nil {
				logger.ErrLog(fmt.Sprintf("Cant connect to %s port,%v", tmp, err))
			}
		}
	}
	logger.PrintNetinfo(&strTemp)
	var wgBrute sync.WaitGroup
	for _, tmp := range openValue {
		wgBrute.Add(1)
		var ts []Task
		var t2 []T1
		var webts []string
		go func(tmp string) {
			switch {
			case !*noBrute && strings.Contains(tmp, ":21"):
				{
					conn, err := net.DialTimeout("tcp", tmp, 10)
					if err != nil {
						logger.ErrLog(fmt.Sprintf("Can't connect to %s,%v\n", tmp, err))
						break
					} else {
						conn.Close()
					}
					for _, userDict := range portdic.Users["ftp"] {
						for _, passDict := range portdic.Passwords {
							t2 = append(t2, T1{tmp, userDict, passDict})
						}
					}
					runNewTask(t2, "ftp")
					break
				}
			case !*noBrute && strings.Contains(tmp, ":22"):
				{
					for _, userDict := range portdic.Users["ssh"] {
						for _, passDict := range portdic.Passwords {
							t2 = append(t2, T1{tmp, userDict, passDict})
						}
					}
					runNewTask(t2, "ssh")
					break
				}
			case !*noBrute && strings.Contains(tmp, ":445"):
				{
					for _, userDict := range portdic.Users["smb"] {
						for _, passDict := range portdic.Passwords {
							ts = append(ts, Task{strings.Split(tmp, ":")[0], "445", userDict, passDict})
						}
					}
					runTask(ts, thread, "smb")
					break
				}
			case !*noBrute && strings.Contains(tmp, ":1433"):
				{
					for _, userDict := range portdic.Users["mssql"] {
						for _, passDict := range portdic.Passwords {
							ts = append(ts, Task{strings.Split(tmp, ":")[0], "1433", userDict, passDict})
						}
					}
					runTask(ts, thread, "mssql")
					break
				}
			case !*noBrute && strings.Contains(tmp, ":3306"):
				{
					for _, userDict := range portdic.Users["mysql"] {
						for _, passDict := range portdic.Passwords {
							//fmt.Println(strings.Split(tmp, ":")[0])
							ts = append(ts, Task{strings.Split(tmp, ":")[0], "3306", userDict, passDict})
						}
					}
					runTask(ts, thread, "mysql")
					break
				}
			case !*noBrute && strings.Contains(tmp, ":3389"):
				{
					fmt.Println("执行RDP服务爆破......")
					//ToDO:*****
					break
				}
			case !*noBrute && strings.Contains(tmp, ":5432"):
				{
					for _, userDict := range portdic.Users["postgresql"] {
						for _, passDict := range portdic.Passwords {
							ts = append(ts, Task{strings.Split(tmp, ":")[0], "5432", userDict, passDict})

						}
					}
					runTask(ts, thread, "postgresql")
					break
				}
			case !*noBrute && strings.Contains(tmp, ":6379"):
				{
					for _, userDict := range portdic.Users["redis"] {
						for _, passDict := range portdic.Passwords {
							ts = append(ts, Task{strings.Split(tmp, ":")[0], "6379", userDict, passDict})

						}
					}
					runTask(ts, thread, "redis")
					break
				}
			case !*noBrute && strings.Contains(tmp, ":27017"):
				{
					for _, userDict := range portdic.Users["mongodb"] {
						for _, passDict := range portdic.Passwords {
							ts = append(ts, Task{strings.Split(tmp, ":")[0], "27017", userDict, passDict})

						}
					}
					runTask(ts, thread, "mongodb")
					break
				}
			case !*noWeb && !strings.Contains(tmp, ":21") && !strings.Contains(tmp, ":22") && !strings.Contains(tmp, ":135") && !strings.Contains(tmp, ":139") && !strings.Contains(tmp, ":445"):
				{
					webts = append(webts, fmt.Sprintf("http://%s:%s", strings.Split(tmp, ":")[0], strings.Split(tmp, ":")[1]))
					webts = append(webts, fmt.Sprintf("https://%s:%s", strings.Split(tmp, ":")[0], strings.Split(tmp, ":")[1]))
					httpdScan(webts, thread)
					break
				}
			}
			defer wgBrute.Done()
		}(tmp)
	}
	wgBrute.Wait()

}

func portOper(wg *sync.WaitGroup, ipArr []string, sem chan struct{}, openHostPorts *[]HostPort) {
	portdict := strings.Split(portdic.BasicPorts, ",")
	for _, port := range portdict {
		wg.Add(len(ipArr))
		for _, host := range ipArr {
			go portScan2(wg, sem, host, port, openHostPorts)
		}
	}
	wg.Wait()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
