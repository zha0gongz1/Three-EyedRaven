package plugins

import (
	dict "Three-EyedRaven/config"
	logger "Three-EyedRaven/config"
	parseIP "Three-EyedRaven/config"
	"context"
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/go-redis/redis/v8"
	//_ "github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"github.com/masterzen/winrm"
	"github.com/stacktitan/smb/smb"
	"golang.org/x/crypto/ssh"
	"gopkg.in/mgo.v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"Three-EyedRaven/goftp"
)

type Task struct {
	target   string
	port     string
	user     string
	password string
}

type T1 struct {
	target   string
	user     string
	password string
}

var tasks []Task
var t1 []T1

type ServResult struct {
	FTP []string
	SSH []string
	// 添加更多的服务类型
}


func BruteService(user, pass string, ipd *string, service *string, p1 string, thread *int) {
	fmt.Printf("[*]Executing enumeration of %s service...\n", *service)
	serv := strings.ToLower(*service)
	switch {
	case serv == "ssh":
		if p1 != "" {
			if strings.Contains(*ipd, "/") { 
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				sshBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				sshBrute(user, pass, ips, p1, thread, serv)
			}

		} else { 
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				res := whatIsServ(ips, thread)
				fmt.Println("[*]Detected ssh service on", res.SSH)
				sshNewBrute(user, pass, res.SSH, serv)

			} else {
				var ips []string
				ips = append(ips, *ipd)
				res := whatIsServ(ips, thread)
				fmt.Println("[*]Detected ssh service on", res.SSH)
				sshNewBrute(user, pass, res.SSH, serv)
				//sshBrute(user, pass, ips, "22", thread, serv)
			}
		}
		break

	case serv == "ftp":
		if p1 != "" {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				ftpBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)

				ftpBrute(user, pass, ips, p1, thread, serv)

			}
		} else {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				res := whatIsServ(ips, thread)
				fmt.Println("[*]Detected ftp service on", res.FTP)
				ftpNewBrute(user, pass, res.FTP, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				res := whatIsServ(ips, thread)
				fmt.Println("[*]Detected ftp service on", res.FTP)
				ftpNewBrute(user, pass, res.FTP, serv)
			}
		}
		break
	case serv == "smb":
		if p1 != "" {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				smbBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				smbBrute(user, pass, ips, p1, thread, serv)
			}

		} else { //端口未设置，采取默认445端口
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				smbBrute(user, pass, ips, "445", thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				smbBrute(user, pass, ips, "445", thread, serv)
			}
		}
		break
	case serv == "rdp":
		fmt.Println("执行RDP服务爆破......")
		//ToDO:*****
		break
	case serv == "postgresql":
		if p1 != "" {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				postgresBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				postgresBrute(user, pass, ips, p1, thread, serv)
			}

		} else {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				postgresBrute(user, pass, ips, "5432", thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				postgresBrute(user, pass, ips, "5432", thread, serv)
			}
		}
		break
	case serv == "mysql":
		if p1 != "" {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				mysqlBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				mysqlBrute(user, pass, ips, p1, thread, serv)
			}

		} else {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				mysqlBrute(user, pass, ips, "3306", thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				mysqlBrute(user, pass, ips, "3306", thread, serv)
			}
		}
		break
	case serv == "mongodb":
		if p1 != "" {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				mongodbBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				mongodbBrute(user, pass, ips, p1, thread, serv)
			}

		} else {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				mongodbBrute(user, pass, ips, "27017", thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				mongodbBrute(user, pass, ips, "27017", thread, serv)
			}
		}
		break
	case serv == "winrm":
		if p1 != "" {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				winrmBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				winrmBrute(user, pass, ips, p1, thread, serv)
			}

		} else { //端口未设置，采取默认5985端口
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				winrmBrute(user, pass, ips, "5985", thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				winrmBrute(user, pass, ips, "5985", thread, serv)
			}
		}
		break
	case serv == "redis":
		if p1 != "" {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				redisBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				redisBrute(user, pass, ips, p1, thread, serv)
			}

		} else {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				redisBrute(user, pass, ips, "6379", thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				redisBrute(user, pass, ips, "6379", thread, serv)
			}
		}
		break
	case serv == "mssql":
		if p1 != "" {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				mssqlBrute(user, pass, ips, p1, thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				mssqlBrute(user, pass, ips, p1, thread, serv)
			}

		} else {
			if strings.Contains(*ipd, "/") {
				ips, err := parseIP.ConvertIpFormatA(*ipd)
				if err != nil {
					fmt.Println("parse ips has an error")
					return
				}
				mssqlBrute(user, pass, ips, "1433", thread, serv)
			} else {
				var ips []string
				ips = append(ips, *ipd)
				mssqlBrute(user, pass, ips, "1433", thread, serv)
			}
		}
		break
	default:
		fmt.Println("[!]Please specify the blasting service name(.eg -S smb/ssh/rdp)")
	}
}

func sshBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	//爆破两种方式：1.指定字典 1.1指定用户名；1.2指定密码字典；2.不指定字典，内置爆破；
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts { //密码喷洒（一组密码对应多个IP尝试）
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
						fmt.Println(tasks)
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["ssh"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
			runTask(tasks, threads, serv)
		}
		runTask(tasks, threads, serv)

	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["ssh"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}
		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}
		runTask(tasks, threads, serv)
	}
}

func sshNewBrute(userDict, passDict string, Target []string, serv string) {
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipport := range Target {
						t1 = append(t1, T1{ipport, userDict, passDict})
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["ssh"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipport := range Target {
						t1 = append(t1, T1{ipport, userDict, passDict})
					}
				}
			}

			runNewTask(t1, serv)
		}

		runNewTask(t1, serv)

	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["ssh"] {
			for _, passDict := range dict.Passwords {
				for _, ipport := range Target {
					t1 = append(t1, T1{ipport, userDict, passDict})
				}
			}
		}

		runNewTask(t1, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipport := range Target {
					t1 = append(t1, T1{ipport, userDict, passDict})
				}
			}
		}

		runNewTask(t1, serv)
	}
}

func ftpBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["ftp"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}

			runTask(tasks, threads, serv)
		}

		runTask(tasks, threads, serv)

	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["ftp"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	}
}

func ftpNewBrute(userDict, passDict string, Target []string, serv string) {

	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipport := range Target {
						t1 = append(t1, T1{ipport, userDict, passDict})
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["ftp"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipport := range Target {
						t1 = append(t1, T1{ipport, userDict, passDict})
					}
				}
			}
			runNewTask(t1, serv)
		}
		runNewTask(t1, serv)

	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["ftp"] {
			for _, passDict := range dict.Passwords {
				for _, ipport := range Target {
					t1 = append(t1, T1{ipport, userDict, passDict})
				}
			}
		}

		runNewTask(t1, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipport := range Target {
					t1 = append(t1, T1{ipport, userDict, passDict})
				}
			}
		}

		runNewTask(t1, serv)
	}
}

func filter(slice []string, f func(string) bool) []string {
	result := make([]string, 0)
	for _, s := range slice {
		if f(s) {
			result = append(result, s)
		}
	}
	return result
}

func smbBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	p2, _ := strconv.Atoi(port)
	openHostsRes := filter(openHosts, func(ip string) bool {
		options := smb.Options{
			Host:        ip,
			Port:        p2,
			User:        "",
			Password:    "",
			Domain:      "",
			Workstation: "",
		}
		session, err := smb.NewSession(options, false)
		if err != nil {
			return true
		}
		defer session.Close()
		fmt.Println("[*]" + ip + " SMB allows anonymous access!")
		logger.PrintInfo("[*]" + ip + " SMB allows anonymous access")
		return !session.IsAuthenticated
	})
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHostsRes {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["smb"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHostsRes {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
			runTask(tasks, threads, serv)
		}

		runTask(tasks, threads, serv)

	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["smb"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHostsRes {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHostsRes {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	}
}

func mysqlBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	//if port.PortCheck(Target, 21) {
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["mysql"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
			runTask(tasks, threads, serv)
		}
		runTask(tasks, threads, serv)

	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["mysql"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}
		runTask(tasks, threads, serv)
	}
}

func mssqlBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["mssql"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}

			runTask(tasks, threads, serv)
		}

		runTask(tasks, threads, serv)
	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["mssql"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	}
}

func mongodbBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts { //密码喷洒（一组密码对应多个IP尝试）
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
						fmt.Println(tasks)
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["mongodb"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
			runTask(tasks, threads, serv)
		}
		runTask(tasks, threads, serv)
	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["mongodb"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}
		runTask(tasks, threads, serv)
	}
}
func postgresBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts { //密码喷洒（一组密码对应多个IP尝试）
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
						fmt.Println(tasks)
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["postgresql"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
			runTask(tasks, threads, serv)
		}
		runTask(tasks, threads, serv)
	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["postgresql"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	}
}

func winrmBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["winrm"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}
			runTask(tasks, threads, serv)
		}

		runTask(tasks, threads, serv)

	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["winrm"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	}
}

func redisBrute(userDict, passDict string, Target []string, port string, threads *int, serv string) {
	res := make(chan []string)
	go portCheck(Target, port, res)
	openHosts := <-res
	if dict.PassIsExist(passDict) {
		if dict.UserIsExist(userDict) {
			for _, userDict := range dict.UserDict(userDict) {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts { //密码喷洒（一组密码对应多个IP尝试）
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})

					}
				}
			}
		} else {
			fmt.Println("[*]No user dict specified! Using built-in user dict")
			for _, userDict := range dict.Users["redis"] {
				for _, passDict := range dict.PassDict(passDict) {
					for _, ipDict := range openHosts {
						tasks = append(tasks, Task{ipDict, port, userDict, passDict})
					}
				}
			}

			runTask(tasks, threads, serv)
		}

		runTask(tasks, threads, serv)
	} else if !dict.PassIsExist(passDict) && !dict.UserIsExist(userDict) {
		fmt.Println("[*]Using the built-in user && password dict to blast!")
		for _, userDict := range dict.Users["redis"] {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	} else {
		fmt.Println("[*]No password dict specified! Using built-in password dict")
		for _, userDict := range dict.UserDict(userDict) {
			for _, passDict := range dict.Passwords {
				for _, ipDict := range openHosts {
					tasks = append(tasks, Task{ipDict, port, userDict, passDict})
				}
			}
		}

		runTask(tasks, threads, serv)
	}
}

func sshAuth(host string, port string, user string, pass string) (result bool, err error) {
	result = false
	authMethods := []ssh.AuthMethod{}

	keyboardInteractiveChallenge := func(
		user,
		instruction string,
		questions []string,
		echos []bool,
	) (answers []string, err error) {
		if len(questions) == 0 {
			return []string{}, nil
		}
		return []string{pass}, nil
	}

	authMethods = append(authMethods, ssh.KeyboardInteractive(keyboardInteractiveChallenge))
	authMethods = append(authMethods, ssh.Password(pass))

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: authMethods,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", host, port), sshConfig)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		errRet := session.Run("echo hello")
		if err == nil && errRet == nil {
			defer session.Close()
			result = true
		}
	}
	return result, err
}

func ftpAuth(ip string, port string, user string, pass string) (result bool, err error) {
	result = false
	var Lftp *goftp.FTP

	if Lftp, err = goftp.Connect(ip + ":" + port); err != nil {
		fmt.Println(err)
	}
	if Lftp != nil {
		defer Lftp.Close()
	}

	if err = Lftp.Login(user, pass); err == nil {
		result = true
	}
	return result, err
}

func smbAuth(ip string, port string, user string, pass string) (result bool, err error) {
	result = false

	options := smb.Options{
		Host:        ip,
		Port:        445,
		User:        user,
		Password:    pass,
		Domain:      "",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			result = true
		}
	}
	return result, err
}

func winrmAuth(ip, user, pass string, port int) (result bool, err error) {
	result = false
	endpoint := winrm.NewEndpoint(ip, port, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, user, pass)
	//if err != nil {
	//	panic(err)
	//}
	res, err := client.Run("echo hello", os.Stdout, os.Stderr)
	if res == 0 {
		result = true
	}
	return result, err
}

func mysqlAuth(ip, port, user, pass string) (result bool, err error) {
	result = false
	db, err := sql.Open("mysql", user+":"+pass+"@tcp("+ip+":"+port+")/mysql?charset=utf8")
	if err != nil {
	}
	if db.Ping() == nil {
		result = true
	}
	return result, err
}

func mssqlAuth(ip, port, user, pass string) (result bool, err error) {
	result = false
	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%s;encrypt=disable", ip, user, pass, port)
	db, err := sql.Open("mssql", connString)
	if err == nil {
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result = true
		}
	}
	return result, err
}

func mogodbAuth(ip string, port string, username string, password string) (result bool, err error) {
	session, err := mgo.DialWithTimeout("mongodb://"+username+":"+password+"@"+ip+":"+port+"/"+"admin", time.Second*3)
	if err == nil && session.Ping() == nil {
		defer session.Close()
		if err == nil && session.Run("serverStatus", nil) == nil {
			result = true
		}
	}
	return result, err
}

func postgresAuth(ip string, port string, username string, password string) (result bool, err error) {
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", username, password, ip, port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(3 * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			temp := fmt.Sprintf("[+] Postgres:%v:%v:%v %v", ip, port, username, password)
			fmt.Println(temp)
			result = true
		}
	}
	return result, err
}

func runTask(tasks []Task, threads *int, serv string) {
	Threads := *threads
	var wg sync.WaitGroup
	taskCh := make(chan Task, Threads*2)
	switch {
	case serv == "ssh":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						res, err := sshAuth(task.target, task.port, task.user, task.password)
						if res == true && err == nil {
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "SSH", task.port, task.user, task.password)
						}
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}
	case serv == "ftp":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						//fmt.Println("[-]Checking " + task.target + " [" + task.port + "] " + task.user + " " + task.password)
						res, err := ftpAuth(task.target, task.port, task.user, task.password)
						if res == true && err == nil {
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "FTP", task.port, task.user, task.password)
						}
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}
	case serv == "smb":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						res, err := smbAuth(task.target, task.port, task.user, task.password)
						if res == true && err == nil {
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "SMB", task.port, task.user, task.password)
						}
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}
	case serv == "mssql":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						res, err := mssqlAuth(task.target, task.port, task.user, task.password)
						if res == true && err == nil {
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "Mssql", task.port, task.user, task.password)
						}
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}

	case serv == "mysql":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						res, err := mysqlAuth(task.target, task.port, task.user, task.password)
						if res == true && err == nil {
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "Mysql", task.port, task.user, task.password)
						}
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}
	case serv == "postgresql":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						res, err := postgresAuth(task.target, task.port, task.user, task.password)
						if res == true && err == nil {
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "postgresql", task.port, task.user, task.password)
						}
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}
	case serv == "winrm":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						res, err := winrmAuth(task.target, task.user, task.password, 5985)
						if res == true && err == nil {
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "WinRM", task.port, task.user, task.password)
							//fmt.Print("\n")
						}
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}
	case serv == "mongodb":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						res, err := mogodbAuth(task.target, task.port, task.user, task.password)
						if res == true && err == nil {
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "Mongodbsql", task.port, task.user, task.password)
						}
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}
	case serv == "redis":
		{
			for i := 0; i < Threads; i++ {
				go func() {
					for task := range taskCh {
						var client = redis.NewClient(&redis.Options{
							//Addr:     ip + ":6379",
							Addr:     fmt.Sprintf("%s:%s", task.target, task.port),
							Username: fmt.Sprintf("%s", task.user),
							Password: fmt.Sprintf("%s", task.password),
							DB:       0,
						})
						ctx := context.Background()
						pong, err := client.Ping(ctx).Result()
						if pong != "" && err == nil {
							//fmt.Printf("[Success!]%s,username:%s,pass:%s\n", task.target, task.user, task.password)
							fmt.Println("[+]Found:" + task.target + " [" + task.port + "] " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "Redis", task.port, task.user, task.password)
						}
						client.Close()
						wg.Done()
					}
				}()
			}
			for _, task := range tasks {
				wg.Add(1)
				taskCh <- task
			}
			wg.Wait()
			close(taskCh)
			break
		}
	default:
		fmt.Println("The service blasting is not supported!")
	}
}

func runNewTask(tasks []T1, serv string) {
	var wg sync.WaitGroup
	switch {
	case serv == "ftp":
		{
			for _, task := range tasks {
				var Lftp *goftp.FTP
				var err error
				wg.Add(1)
				go func(task T1) {
					defer wg.Done()

					if Lftp, err = goftp.Connect(task.target); err != nil {
						//fmt.Println(err)
					}

					defer Lftp.Close()

					if err = Lftp.Login(task.user, task.password); err == nil {
						fmt.Println("[+]Found:" + task.target + " " + task.user + " " + task.password)
						logger.PrintBrute(task.target, "ftp", "", task.user, task.password)
					}

				}(task)
			}
			wg.Wait()
		}
	case serv == "ssh":
		{
			for _, task := range tasks {
				wg.Add(1)
				authMethods := []ssh.AuthMethod{}
				keyboardInteractiveChallenge := func(
					user,
					instruction string,
					questions []string,
					echos []bool,
				) (answers []string, err error) {
					if len(questions) == 0 {
						return []string{}, nil
					}
					return []string{task.password}, nil
				}
				go func(task T1) {
					defer wg.Done()

					authMethods = append(authMethods, ssh.KeyboardInteractive(keyboardInteractiveChallenge))
					authMethods = append(authMethods, ssh.Password(task.password))

					sshConfig := &ssh.ClientConfig{
						User: task.user,
						Auth: authMethods,
						HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
							return nil
						},
					}

					client, err := ssh.Dial("tcp", task.target, sshConfig)
					if err == nil {
						defer client.Close()
						session, err := client.NewSession()
						errRet := session.Run("echo hello")
						if err == nil && errRet == nil {
							defer session.Close()
							fmt.Println("[+]Found:" + task.target + " " + task.user + " " + task.password)
							logger.PrintBrute(task.target, "ssh", "", task.user, task.password)
						}
					}
				}(task)

			}
			wg.Wait()
		}
	}
}
