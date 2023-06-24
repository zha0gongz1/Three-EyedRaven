package flags

import (
	plugin "Three-EyedRaven/plugins"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"time"
)

type allFlags struct {
	Hosts       string
	Ports       string
	User        string
	Pass        string
	Thread      int
	NoWebDetect bool
	NoBrute     bool
}

type detectFlags struct {
	Hosts       string
	NoWebDetect bool
	Ports       string
	Thread      int
}

type BurpFlags struct {
	Hosts   string
	Service string
	Ports   string
	User    string
	Pass    string
	Thread  int
}

var all allFlags
var detect detectFlags
var burp BurpFlags

var rootCmd = &cobra.Command{

	Use:   "Three-EyedRaven",
	Short: "Three-EyedRaven is a tool to detect",
	Long:  "[Notice]:\n[*]The three-EyedRaven is only used as detection and blasting tool for intranet penetration, doesn't contain any exploit code!",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use Three-EyedRaven -h or --help for help.")
	},
}

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "[*]Use all scanner module.",
	Run: func(cmd *cobra.Command, args []string) {
		if all.Hosts == "" {
			_ = cmd.Help()
			return
		}

		start := time.Now()
		defer func() {
			cost := time.Since(start)
			fmt.Println("[*]Total Time:", cost)
		}()
		plugin.AllFunc(&all.Hosts, &all.Ports, &all.NoWebDetect, &all.NoBrute, all.User, all.Pass, &all.Thread)

	},
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "[*]Intranet host and port detection module.",
	Run: func(cmd *cobra.Command, args []string) {
		if detect.Hosts == "" {
			_ = cmd.Help()
			return
		}

		start := time.Now()
		defer func() {
			cost := time.Since(start)
			fmt.Println("[*]Total Time:", cost)
		}()

		plugin.DetectFunc(&detect.Hosts, &detect.NoWebDetect, &detect.Ports, &detect.Thread)
	},
}

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "[*]Brute Port Services.",
	Run: func(cmd *cobra.Command, args []string) {
		if burp.Hosts == "" {
			_ = cmd.Help()
			return
		}

		start := time.Now()
		defer func() {
			cost := time.Since(start)
			fmt.Println("[*]Total Time:", cost)
		}()

		plugin.BruteService(burp.User, burp.Pass, &burp.Hosts, &burp.Service, burp.Ports, &burp.Thread)
	},
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(allCmd)
	allCmd.Flags().StringVarP(&all.Hosts, "hosts", "H", "", "设置扫描的目标参数(.eg) \n[192.168.233.1]\n[172.16.1.1/16]")
	allCmd.Flags().IntVarP(&all.Thread, "thread", "t", 400, "设置扫描时的扫描线程 (.eg) 默认400线程")
	allCmd.Flags().BoolVar(&all.NoWebDetect, "nw", false, "设置是否进行web服务探测")      //指定--nw即为真(不识别web)，不指定就是默认值 false
	allCmd.Flags().BoolVar(&all.NoBrute, "nb", false, "设置是否进行ftp&ssh&RDP等服务爆破") //指定--nb即为真(不爆破)，不指定就是默认值 false
	allCmd.Flags().StringVarP(&all.User, "udict", "u", "", "设置扫描时爆破采用的用户名字典 (.eg) 不设置将采用默认用户名字典")
	allCmd.Flags().StringVarP(&all.Pass, "pass-dic", "p", "", "设置扫描时爆破采用的密码字典 (.eg) 不设置将采用默认密码字典")

	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().StringVarP(&detect.Hosts, "hosts", "H", "", "设置扫描的目标参数(.eg [-H 192.168.233.1] [-H 172.16.1.1/16])")
	detectCmd.Flags().IntVarP(&detect.Thread, "thread", "t", 400, "设置扫描时的扫描线程 (.eg) 默认400 线程")
	detectCmd.Flags().BoolVar(&detect.NoWebDetect, "nw", false, "设置是否进行web服务探测")
	detectCmd.Flags().StringVarP(&detect.Ports, "ports", "P", "", "设置扫描的端口参数(.eg 80,443-445) 不设置将采用默认端口字典 top 1000\"")

	rootCmd.AddCommand(bruteCmd)
	bruteCmd.Flags().StringVarP(&burp.Hosts, "hosts", "H", "", "设置扫描的目标参数(.eg [-H 192.168.233.1] [-H 172.16.1.1/16])")
	bruteCmd.Flags().StringVarP(&burp.Service, "service", "S", "", "设置爆破的服务名称(.eg) \n[mssql,ftp,ssh,mysql,rdp,postgres,redis,winrm,smb,mongodb]")
	bruteCmd.Flags().IntVarP(&burp.Thread, "thread", "t", 200, "设置扫描时的扫描线程 (.eg) 默认200线程")
	bruteCmd.Flags().StringVarP(&burp.Ports, "ports", "P", "", "设置爆破端口(.eg -P 2222)")
	bruteCmd.Flags().StringVarP(&burp.User, "udict", "u", "", "设置扫描时爆破采用的用户名字典 (.eg -u users.txt),不设置将采用默认用户名字典")
	bruteCmd.Flags().StringVarP(&burp.Pass, "pdict", "p", "", "设置扫描时爆破采用的密码字典 (.eg -p pass.txt),不设置将采用默认密码字典")

}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}
