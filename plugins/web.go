package plugins

import (
	dict "Three-EyedRaven/config"
	logger "Three-EyedRaven/config"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"
)

func httpdScan(Target []string, threads *int) {
	var (
		dialTimout = 7 * time.Second
		keepAlive  = 7 * time.Second
	)
	//proxy, _ := url.Parse("http://127.0.0.1:8080")
	dialer := &net.Dialer{
		Timeout:   dialTimout, //限制建立TCP连接的时间
		KeepAlive: keepAlive,
	}
	tr := &http.Transport{
		//Proxy:           http.ProxyURL(proxy),
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     5,
		MaxIdleConns:        0,         //连接池对所有host的最大连接数量，默认无穷大
		MaxIdleConnsPerHost: 200,       //连接池对每个host的最大连接数量。（一个host的情况下最好与上面保持一致）
		IdleConnTimeout:     keepAlive, //空闲时间设置
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 3 * time.Second, //限制 TLS握手的时间
		DisableKeepAlives:   false,           //默认为false（长连接）
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
		Timeout:   7 * time.Second,
		Transport: tr,
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex
	ch := make(chan struct{}, *threads)
	for _, url := range Target {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			ch <- struct{}{}
			defer func() { <-ch }()
			req, err := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5666.197 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
			req.Header.Set("Accept-Language", "en;q=1.0, fr;q=0.8")
			//req.Header.Set("User-Agent", dict.UA[index])
			//req.Header.Set("Accept-Language", dict.AL[index])
			resp, err := client.Do(req)
			//resp, err := client.Get(url)
			if err != nil {
				//fmt.Printf("Error fetching: %s\n", url)
				return
			}
			defer resp.Body.Close()
			mutex.Lock()
			if resp.StatusCode == 401 {
				fmt.Println(fmt.Sprintf("[401] %s ------BasicBrute", url))
				BasicAuthBrute(url)
			} else {
				re := regexp.MustCompile(`<title>(.*?)</title>`)
				bodyBytes, _ := ioutil.ReadAll(resp.Body)
				bodyString := string(bodyBytes)
				bodyLen := len(bodyString)
				match := re.FindStringSubmatch(bodyString)
				if len(match) != 0 {
					logger.PrintWeb(fmt.Sprintf("[%d] %s [%d]\tTitle:%s", resp.StatusCode, url, bodyLen, match[1]))
				} else {
					logger.PrintWeb(fmt.Sprintf("[%d] %s [%d]\tTitle:NULL", resp.StatusCode, url, bodyLen))
				}
			}
			mutex.Unlock()
		}(url)
	}
	wg.Wait()
}

func BasicAuthBrute(Target string) {
	for _, user := range dict.Users["BaseAuth"] {
		for _, pass := range dict.Passwords {
			res, err := BasicAuth(Target, user, pass)
			if res == true && err == nil {
				logger.PrintWeb(fmt.Sprintf("[+]Basic Brute Success:%s | user:%s | password:%s\n", Target, user, pass))
			}

		}
	}
}

func BasicAuth(url1, user, pass string) (result bool, err error) {
	result = false
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url1, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("Accept-Language", "zh_TW;q=1.0, en_US;q=0.8")
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != 401 {
			//logger.PrintIsok(ScanType,url,user, pass)
			return true, err
		}
	}
	return result, err
}
