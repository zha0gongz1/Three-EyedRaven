package config

import (
	"log"
	"os"
)

var LogFile string

func AliveLog(res *[]string) {
	logFile, err := os.OpenFile("z.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetFlags(0)
	log.Printf("-------------------Alives Res----------------------")
	for _, ip := range *res {
		log.Printf("[+]%s\n", ip)
	}
}

func PortLog(res *[]string) {
	logFile, err := os.OpenFile("z.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.Printf("-------------------Ports Res-----------------------")
	for _, ipport := range *res {
		log.Printf("%s\n", ipport)
	}
}

func PrintBrute(host, ScanProtocol string, port string, user string, pass string) {
	log.SetFlags(0)
	if port != "" {
		logFile, err := os.OpenFile("z.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()
		log.Printf("-------------------Brute Res-----------------------")
		log.SetOutput(logFile)
		log.Printf("[%s] %s [%s][%s][%s]\n", ScanProtocol, host, port, user, pass)
	} else {
		logFile, err := os.OpenFile("z.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
		log.Printf("-------------------Brute Res-----------------------")
		log.Printf("[%s] %s [%s][%s]\n", ScanProtocol, host, user, pass)
	}
}

func PrintNetinfo(res *string) {
	logFile, err := os.OpenFile("z.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	log.Printf("--------------------Net info-----------------------")
	if *res == "" {
		log.Println("[*]Probing ends, but nothing is found.")
	} else {
		log.Printf("%v", *res)
	}

	log.Printf("---------------------------------------------------")
}

func PrintWeb(res string) {
	logFile, err := os.OpenFile("z.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.Printf("%s", res)
}

func ErrLog(e string) {
	logFile, err := os.OpenFile("z_e.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.Printf("[errorMsg]: %s \n", e)
}
