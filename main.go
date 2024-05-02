package main

import (
	"fmt"
)


func printVerbos(verbose int, message string){
	if (verbose==1){fmt.Println(message)}
		elseif (verbose!=0){return null}
}

// Scan for egress options.

func tcpTest(ip string, port int, verbose int) {
	fmt.Println("Scanning TCP Port")
	
}

func udpTest(ip string, port int, verbose int) {
	fmt.Println("Scanning UDP Port")
}

func icmpTest(ip string, verbose int) {
	fmt.Println("Scanning ICMP")
}

func ipTest(ip string, verbose int) {
	fmt.Println("Scanning IP")
}



func main() {
	fmt.Println("Quantum Cat Initializing")

	// Parse command line arguments

}
