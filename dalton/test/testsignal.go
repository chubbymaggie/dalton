package main

import (
	"os"
	"os/signal"
	"syscall"
	"fmt"
)
func main() {
	signals := make(chan os.Signal,1)
	done := make(chan bool , 1)
	//now register the signals channel we have created to receive notifications on signTerm and signInt
	signal.Notify(signals,syscall.SIGINT,syscall.SIGTERM)
	go gracefulShutdown(signals,done)
	fmt.Println("Awaiting any Signal from the operating System To shutdown the current program.")
	<- done
}
func gracefulShutdown(signals chan os.Signal,done chan bool){
	notification := <- signals
	fmt.Println("We received the following Notification for shutting down : " + fmt.Sprintf("Signal : %v",notification))
	fmt.Println("Shutting down the operating system")
	done <- true
	syscall.Reboot(1)
}
