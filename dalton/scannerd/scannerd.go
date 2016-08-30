package main

import (
	"fmt"
	"net/http"
	"dalton/scannerd"

)
/*
   The main function that will run the scannerd
 */
func main() {

	fmt.Println(fmt.Sprintf("Starting %s on Port %d",scannerd.SCANNER_NAME,27009))
	//start handling the mux
	http.Handle("/",scannerd.NewMux())
	go scannerd.StartScanning()
	http.ListenAndServe(":27009",nil)
}
