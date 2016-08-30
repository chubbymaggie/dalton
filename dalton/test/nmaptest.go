package main

import (
	discovery "dalton/security"
	"fmt"

)

func main() {

	ScanSettings := &discovery.ScanSettings{
		Args:[]string{"-A","192.168.1.7"},
		TempDir:"/media/snouto/rest/projects/tmp",
	}

	hosts , err := discovery.Scan(ScanSettings)

	if err != nil {
		fmt.Println(err)
		return
	}
	for _ , host := range hosts {


		output := `IP Address : %s ,
		Comment: %s ,
		 Distance : %s,
		 Status: %s
		`
		fmt.Println(fmt.Sprintf(output,host.Addresses[0].Addr,host.Comment,host.Distance.Value,host.Status.State))
	}




}
