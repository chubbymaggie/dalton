package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"github.com/lair-framework/go-nmap"
)

func main() {

	/*ScanSettings := &discovery.ScanSettings{
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


*/

	path := "/media/snouto/rest/projects/mohamed.xml"
	file ,err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}

	contents , err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return
	}
	nmapRun , err := nmap.Parse(contents)

	for _ , host := range nmapRun.Hosts {

		for _ , port := range host.Ports {

			fmt.Println(port.Service.CPE.Value)
		}
	}

}
