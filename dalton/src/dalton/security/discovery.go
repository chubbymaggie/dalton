package security

import (
	"fmt"
	"github.com/lair-framework/go-nmap"
	"github.com/nu7hatch/gouuid"
	"io/ioutil"
	"os"
	"os/exec"
)

type ScanSettings struct {
	TempDir     string
	FullXmlPath string
	Args        []string
}

func (scan *ScanSettings) initialize() error {

	//do some checking if the temp dir was set or not
	if len(scan.TempDir) <= 0 {
		return fmt.Errorf("Security-nmap : You have to set the temporary directory before initiating the scan")
	}
	if len(scan.Args) <= 0 {
		return fmt.Errorf("Security-nmap : You can't start a Nmap Scan without giving arguments to executing the command")
	}

	//now generate a random file name
	uid, err := uuid.NewV4()
	if err != nil {
		return err

	}
	fileName := fmt.Sprintf("%s.xml", uid.String())
	fullPath := fmt.Sprintf("%s/%s", scan.TempDir, fileName)
	scan.FullXmlPath = fullPath
	return nil
}

func Scan(settings *ScanSettings) ([]nmap.Host, error) {

	//now initialize the scan settings
	settings.initialize()
	//now execute the scan results
	return scan(settings.FullXmlPath, settings.Args...)
}

func scan(tempxmlFile string, args ...string) ([]nmap.Host, error) {

	defer removeFile(tempxmlFile)

	err := executeCommand(tempxmlFile, args...)
	if err != nil {
		return nil, err
	}
	output, err := readOutput(tempxmlFile)
	if err != nil {
		return nil, err
	}
	//access the file
	//now parse the output
	nmapRun, err := nmap.Parse(output)
	if err != nil {
		return nil, err
	}
	if nmapRun != nil {
		return nmapRun.Hosts, nil

	} else {
		return nil, fmt.Errorf("Security-Nmap: Error in getting the output from the nmap tool")
	}
}

func removeFile(location string) error {

	return os.Remove(location)
}

func readOutput(location string) ([]byte, error) {

	//try to open the file and read it fully
	contents, err := ioutil.ReadFile(location)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

func executeCommand(tempFile string, args ...string) error {
	arguments := []string{}
	arguments = append(arguments, "-oX", tempFile)
	arguments = append(arguments, args...)
	command := exec.Command("nmap", arguments...)
	command.Start()
	return command.Wait()

}
