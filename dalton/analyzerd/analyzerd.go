package main

import (

	"dalton/db"
	"dalton/db/models"
	"dalton/engine"
	"fmt"
	"labix.org/v2/mgo"
	"os"
	"path/filepath"
	"strings"


)

var (
	indicator       int
	collection      *mgo.Collection
	session         *mgo.Session
	privateKey      string
	rootDir         string
	target          string
	Vulnerabilities []string
)

func attackTarget(path string, info os.FileInfo, err error) error {

	if !info.IsDir() {
		var messages []string
		var success int
		if strings.EqualFold(filepath.Ext(path), engine.EXT_NASL_SCRIPT) {

			script, err := describeNaslFile(path, rootDir)
			if err != nil {
				return err
			}
			err = executeNaslFile(target, path, rootDir, &messages, &success)
			if err != nil {
				return err
			}

			indicator++
			fmt.Println(fmt.Sprintf("Score : %v , Vulnerabilities : %d , Ids :%v",script.GetCVSS(),
				len(Vulnerabilities),Vulnerabilities))

			if success == 1 { //meaning that the script successfully execute

				//append it to the vulnerabilities
				if len(script.ScriptCveIds) > 0 && script.GetCVSS() > 0.0{
					Vulnerabilities = append(Vulnerabilities, script.ScriptOid)
				       fmt.Println(fmt.Sprintf("Total Vulnerabilities Found : %d , Indicator : %d", len(Vulnerabilities), indicator))
				}
			}

			success = 0
		}

	}

	return nil
}

func collectScripts(path string, info os.FileInfo, err error) error {

	if !info.IsDir() { //meaning that it is a file

		if strings.EqualFold(filepath.Ext(path), engine.EXT_NASL_SCRIPT) { // meaning that it is a nasl script

			script, err := describeNaslFile(path, rootDir)
			script.ScriptFileName = path
			if err != nil {
				return err
			}
			indicator++

			//now save the script into the database
			err = db.InsertScript(script, collection)
			//now sign the current script
			err = engine.SignScript(path, privateKey)
			if err == nil {
				fmt.Println(fmt.Sprintf("Script Inserted , Counter : %d", indicator))
				return nil
			} else {
				fmt.Println(fmt.Sprintf("%v", err))
				return nil
			}

		} else if strings.EqualFold(filepath.Ext(path), ".asc") { //meaning that it is a signature

			//defer the removal process of the current file
			defer os.Remove(path)
			//get the script file name from the .asc file
			scriptPath := strings.Replace(path, ".asc", ".nasl", len(".asc"))
			//now sign the current script
			engine.SignScript(scriptPath, privateKey)
		}

	}

	return nil
}

func executeNaslFile(target, path, rootDir string, messages *[]string, success *int) error {

	naslFile := &engine.NaslFile{
		DescriptionOnly: 0,
		Authenticated:   1,
		File:            path,
		Target:          target,
		RootDir:         rootDir,
	}
	return engine.ExecuteNaslScript(naslFile, messages, success)
}

func describeNaslFile(path, rootDir string) (*models.Script, error) {

	naslFile := &engine.NaslFile{
		DescriptionOnly: 1,
		Authenticated:   1,
		File:            path,
		Target:          "192.168.1.8",
		RootDir:         rootDir,
	}
	//begin the description process
	return engine.DescribeNaslFile(naslFile)
}

func main() {
	/*indicator = 0
	target = "192.168.1.8"
	collection , session = db.GetCollection(db.SCRIPTS_COLLECTION_NAME)
	defer session.Close()
	privateKey = config.ReadKey("security","privatekey").String()
	rootDir = config.ReadKey("General", "plugins_dir").String()
	fmt.Println("Begin The Collection Process")
	//define the root
	root := "/media/snouto/rest/projects/openvas/nvts"
	//now get the total number of scripts in path
	totalNumber, err := engine.GetNumScriptsInPath(root)
	if err != nil {
		fmt.Println(fmt.Sprintf("Received : %s", err))
		return
	}
	fmt.Println("Total Number of Scripts : ", totalNumber)
	fmt.Println("Begin the walking process")

	engine.WalkDirTree(root, collectScripts)

	if len(Vulnerabilities) > 0 {

		for _, vuln := range Vulnerabilities {

			fmt.Println(fmt.Sprintf("We found this : %s", vuln))
		}
	}
	fmt.Println("Finished")
	*/


	engine := &engine.DaltonEngine{}
	err := engine.InitEngine()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Finished")

	/*naslFile := &engine.NaslFile{
		DescriptionOnly:1,
		Authenticated:1,
		File:"/media/snouto/rest/projects/openvas/nvts/gb_default_smb_credentials.nasl",
		Target:"192.168.1.8",
	}
	//get description and the script out from the current nasl file
	*/ /*var messages []string
	var success int
	err := engine.ExecuteNaslScript(naslFile,&messages,&success)
	if err != nil {
		fmt.Printf("We received an error : %v",err)
		return
	}
	for _ , msg := range messages{
		fmt.Println(msg)
	}
	fmt.Printf("Script Result : %v",success)*/ /*
		script , err := engine.DescribeNaslFile(naslFile)
		if err != nil {
			fmt.Printf("Received the following error : %v\n",err)
			return
		}
		//now save it into the database
		Collection , session := db.GetCollection(db.SCRIPTS_COLLECTION_NAME)
		defer session.Close()
		err = db.InsertScript(script,Collection)

		if err != nil {
			fmt.Printf("Received the following error during saving the current file : %v\n",err)
			return
		}
		fmt.Printf("Successfully saved the details of the current Nasl Script into the database\n")*/

}
