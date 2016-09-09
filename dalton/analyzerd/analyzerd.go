package main

import (
	"dalton/engine"
	"fmt"

)

func main() {

	naslFile := &engine.NaslFile{
		DescriptionOnly:0,
		Authenticated:1,
		File:"/media/snouto/rest/projects/openvas/nvts/gb_default_smb_credentials.nasl",
		Target:"192.168.1.8",
	}
	//get description and the script out from the current nasl file
	var messages []string
	var success int
	err := engine.ExecuteNaslScript(naslFile,&messages,&success)
	if err != nil {
		fmt.Printf("We received an error : %v",err)
		return
	}
	for _ , msg := range messages{
		fmt.Println(msg)
	}
	fmt.Printf("Script Result : %v",success)
	/*script , err := engine.DescribeNaslFile(naslFile)
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
