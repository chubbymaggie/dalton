package main

import (
	"labix.org/v2/mgo/bson"
	"dalton/db"
	"fmt"
)

func main() {

	query := bson.M{"products":bson.M{"$regex":"jboss_bpm_suite:([0-9]+)(.?[0-9]?)?"}}
	results , err := db.SearchCVEs(query,0,-1)

	if err != nil {
		fmt.Println("Received the following error , " , err)
		return
	}
	fmt.Println(len(results))

	for _ , cve := range results {

		fmt.Println(cve.CveId , " : " , cve.Product)
	}
}
