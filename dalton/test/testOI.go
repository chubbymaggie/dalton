package main

import (

	"fmt"
	"time"


	"labix.org/v2/mgo/bson"
	"dalton/utils"
)

func main() {

	memory := make(map[bson.ObjectId]string)
	max := 100000
	var i int  = 0
	var collisions int
	for i < max {


		currentID := utils.NewObjectId()

		if(memory[currentID] != ""){

			collisions++
			continue
		}
		memory[currentID] = currentID.String()

		time.Sleep(time.Duration(10))

		i++
	}

	fmt.Println("Number of Collisions : ",collisions)
}
