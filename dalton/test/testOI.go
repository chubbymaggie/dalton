package main

import (

)
import (
	"os"
	"fmt"


)

func main() {

	dir := "/media/snouto/rest/projects/openvas/nvts"
	info  , _ := os.Lstat(dir)


	fmt.Println(fmt.Sprintf("Dir MTime : %v",info.ModTime()))
	/*memory := make(map[bson.ObjectId]string)
	max := 100000
	var i int = 0
	var collisions int
	for i < max {

		currentID := utils.NewObjectId()

		if memory[currentID] != "" {

			collisions++
			continue
		}
		memory[currentID] = currentID.String()

		time.Sleep(time.Duration(10))

		i++
	}

	fmt.Println("Number of Collisions : ", collisions)*/
}
