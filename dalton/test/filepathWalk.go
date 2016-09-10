package main

import (
	"path/filepath"
	"os"
	"fmt"
	"flag"
)

var (
	counter int
)
func main() {
	flag.Parse()
	//Get the root path
	root := flag.Arg(0)
	//now begin the walk process
	//dir := filepath.Dir(root)
	filepath.Walk(root,visit)

	/*file ,err := os.Open(root)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	stats , err := file.Stat()
	fmt.Println(stats.Name())*/
	/*err := filepath.Walk(root,visit)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Finished Traversing the root at : ",root," With Number of Files : ",counter)*/
}
func visit(path string , info os.FileInfo , err error) error {


	fmt.Println(fmt.Sprintf("Path:%s , info:%s", path, info.Name()))

	return nil
}
