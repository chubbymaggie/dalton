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
	err := filepath.Walk(root,visit)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Finished Traversing the root at : ",root," With Number of Files : ",counter)
}
func visit(path string , info os.FileInfo , err error) error {
	if info.IsDir(){
		fmt.Println(fmt.Sprintf("path : %s , info : %v ,ext : %s, IsDir:%v",path,info.Name(),filepath.Ext(path),info.IsDir()))
	}else {
		counter++
	}
	return nil
}
