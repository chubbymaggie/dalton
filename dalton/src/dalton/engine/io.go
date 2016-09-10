package engine

import (
	path "path/filepath"
	"os"
	"strings"
)

var (
	NumOfFiles int
)

func WalkDirTree(root string , WalkFunc path.WalkFunc) error {

	return path.Walk(root,WalkFunc)
}

func GetNumScriptsInPath(root string) (int,error){

	//Empty the counter each time this function is called
	NumOfFiles = 0
	err := path.Walk(root,counterWalkFunc)
	if err != nil {
		return -1,err
	}
	return NumOfFiles,nil
}

func counterWalkFunc(root string, info os.FileInfo, err error) error {

	if strings.EqualFold(path.Ext(root),EXT_NASL_SCRIPT) {

		NumOfFiles++
	}
	return nil
}
