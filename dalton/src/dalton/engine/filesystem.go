package engine

import (
	"time"
	"os"
	"encoding/gob"
	"fmt"
)

//This function checks if the Knowledge base date/time of modification is equal (0)
//or larger than 1 or less than -1 that of the physical scripts directory itself

func CheckModificationTime(KB_Date time.Time,dir string) int {

	//get the current modification date for the current directory
	info , _ := os.Stat(dir)

	if (KB_Date == info.ModTime()) {
		return 0
	}else if (KB_Date.After(info.ModTime())){
		return 1
	}else {
		return -1
	}
}

func SaveKB(kb *DaltonKB,topath string ) error {

	//
	fullName := fmt.Sprintf("%s/%s",topath,DALTON_KB_GOB_FILENAME)
	//create a new encoder
	file , err := os.OpenFile(fullName,os.O_WRONLY|os.O_CREATE|os.O_APPEND,os.FileMode(0777))
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := gob.NewEncoder(file)
	return encoder.Encode(kb)
}

func LoadKBFromDesk(location string) (*DaltonKB,error) {

	fullName := fmt.Sprintf("%s/%s",location,DALTON_KB_GOB_FILENAME)
	file , err := os.Open(fullName)
	if err != nil {
		return nil , err
	}
	defer file.Close()
	decoder := gob.NewDecoder(file)
	kb := &DaltonKB{}
	err = decoder.Decode(kb)
	if err != nil {
		return nil , err
	}
	return kb , nil
}
