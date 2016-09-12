package engine

import (
	"labix.org/v2/mgo/bson"
	"fmt"
)

type DaltonEngine struct {

	Target string //the target which will be scanned
	RootDir string //the root dir of the script to run scanning
	ScanDB_ID bson.ObjectId //the scan id
	PrivateKey string // the private key needed for verifying scripts signature
	initStatus bool // the initialization status of the engine
}

func (dalton *DaltonEngine) InitEngine() error{

	//This function should be called first to initialize the engine and do any housekeeping operations needed
	return dalton.initEngine()
}

func (dalton *DaltonEngine) initEngine() error {

	//do any house keeping operations in here privately
	return nil
}

func (dalton *DaltonEngine) StartScanning () error {

	//this method should be called after successful scanning
	if !dalton.initStatus {

		return fmt.Errorf("Dalton Engine wasn't initialized Successfully , Please Initialize the scan engine first")
	}

	return nil
}



