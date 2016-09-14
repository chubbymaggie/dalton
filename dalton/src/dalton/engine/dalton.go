package engine

import (
	"fmt"
	"sync"
	"dalton/config"
	"dalton/log"
	"encoding/gob"
	"time"

)
const (
	DALTON_ENGINE_NAME = "Dalton Engine v0.1"
	DALTON_KB_GOB_FILENAME ="dalton.gob"
)


//Register the Dalton Knowledge base into go gob binary format
func init(){
	gob.Register(DaltonKB{})
}


type DaltonEngine struct {
	KB *DaltonKB
	Target string //the target which will be scanned
	RootDir string //the root dir of the script to run scanning
	PrivateKey string // the private key needed for verifying scripts signature
	initStatus bool // the initialization status of the engine
}
func (engine *DaltonEngine) GetTotalNumberOfScripts() int {

	totalNumber := 0

	for _ , val := range engine.KB.KB {

		totalNumber += len(val)
	}

	return totalNumber


}
func (dalton *DaltonEngine) InitEngine() error{


	//This function should be called first to initialize the engine and do any housekeeping operations needed
	return dalton.initEngine()
}

func (dalton *DaltonEngine) initEngine() error {
	//do any house keeping operations in here privately
	loader := &ScriptLoader{}
	loader.InitLoader()
	//get the root directory from the configuration
	rootDir := config.ReadKey("general","plugins_dir").String()
	//begin the loading process

	if dalton.KB == nil || len(dalton.KB.KB) <=0 || dalton.checkKBModTime(rootDir) < 0 {
		//get the KB Location
		kb_dir := config.ReadKey("general","kb_dir").String()
		kb , err := loader.LoadKnowledgeBase(kb_dir,rootDir)
		if err != nil {
			log.Log(DALTON_ENGINE_NAME,err)
			return err
		}
		dalton.KB = kb
	}
	dalton.RootDir = rootDir
	dalton.initStatus = true
	dalton.PrivateKey = config.ReadKey("security","privatekey").String()
	return nil
}

func (dalton *DaltonEngine) checkKBModTime(rootDir string) int {

	return CheckModificationTime(dalton.KB.ModTime,rootDir)
}

func (dalton *DaltonEngine) StartScanning() error {

	//this method should be called after successful scanning
	if !dalton.initStatus {

		return fmt.Errorf("Dalton Engine wasn't initialized Successfully , Please Initialize the scan engine first")
	}

	return nil
}


//////////////////////////////////Dalton Knowledge base////////////////////////////

type DaltonKB struct {
	KB map[int][]DaltonNode // The dalton knowledge base
	lock *sync.Mutex
	ready bool //Whether the Dalton KB is ready or not
	scriptsCount int //the total number of scripts
	RootDir string // the root directory for physical scripts
	ModTime time.Time
}
func (kb *DaltonKB) InitKnowledgeBase() error {
	//initialize the variables needed for Dalton Knowledge base to function properly
	kb.KB = make(map[int][]DaltonNode)
	kb.lock = &sync.Mutex{}
	kb.ready = false
	return nil
}

func (kb *DaltonKB) AddKnowledgeBase(category int , data *DaltonNode) error {

	if _ , ok := kb.KB[category]; ok {

		//get the total number of elements in the data queue
		//val.Push(data)
		kb.KB[category] = append(kb.KB[category],*data)

		return nil
	}else {
		//that means the category does not exist at all
		//so add it
		kb.KB[category] = make([]DaltonNode,1)
		//kb.KB[category].Push(*data)
		kb.KB[category] = append(kb.KB[category],*data)
		return nil
	}
}
func (kb *DaltonKB) IsReady() bool {
	return kb.ready
}
func (kb *DaltonKB) GetTotalScriptsCount() int {
	return kb.scriptsCount
}




