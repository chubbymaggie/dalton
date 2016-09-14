package engine

import (

	"dalton/db/models"
	filepath "path/filepath"
	"dalton/log"
	"os"
	"strings"
	"fmt"

	"crypto/md5"
	"dalton/utils"

)
const (

	KB_NAME ="DaltonKB"
	MAX_COUNT_PER_LOOP = 1000
	MAX_SCRIPT_CATEGORIES = 12
)

var (
	totalScriptCount int

)

/*

  This file contains all required functions to load all Scripts in the database and stores it in memory
  as a processed ordered queue in memory

  ---The functions in here , will do the following in sequence:
  ============================================================
  1. It will communicate with the database to grab ALL registered scripts in Dalton
  2. It will begin processing each script dependency one by one.
  3. It will store that into an ordered Queue in memory
  4.It marks the overall status of Dalton Engine as Complete/Processed/Ready.
  5.It provides functions to create subsets of the ordered queue containing specific subset of scripts, in order to customize different scans
 */
type ScriptLoader struct {

	History map[string]DaltonNode

}

func (loader *ScriptLoader) InitLoader() error {

	loader.History = make(map[string]DaltonNode)
	return nil
}
func (loader *ScriptLoader) hashFile(path string) (string , error) {

	md5 := md5.New()
	bytes := []byte(path)
	md5.Write(bytes)
	hashed := md5.Sum(nil)
	return utils.EncodeToString(hashed) , nil
}
//////////////////////////////////////////////////These are functions to load scripts from the database////////////////////////////////////////////

func (loader *ScriptLoader) LoadKnowledgeBase(kb_dir,rootDir string) (*DaltonKB,error) {

	//check to see if KB exists as glob
	fullName := fmt.Sprintf("%s/%s",kb_dir,DALTON_KB_GOB_FILENAME)
	if _ , err := os.Stat(fullName);os.IsNotExist(err) {

		return loader.load(kb_dir,rootDir)
	}
	//That means the file exists , so load it
	return LoadKBFromDesk(kb_dir)

}
func (loader *ScriptLoader) load(kb_dir,rootDir string) (*DaltonKB,error) {

	kb := &DaltonKB{}
	//init the knowledge base
	kb.InitKnowledgeBase()
	info , _ := os.Stat(rootDir)
	kb.ModTime = info.ModTime()
	iterator := 0

	collectScripts := func (path string, info os.FileInfo, err error) error {

		if !info.IsDir() { // that means it is a file

			if strings.EqualFold(filepath.Ext(path),EXT_NASL_SCRIPT) { // meaning that it is a nasl file

				fmt.Println("Executing : ",path," , counter : ",iterator)

				script , err := describeNaslFile(path,rootDir)

				if err != nil {
					log.Log(KB_NAME,err)
				}

				//now Convert that script into a dalton node
				node := &DaltonNode{executed:false,ScriptFileName:path}
				//check to see if that script has dependencies
				/*if len(script.ScriptDependencies) > 0 {

					children := 0

					for children < len(script.ScriptDependencies) {

						depPath := fmt.Sprintf("%s/%s",rootDir,script.ScriptDependencies[children])
						if _ , err := os.Stat(depPath);err != nil && os.IsNotExist(err){
							children++
							continue

						}else{
							recursivelyLookForDependencies(loader,node,depPath,rootDir)
						}

						children++
					}
				}*/
				kb.AddKnowledgeBase(script.ScriptCategory,node)
				iterator++
			}

		}

		return nil
	}

	//now begin walking the dir tree
	filepath.Walk(rootDir,collectScripts)
	//finally return the knowledge base
	kb.ready = true
	//now save it into the file System and return
	err :=SaveKB(kb,kb_dir)
	fmt.Println("Finished Loading the engine")
	return kb ,err
}

func recursivelyLookForDependencies(loader *ScriptLoader,parentNode *DaltonNode, dep,rootDir string) error {



	hashed,_ := loader.hashFile(dep)

	if val , ok := loader.History[hashed];!ok {

			fmt.Println("Recursively Executing : ",dep," , Parent node : ",parentNode.ScriptFileName)
			executingScript, err := describeNaslFile(dep,rootDir)
			if err != nil {
				log.Log(KB_NAME,err)
			}
			//create a child node from that script
			child := &DaltonNode{ScriptFileName:dep,executed:false}
		        loader.History[hashed] = *child
			if len(executingScript.ScriptDependencies) > 0 { // that means it has other dependencies

				//so recursively append its children
				childrenCount := 0
				for childrenCount < len(executingScript.ScriptDependencies) {

					//get the current dependency location
					loc := fmt.Sprintf("%s/%s",rootDir, executingScript.ScriptDependencies[childrenCount])

					if(strings.EqualFold(filepath.Ext(loc),EXT_NASL_SCRIPT)){

						if _ , err := os.Stat(loc); err != nil && os.IsNotExist(err) {
							childrenCount++
							continue
						}else {
							recursivelyLookForDependencies(loader,child,loc,rootDir)
						}

					}else{
						continue
					}

					childrenCount++
				}
			}

	}else {
		fmt.Println("Appending from Internal Map")
		//append the child to the parent
		val.ScriptFileName = dep
		parentNode.Children = append(parentNode.Children,val)
	}


	return nil
}


/*func recursivelyLookForDependencies(loader *ScriptLoader,parentNode *DaltonNode, dep,rootDir string) error {



	hashed,_ := loader.hashFile(dep)

	if val , ok := loader.History[hashed];!ok {

			fmt.Println("Recursively Executing : ",dep," , Parent node : ",parentNode.ScriptFileName)
			executingScript, err := describeNaslFile(dep,rootDir)
			if err != nil {
				log.Log(KB_NAME,err)
			}
			//create a child node from that script
			child := &DaltonNode{ScriptFileName:dep,executed:false}
		        loader.History[hashed] = *child
			if len(executingScript.ScriptDependencies) > 0 { // that means it has other dependencies

				//so recursively append its children
				childrenCount := 0
				for childrenCount < len(executingScript.ScriptDependencies) {

					//get the current dependency location
					loc := fmt.Sprintf("%s/%s",rootDir, executingScript.ScriptDependencies[childrenCount])

					if(strings.EqualFold(filepath.Ext(loc),EXT_NASL_SCRIPT)){

						if _ , err := os.Stat(loc); err != nil && os.IsNotExist(err) {
							childrenCount++
							continue
						}else {
							recursivelyLookForDependencies(loader,child,loc,rootDir)
						}

					}else{
						continue
					}

					childrenCount++
				}
			}

	}else {
		fmt.Println("Appending from Internal Map")
		//append the child to the parent
		val.ScriptFileName = dep
		parentNode.Children = append(parentNode.Children,val)
	}


	return nil
}*/


func describeNaslFile(path, rootDir string) (*models.Script, error) {

	naslFile := &NaslFile{
		DescriptionOnly: 1,
		Authenticated:   1,
		File:            path,
		Target:          "192.168.1.8",
		RootDir:         rootDir,
	}
	//begin the description process
	return DescribeNaslFile(naslFile)
}

