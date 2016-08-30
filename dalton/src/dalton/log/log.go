package log

import (
	"log"
	"dalton/config"
	"fmt"
	"os"
	"strings"
)





func InitLog(name string){


	log.SetFlags(log.Ldate|log.LstdFlags|log.Lshortfile)
	log.SetPrefix(fmt.Sprintf("%s : ",name))
	location , err := config.ReadConfigKey("logging","location")
	if err != nil {

		log.Println(err)
		return
	}
	/*perm , err := config.ReadKey("logging","perm").Int()

	if err != nil {

		log.Println(err)
		return
	}*/

	location += strings.ToLower(name)+".log"

	file , err := os.OpenFile(location,os.O_CREATE|os.O_APPEND|os.O_RDWR,0777)

	if err != nil {
		log.Println(err)
		return
	}
	log.SetOutput(file)

}

func init(){

	log.SetFlags(log.Ldate|log.LstdFlags|log.Lshortfile)
	name , _ := config.ReadConfigKey("product","name")
	log.SetPrefix(fmt.Sprintf("%s : ",name))
	location , err := config.ReadConfigKey("logging","location")
	if err != nil {

		log.Println(err)
		return
	}
	/*perm , err := config.ReadKey("logging","perm").Int()

	if err != nil {

		log.Println(err)
		return
	}*/

	location += strings.ToLower(name)+".log"

	file , err := os.OpenFile(location,os.O_CREATE|os.O_APPEND|os.O_RDWR,0777)

	if err != nil {
		log.Println(err)
		return
	}
	log.SetOutput(file)
}

func Log(v ...interface{}){

	log.Print(v)
}
