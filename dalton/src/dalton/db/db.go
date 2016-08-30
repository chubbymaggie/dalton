package db

import (
	"dalton/config"
	"dalton/log"
	"labix.org/v2/mgo"
	"fmt"
)


var (

	host string
	port int
	database string
	session *mgo.Session
)

/*
   This function will test if the database feature is already enabled or disabled
 */
func init(){



	defer func(){


		if data:= recover();data != nil {

			log.Log(data)
			return
		}
	}()

	//check to see if the database feature is enabled or not enabled
	if (!isEnabled()){

		log.Log("Database is not enabled , returning....")
		return
	}
}

func Connect() (*mgo.Session,error) {


	if (!isEnabled()){

		return nil , fmt.Errorf("Database feature is disabled.")
	}

	defer func(){


		if data := recover();data != nil {

			log.Log(data)
			//return empty or nil session to the database
			return
		}
	}()
	loadDBInfo()
	return session , nil
}

func WithCollection(collection string, s func(*mgo.Collection) error) error {
    session , err := Connect()
	if err != nil {
		return err
	}

    defer session.Close()
    c := session.DB(database).C(collection)
    return s(c)
}


func loadDBInfo() {

	//get the host of the database
	db_type , _ := config.ReadConfigKey("database","type")
	host = config.ReadKey(db_type,"host").String()
	port , _ = config.ReadKey(db_type,"port").Int()
	database = config.ReadKey(db_type,"db").String()
	//make sure there is no previous ongoing connection
	CloseConnection()
	//connect to the database
	var err error
	session , err = mgo.Dial(host)
	if err != nil {
		panic(err)
		return
	}
}


func CloseConnection(){

	if session != nil {

		session.Close()
	}
}

func IsConnected() bool {

	if session != nil {
		return true
	}else{
		return false
	}
}

/*
   this function will check whether the database is enabled or not enabled
 */
func isEnabled() bool{

	enabled , err := config.ReadKey("database","enabled").Int()

	if err != nil {

		log.Log(err)
		return false
	}

	if enabled > 0 {
		return true
	}else {
		return false
	}
}


/*
   this function returns a handler to the underlying database or nil
 */
func GetDatabase() *mgo.Database {

	session , error := Connect()
	if error != nil {

		log.Log(error)
		return nil
	}
	return session.DB(database)
}

func GetCollection(collectionName string) *mgo.Collection {

	Database := GetDatabase()

		if Database != nil {
			collection := Database.C(collectionName)
			ensureIndices(collectionName,collection)
			return collection

		}else {
			return nil
		}
}

func ensureIndices(collectionName string ,  C *mgo.Collection) error {

	switch collectionName {

	case Users_Collection_Name:
		return EnsureUsersIndices(C)
	case SCANS_COLLECTION_NAME:
		return EnsureScansIndices(C)
	case ASSETS_COLLECTION_NAME:
		return EnsureAssetsIndices(C)
	case ENTRIES_COLLECTION_NAME:
		return EnsureEntriesIndices(C)
	case CVE_COLLECTION_NAME:
		return EnsureCVEsIndices(C)
	}
	return nil
}





