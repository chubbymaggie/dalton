package db

import (
	"labix.org/v2/mgo"
	"dalton/db/models"
	"labix.org/v2/mgo/bson"
	"dalton/utils"
)

const (

	ENTRIES_COLLECTION_NAME="scanEntries"
)

func GetAllScanEntries() (searchResults []models.ScanEntry , err error){

	searchResults = []models.ScanEntry{}
	query := func(c *mgo.Collection) error {

		return c.Find(bson.M{"status":false}).All(&searchResults)

	}
	search := func() error {
		return WithCollection(ENTRIES_COLLECTION_NAME,query)
	}
	err = search()
	if err != nil {
		return
	}
	return
}
func SearchEntries(q interface{},skip,limit int) (searchResults []models.ScanEntry , err error){
	searchResults = []models.ScanEntry{}
	query := func(c *mgo.Collection) error {

		fn := c.Find(q).Skip(skip).Limit(limit).All(&searchResults)

		if limit < 0 {
			fn = c.Find(q).Skip(skip).All(&searchResults)
		}
		return fn
	}
	search := func() error {
		return WithCollection(ENTRIES_COLLECTION_NAME,query)
	}
	err = search()
	if err != nil {
		return
	}
	return
}
func InsertEntry(entry *models.ScanEntry) error {

	collection , session := GetCollection(ENTRIES_COLLECTION_NAME)
	defer session.Close()
	//create a new object Id for the passed scan entry
	if entry.ScanId == "" {
		entry.ScanId = utils.NewObjectId()
	}

	return collection.Insert(entry)
}
func DeleteEntry(entry *models.ScanEntry) error {
	collection , session := GetCollection(ENTRIES_COLLECTION_NAME)
	defer session.Close()
	return collection.Remove(bson.M{"_id":entry.ScanId})
}
func UpdateEntry(entry *models.ScanEntry) error {
	collection , session := GetCollection(ENTRIES_COLLECTION_NAME)
	defer session.Close()
	id := entry.ScanId
	update := bson.M{"$set":bson.M{"startTime":entry.StartTime,"endTime":entry.EndTime,
		"initiatedBy":entry.InitiatedBy,"status":entry.Status,"commandArgs":entry.CommandArgs,
		"progress":entry.Progress,
		"statusMessage":entry.StatusMessage,
	}}
	return collection.UpdateId(id,update)
}
func UpdateEntryWith(entry *models.ScanEntry , updateQuery *bson.M) error {
	collection,session := GetCollection(ENTRIES_COLLECTION_NAME)
	defer session.Close()
	id := entry.ScanId
	return collection.UpdateId(id,updateQuery)
}
func EnsureEntriesIndices (c *mgo.Collection) error {

	index := mgo.Index{

		Key:[]string{"initiatedBy","status"},
		Unique:     false,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	return c.EnsureIndex(index)
}
