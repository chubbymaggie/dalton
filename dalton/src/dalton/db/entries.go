package db

import (
	"dalton/db/models"
	"dalton/utils"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

const (
	ENTRIES_COLLECTION_NAME = "Reconns"
)

func GetAllScanEntries() (searchResults []models.Reconn, err error) {

	searchResults = []models.Reconn{}
	query := func(c *mgo.Collection) error {

		return c.Find(bson.M{"status": false}).All(&searchResults)

	}
	search := func() error {
		return WithCollection(ENTRIES_COLLECTION_NAME, query)
	}
	err = search()
	if err != nil {
		return
	}
	return
}
func SearchEntries(q interface{}, skip, limit int) (searchResults []models.Reconn, err error) {
	searchResults = []models.Reconn{}
	query := func(c *mgo.Collection) error {

		fn := c.Find(q).Skip(skip).Limit(limit).All(&searchResults)

		if limit < 0 {
			fn = c.Find(q).Skip(skip).All(&searchResults)
		}
		return fn
	}
	search := func() error {
		return WithCollection(ENTRIES_COLLECTION_NAME, query)
	}
	err = search()
	if err != nil {
		return
	}
	return
}
func InsertEntry(entry *models.Reconn) error {

	collection, session := GetCollection(ENTRIES_COLLECTION_NAME)
	defer session.Close()
	//create a new object Id for the passed scan entry
	if entry.ScanId == "" {
		entry.ScanId = utils.NewObjectId()
	}

	return collection.Insert(entry)
}
func DeleteEntry(entry *models.Reconn) error {
	collection, session := GetCollection(ENTRIES_COLLECTION_NAME)
	defer session.Close()
	return collection.Remove(bson.M{"_id": entry.ScanId})
}
func UpdateEntry(entry *models.Reconn) error {
	collection, session := GetCollection(ENTRIES_COLLECTION_NAME)
	defer session.Close()
	id := entry.ScanId
	update := bson.M{"$set": bson.M{"startTime": entry.StartTime, "endTime": entry.EndTime,
		"initiatedBy": entry.InitiatedBy, "status": entry.Status, "commandArgs": entry.CommandArgs,
		"progress":      entry.Progress,
		"statusMessage": entry.StatusMessage,
	}}
	return collection.UpdateId(id, update)
}
func UpdateEntryWith(entry *models.Reconn, updateQuery *bson.M) error {
	collection, session := GetCollection(ENTRIES_COLLECTION_NAME)
	defer session.Close()
	id := entry.ScanId
	return collection.UpdateId(id, updateQuery)
}
func EnsureEntriesIndices(c *mgo.Collection) error {

	index := mgo.Index{

		Key:        []string{"initiatedBy", "status"},
		Unique:     false,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	return c.EnsureIndex(index)
}
