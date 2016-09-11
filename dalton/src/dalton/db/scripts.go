package db

import (
	"dalton/db/models"
	"dalton/utils"
	"fmt"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

const (
	SCRIPTS_COLLECTION_NAME = "Scripts"
)

func UpdateScriptWith(script *models.Script, updateQuery *bson.M) error {

	collection, session := GetCollection(SCRIPTS_COLLECTION_NAME)
	defer session.Close()
	id := script.Id
	return collection.UpdateId(id, updateQuery)
}

func UpdateScript(script *models.Script) error {

	collection, session := GetCollection(SCRIPTS_COLLECTION_NAME)
	defer session.Close()
	id := script.Id
	return collection.UpdateId(id, script.GetUpdateQuery())
}
func DeleteScript(script *models.Script) error {
	collection, session := GetCollection(SCRIPTS_COLLECTION_NAME)
	defer session.Close()
	return collection.Remove(bson.M{"id": script.Id})
}

func InsertScript(script *models.Script, collection *mgo.Collection) error {

	if script == nil {
		fmt.Println("nil Script")
		return fmt.Errorf("nil Script")
	}
	if script.Id == "" {
		script.Id = utils.NewObjectId()
	}
	err := collection.Insert(script)
	return err
}

func SearchScripts(q interface{}, skip, limit int) (searchResults []models.Script, err error) {

	searchResults = []models.Script{}
	query := func(c *mgo.Collection) error {
		fn := c.Find(q).Skip(skip).Limit(limit).All(&searchResults)
		if limit < 0 {
			fn = c.Find(q).Skip(skip).All(&searchResults)
		}
		return fn
	}
	search := func() error {
		return WithCollection(SCRIPTS_COLLECTION_NAME, query)
	}

	err = search()
	if err != nil {
		return
	}
	return
}

func EnsureScriptsIndices(c *mgo.Collection) error {

	indices := []mgo.Index{{
		Key:        []string{"sid", "oid"},
		Unique:     true,
		DropDups:   false,
		Background: true,
		Sparse:     true,
	},
		{
			Key:        []string{"cveIds", "name", "fileName"},
			Unique:     false,
			DropDups:   false,
			Background: true,
			Sparse:     true,
		}}
	if c != nil {
		var err error
		for _, index := range indices {

			err = c.EnsureIndex(index)
			if err != nil {
				return err
			}

		}

		return nil
	} else {
		fmt.Println("Error , nil Collection")
		return fmt.Errorf("Error , nil collection")
	}

}
