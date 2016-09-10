package db

import (
	"labix.org/v2/mgo"
	"dalton/db/models"
	"fmt"
	"dalton/utils"
	"labix.org/v2/mgo/bson"
)

const (

	VULNS_COLLECTION_NAME = "vulns"
)


func UpdateVulnWith(vuln *models.Vulnerability , updateQuery *bson.M) error{
	collection , session := GetCollection(VULNS_COLLECTION_NAME)
	defer session.Close()
	id := vuln.Id
	return collection.UpdateId(id,updateQuery)
}
func UpdateVuln(vuln *models.Vulnerability) error{

	collection , session := GetCollection(VULNS_COLLECTION_NAME)
	defer session.Close()
	id := vuln.Id
	return collection.UpdateId(id,vuln.GetUpdateQuery())
}
func DeleteVuln(vuln *models.Vulnerability) error {

	collection , session := GetCollection(VULNS_COLLECTION_NAME)
	defer session.Close()
	return collection.Remove(bson.M{"id":vuln.Id})
}
func InsertVuln(vuln *models.Vulnerability,collection *mgo.Collection) error{

	if vuln == nil {
		fmt.Println("nilled Vulnerability")
		return fmt.Errorf("nil Vulnerability")
	}
	if vuln.Id == "" {
		vuln.Id = utils.NewObjectId()
	}
	err := collection.Insert(vuln)
	return err
}
func SearchVulns(q interface{},skip,limit int) (searchResults []models.Vulnerability,err error){

	searchResults = []models.Vulnerability{}
	query := func(c *mgo.Collection) error{
		fn := c.Find(q).Skip(skip).Limit(limit).All(&searchResults)
		if limit < 0 {
			fn = c.Find(q).Skip(skip).All(&searchResults)
		}
		return fn
	}

	search := func() error{
		return WithCollection(VULNS_COLLECTION_NAME,query)
	}

	err = search()
	if err != nil {
		return
	}
	return
}
func EnsureVulnsIndices(C *mgo.Collection) error{

	index := mgo.Index{

		Key: []string{"scanId","scriptId"},
		Unique:     false,
		DropDups:   false,
		Background: true,
		Sparse:     true,
	}
	return C.EnsureIndex(index)
}
