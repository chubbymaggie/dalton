package db

import (


	"dalton/db/models"
	"labix.org/v2/mgo/bson"
	"dalton/utils"
	"labix.org/v2/mgo"
	"fmt"
)

const (

	CVE_COLLECTION_NAME = "cves"
)
func UpdateCVEWith(Cve *models.CVE , updateQuery *bson.M) error {
	collection , session := GetCollection(CVE_COLLECTION_NAME)
	defer session.Close()
	id := Cve.Id
	return collection.UpdateId(id,updateQuery)
}
func UpdateCVE(cve *models.CVE) error {
	collection,session := GetCollection(CVE_COLLECTION_NAME)
	defer session.Close()
	id := cve.Id
	update := bson.M{"$set":bson.M{"cve_id":cve.CveId,"products":cve.Product,"discovered_datetime":cve.DiscoveredDate,"disclosure_datetime":cve.DisclosureDate,
	"exploit_publish_datetime":cve.ExploitPubDate,"last_modified_datetime":cve.LastModifiedDate,"cvss":cve.CVSS,
	"security_protection":cve.SecurityProtection,"cwe_id":cve.CweId,"references":cve.References,"summary":cve.Summary}}
	return collection.UpdateId(id,update)
}
func DeleteCVE(cve *models.CVE) error {

	collection , session := GetCollection(CVE_COLLECTION_NAME)
	defer session.Close()
	return collection.Remove(bson.M{"_id":cve.Id})
}
func InsertCVE(cve *models.CVE,collection *mgo.Collection) error {
	if cve == nil {
		fmt.Println("nil CVE")
		return fmt.Errorf("nil CVE")
	}
	if cve.Id == "" {
		cve.Id = utils.NewObjectId()
	}
	err := collection.Insert(cve)
	return err
}
func SearchCVEs(q interface{},skip,limit int) (searchResults []models.CVE , err error) {
	searchResults = []models.CVE{}
	query := func(c *mgo.Collection) error {
		fn := c.Find(q).Skip(skip).Limit(limit).All(&searchResults)
		if limit < 0 {
			fn = c.Find(q).Skip(skip).All(&searchResults)
		}
		return fn
	}
	search := func () error {
		return WithCollection(CVE_COLLECTION_NAME,query)
	}
	err = search()
	if err != nil {
		return
	}
	return
}
func EnsureCVEsIndices (c *mgo.Collection) error {

	index := mgo.Index{
		Key: []string{"cve_id"},
		Unique:     false,
		DropDups:   false,
		Background: true,
		Sparse:     true,
	}
	if c != nil {
			return c.EnsureIndex(index)
	}else{
		fmt.Println("Error , nil Collection")
		return fmt.Errorf("Error , nil collection")
	}
}