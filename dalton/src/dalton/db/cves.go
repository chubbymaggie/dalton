package db

import (


	"dalton/db/models"
	"labix.org/v2/mgo/bson"
	"dalton/utils"
	"labix.org/v2/mgo"
)

const (

	CVE_COLLECTION_NAME = "cves"
)
func UpdateCVEWith(Cve *models.CVE , updateQuery *bson.M) error {

	session , err := Connect()
	if err != nil {
		return err
	}
	defer session.Close()
	collection := GetCollection(CVE_COLLECTION_NAME)
	id := Cve.Id
	return collection.UpdateId(id,updateQuery)
}
func UpdateCVE(cve *models.CVE) error {
	session , err := Connect()
	if err != nil {
		return err
	}
	defer session.Close()
	collection := GetCollection(CVE_COLLECTION_NAME)
	id := cve.Id
	update := bson.M{"$set":bson.M{"cve_id":cve.CveId,"products":cve.Product,"discovered_datetime":cve.DiscoveredDate,"disclosure_datetime":cve.DisclosureDate,
	"exploit_publish_datetime":cve.ExploitPubDate,"last_modified_datetime":cve.LastModifiedDate,"cvss":cve.CVSS,
	"security_protection":cve.SecurityProtection,"cwe_id":cve.CweId,"references":cve.References,"summary":cve.Summary}}
	return collection.UpdateId(id,update)
}
func DeleteCVE(cve *models.CVE) error {
	session,err := Connect()
	if err != nil {
		return err
	}
	defer session.Close()
	collection := GetCollection(CVE_COLLECTION_NAME)
	return collection.Remove(bson.M{"_id":cve.Id})
}
func InsertCVE(cve *models.CVE) error {
	session , err := Connect()
	if err != nil {
		return err
	}
	defer session.Close()
	collection := GetCollection(CVE_COLLECTION_NAME)
	if cve.Id == "" {
		cve.Id = utils.NewObjectId()
	}

	return collection.Insert(cve)
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
	return searchResults,err
}
func EnsureCVEsIndices (c *mgo.Collection) error {

	index := mgo.Index{
		Key: []string{"cve_id"},
		Unique:     true,
		DropDups:   false,
		Background: true,
		Sparse:     true,
	}
	return c.EnsureIndex(index)
}