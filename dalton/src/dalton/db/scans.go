package db

import (
	"dalton/db/models"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"dalton/utils"
)

const (

	SCANS_COLLECTION_NAME = "Scans"
)

/*
   This function will update a scan based on an external query that is passed to it
 */
func UpdateScanWith(scan *models.ScanDB , query *bson.M) error {

	collection , session := GetCollection(SCANS_COLLECTION_NAME)
	defer session.Close()
	id := scan.Id
	return collection.UpdateId(id,query)
}

/*
    This function will update all properties of a scan object into the database based on an existing ObjectId.
 */
func UpdateScan(scan *models.ScanDB) error {

	collection , session := GetCollection(SCANS_COLLECTION_NAME)
	defer session.Close()
	id := scan.Id
	update := bson.M{"$set":bson.M{"name":scan.Name,"createdAt":scan.CreatedAt,"userId":scan.UserId,
	"status":scan.Status,"hostId":scan.HostId,"severity":scan.Severity}}
	return collection.UpdateId(id,update)
}


/*
   This function will delete a scan permanently from mongodb
 */
func DeleteScan(scan *models.ScanDB) error {

	collection , session := GetCollection(SCANS_COLLECTION_NAME)
	defer session.Close()
	return collection.Remove(bson.M{"_id":scan.Id})
}
/*
   This function will insert a new Scan into mongodb
 */
func InsertScan(scan *models.ScanDB) error {
	collection , session := GetCollection(SCANS_COLLECTION_NAME)
	defer session.Close()
	//Create a new ObjectId for the asset
	if scan.Id == "" {
		scan.Id = utils.NewObjectId()
	}
	return collection.Insert(scan)
}

func SearchScans(q interface{},skip,limit int) (searchResults []models.ScanDB , err error) {

	searchResults = []models.ScanDB{}
	query := func (c *mgo.Collection) error {
		fn := c.Find(q).Skip(skip).Limit(limit).All(&searchResults)

		if limit <0 {
			fn = c.Find(q).Skip(skip).All(&searchResults)
		}
		return fn
	}
	search := func() error {

		return WithCollection(SCANS_COLLECTION_NAME,query)
	}
	err = search()

	if err != nil {
		return
	}
	return
}


func EnsureScansIndices (c *mgo.Collection) error {

	index := mgo.Index{

		Key:[]string{"name","userId","status","hostId","severity"},
		Unique:     false,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	return c.EnsureIndex(index)
}