package db

import (
	"dalton/db/models"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"dalton/utils"
)
const (

	ASSETS_COLLECTION_NAME = "Assets"
)
/*
   This function will update the assets with specific update Query Selector based on the passed UserId
*/
func UpdateAssetWith(asset *models.AssetDB , updateQuery *bson.M) error {
	collection , session := GetCollection(ASSETS_COLLECTION_NAME)
	defer session.Close()
	id := asset.Id
	return collection.UpdateId(id,updateQuery)
}
/*
   this function blindly update All the asset properties
 */
func UpdateAsset(asset *models.AssetDB) error {
	collection , session := GetCollection(ASSETS_COLLECTION_NAME)
	defer session.Close()
	id := asset.Id
	update := bson.M{"$set":bson.M{"host":asset.Host,"ipAddrs":asset.IPAddrs,"createdAt":asset.CreatedAt,
	"reachable":asset.Reachable,"status":asset.Status,"osInfo":asset.OSInfo,"upTime":asset.UpTime,"entryId":asset.EntryId},"os":asset.OS,
	 "ports":asset.Ports}
	return collection.UpdateId(id,update)
}
/*
  This function will delete an existing asset based on the objectId
 */
func DeleteAsset(asset *models.AssetDB) error {

	collection , session := GetCollection(ASSETS_COLLECTION_NAME)
	defer session.Close()
	return collection.Remove(bson.M{"_id":asset.Id})
}
/*
    This function will add/insert a completely new Asset
 */
func InsertAsset(asset *models.AssetDB) error {

	collection,session := GetCollection(ASSETS_COLLECTION_NAME)
	defer session.Close()
	//Create a new ObjectId for the asset
	if asset.Id == "" {
		asset.Id = utils.NewObjectId()
	}
	return collection.Insert(asset)
}
/*
   This function will search assets based on a specific Query selector with skip and limit variables
   to control the amount of results returned.
 */
func SearchAssets(q interface{},skip,limit int) (searchResults []models.AssetDB , err error) {

	searchResults = []models.AssetDB{}
	query := func (c *mgo.Collection) error {
		fn := c.Find(q).Skip(skip).Limit(limit).All(&searchResults)
		if limit <0 {
			fn = c.Find(q).Skip(skip).All(&searchResults)
		}
		return fn
	}
	search := func() error {

		return WithCollection(ASSETS_COLLECTION_NAME,query)
	}
	err = search()

	if err != nil {
		return
	}
	return searchResults , err
}
/*
   This function will ensure indices against mongodb server
 */
func EnsureAssetsIndices (c *mgo.Collection) error {

	index := mgo.Index{

		Key:[]string{"host","ip","entryId"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}

	return c.EnsureIndex(index)
}