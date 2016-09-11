package db

import (
	"dalton/db/models"
	"dalton/utils"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

const (
	Users_Collection_Name = "Users"
)

/*
   This function will search Users based on a query selector , skip and limit variables to control the search results.
*/
func SearchUsers(q interface{}, skip, limit int) (searchResults []models.UserDB, err error) {

	searchResults = []models.UserDB{}

	query := func(c *mgo.Collection) error {
		fn := c.Find(q).Skip(skip).Limit(limit).All(&searchResults)

		if limit < 0 {
			fn = c.Find(q).Skip(skip).All(&searchResults)
		}
		return fn
	}

	search := func() error {

		return WithCollection(Users_Collection_Name, query)
	}

	err = search()

	if err != nil {
		return
	}

	return

}

/*
   This function will insert a completely new user into the database
*/
func InsertUser(user *models.UserDB) error {
	//now insert into the database collection users the new user
	collection, session := GetCollection(Users_Collection_Name)
	defer session.Close()
	//initialize the user with a new ObjectId
	if user.Id == "" {
		user.Id = utils.NewObjectId()
	}
	return collection.Insert(user)
}

/*
   This function will update the user based on an update query that is passed externally from the calling function
*/
func UpdateUserWith(user *models.UserDB, update *bson.M) error {

	collection, session := GetCollection(Users_Collection_Name)
	defer session.Close()
	id := user.Id
	return collection.UpdateId(id, update)
}

/*
  this function will update all given user details into the database based on an existing objectId
*/
func UpdateUser(user *models.UserDB) error {

	collection, session := GetCollection(Users_Collection_Name)
	defer session.Close()
	id := user.Id
	update := bson.M{"$set": bson.M{"email": user.Email, "fullName": user.FullName, "joinedDate": user.JoinedDate,
		"password": user.Password, "role": user.Role, "title": user.Title, "userName": user.UserName}}
	return collection.UpdateId(id, update)

}

/*
  This function will completely delete the given user from the database.
*/
func DeleteUser(user *models.UserDB) error {
	collection, session := GetCollection(Users_Collection_Name)
	defer session.Close()
	return collection.Remove(bson.M{"_id": user.Id})
}

/*
  This function will ensure indices for Users into the mongodb
*/
func EnsureUsersIndices(c *mgo.Collection) error {

	index := mgo.Index{
		Key:        []string{"userName", "email"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	return c.EnsureIndex(index)
}
