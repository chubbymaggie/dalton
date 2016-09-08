package db

import (
	"labix.org/v2/mgo"
	"fmt"
)

const (

	SCRIPTS_COLLECTION_NAME = "Scripts"
)


func EnsureScriptsIndices(c *mgo.Collection) error{

	indices := []mgo.Index{{
		Key: []string{"sid","oid"},
		Unique:     true,
		DropDups:   false,
		Background: true,
		Sparse:     true,
	},
		{
			Key: []string{"cveIds","name"},
		Unique:     false,
		DropDups:   false,
		Background: true,
		Sparse:     true,
		}}
	if c != nil {
		var err error
			for _ , index := range indices {

				err = c.EnsureIndex(index)
				if err != nil {
					return err
				}

			}

		return nil
	}else{
		fmt.Println("Error , nil Collection")
		return fmt.Errorf("Error , nil collection")
	}

}
