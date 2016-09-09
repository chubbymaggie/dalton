package models

import (
	"labix.org/v2/mgo/bson"
	"time"
	"fmt"

)

type ScanDB struct {

	Id        bson.ObjectId `bson:"_id,omitempty" json:"_id,omitempty"`
	Name      string `bson:"name" json:"name"`
	CreatedAt time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UserId    bson.ObjectId `bson:"userId" json:"userId"`
	Status    int `bson:"status" json:"status"`
	AssetId   bson.ObjectId `bson:"assetId" json:"assetId"`
	Severity  int `bson:"severity,omitempty" json:"severity,omitempty"`
}


func (scan ScanDB) GoString() string {
	return fmt.Sprintf("Id:%v , Name : %s , Created At : %v , UserId : %v , Status:%d , HostId: %v , Severity: %d",
	scan.Id,scan.Name,scan.CreatedAt,scan.UserId,scan.Status,scan.AssetId,scan.Severity)
}

