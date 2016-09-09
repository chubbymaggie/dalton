package models

import (
	"time"
	"labix.org/v2/mgo/bson"
)

const (
	DISCOVERED_BY_SCANNERD = "scannerd"
	DISCOVERED_BY_ANALYZERD = "analyzerd"
)

type Vulnerability struct {

	DiscoveredTime time.Time `bson:"discoveredTime,omitempty" json:"discoveredTime,omitempty"`
	ScanId bson.ObjectId	`bson:"scanId" json:"scanId"`
	ScriptId bson.ObjectId `bson:"scriptId,omitempty" json:"scriptId,omitempty"`
	ScriptName string `bson:"scriptName" json:"scriptName"`
	Success bool `bson:"success" json:"success"`
	Messages []string `bson:"messages,omitempty" json:"messages,omitempty"`
	DiscoveredBy string `bson:"discoveredBy,omitempty" json:"discoveredBy,omitempty"`

}
