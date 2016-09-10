package models

import (
	"time"
	"labix.org/v2/mgo/bson"


)
/*
    This structure defines a vulnerability finding for a given scanDB
 */
type Vulnerability struct {
	Id bson.ObjectId `bson:"id,omitempty" json:"id,omitempty"`
	DiscoveredTime time.Time `bson:"discoveredTime,omitempty" json:"discoveredTime,omitempty"`
	ScanId bson.ObjectId	`bson:"scanId" json:"scanId"`
	ScriptId bson.ObjectId `bson:"scriptId,omitempty" json:"scriptId,omitempty"`
	Success bool `bson:"success" json:"success"`
	Messages []string `bson:"messages,omitempty" json:"messages,omitempty"`
	CVSS float64 `bson:"score,omitempty" json:"score,omitempty"`
	CVSS_Vector string `bson:"cvss_vector,omitempty" json:"cvss_vector,omitempty"`
}


func (vuln Vulnerability) GetUpdateQuery() *bson.M {

	return &bson.M{"$set":bson.M{
		"discoveredTime":vuln.DiscoveredTime,
		"scanId":vuln.ScanId,
		"scriptId":vuln.ScriptId,
		"success":vuln.Success,
		"messages":vuln.Messages,
		"score":vuln.CVSS,
		"cvss_vector":vuln.CVSS_Vector,
	}}
}