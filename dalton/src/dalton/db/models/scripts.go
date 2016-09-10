package models

import (
	"labix.org/v2/mgo/bson"
	"time"
	"strings"
	"strconv"
)

const (

	CVSS_BASE = "cvss_base"
	CVSS_BASE_VECTOR ="cvss_base_vector"
)

/*
   This file contains the model that represents The knowledge base that Dalton has
   Simply , The knowledge base refers to all the pool of nasl scripts That dalton has

 */

type Script struct {
	Id bson.ObjectId `bson:"id" json:"id"`
	ScriptName string `bson:"name" json:"name"`
	ScriptVersion string `bson:"version" json:"version"`
	ScriptTimeout int `bson:"timeout,omitempty" json:"timeout,omitempty"`
	ScriptDescription string `bson:"description,omitempty" json:"description,omitempty"`
	ScriptCopyRight string `bson:"copyright,omitempty" json:"copyright,omitempty"`
	ScriptSummary string `bson:"summary,omitempty" json:"summary,omitempty"`
	ScriptCategory int `bson:"category" json:"category"`
	ScriptFamily string `bson:"family,omitempty" json:"family,omitempty"`
	ScriptId string `bson:"sid,omitempty" json:"sid,omitempty"`
	ScriptOid string `bson:"oid,omitempty" json:"oid,omitempty"`
	ScriptCveIds []string `bson:"cveIds,omitempty" json:"cveIds,omitempty"`
	ScriptBugTraqIds []string `bson:"bugTraqIds,omitempty" json:"bugTraqIds,omitempty"`
	ScriptDependencies []string `bson:"deps,omitempty" json:"deps,omitempty"`
	ScriptRequireKeys []string `bson:"rKeys,omitempty" json:"rKeys,omitempty"`
	ScriptMandatoryKeys []string `bson:"mKeys,omitempty" json:"mKeys,omitempty"`
	ScriptRequirePorts []string `bson:"rPorts,omitempty" json:"rPorts,omitempty"`
	ScriptRequireUDP []string `bson:"rUDPs,omitempty" json:"rUDPs,omitempty"`
	ScriptExcludeKeys []string `bson:"eKeys,omitempty" json:"eKeys,omitempty"`
	ScriptAddPreferences []DaltonDictContainer `bson:"prefs,omitempty" json:"prefs,omitempty"`
	ScriptXRefs []DaltonNameValuePair `bson:"xRefs,omitempty" json:"xRefs,omitempty"`
	ScriptTags []DaltonNameValuePair `bson:"tags,omitempty" json:"tags,omitempty"`
	InsertedTime time.Time `bson:"insertedTime,omitempty" json:"insertedTime,omitempty"`
	ModifiedTime time.Time `bson:"modifiedTime,omitempty" json:"modifiedTime,omitempty"`
	ScriptFileName string `bson:"fileName,omitempty" json:"fileName,omitempty"`
}


func (script Script) GetCVSS() float64{

	for _ , tag := range script.ScriptTags {

		tagName := strings.ToLower(tag.Name)
		if strings.EqualFold(tagName,CVSS_BASE) {

			cvss , err := strconv.ParseFloat(tag.Value,64)
			if err != nil {
				continue
			}

			return cvss

		}
	}

	return -1
}

func (script Script) GetCVSS_Vector() string {

	var vector string = ""

	for _ , tag := range script.ScriptTags{

		tagName := strings.ToLower(tag.Name)
		if strings.EqualFold(tagName,CVSS_BASE_VECTOR){
			vector = tag.Value
			break
		}
	}
	return vector
}

func (script Script) GetUpdateQuery() bson.M {

	return bson.M{"$set":bson.M{
		"name":script.ScriptName,
		"version":script.ScriptVersion,
		"timeout":script.ScriptTimeout,
		"description":script.ScriptDescription,
		"copyright":script.ScriptCopyRight,
		"summary":script.ScriptSummary,
		"category":script.ScriptCategory,
		"family":script.ScriptFamily,
		"sid":script.ScriptId,
		"oid":script.ScriptOid,
		"cveIds":script.ScriptCveIds,
		"bugTraqIds":script.ScriptBugTraqIds,
		"deps":script.ScriptDependencies,
		"rKeys":script.ScriptRequireKeys,
		"mKeys":script.ScriptMandatoryKeys,
		"rPorts":script.ScriptRequirePorts,
		"rUDPs":script.ScriptRequireUDP,
		"eKeys":script.ScriptExcludeKeys,
		"prefs":script.ScriptAddPreferences,
		"xRefs":script.ScriptXRefs,
		"tags":script.ScriptTags,
		"insertedTime":script.InsertedTime,
		"modifiedTime":time.Now(),
		"fileName":script.ScriptFileName,
	}}
}

type DaltonNameValuePair struct {

	Name string `bson:"name,omitempty" json:"name,omitempty"`
	Value string `bson:"value,omitempty" json:"value,omitempty"`
}

type DaltonDictContainer struct {

	Name string `bson:"name,omitempty" json:"name,omitempty"`
	Type string `bson:"type,omitempty" json:"type,omitempty"`
	Value string `bson:"value,omitempty" json:"value,omitempty"`
}



/*

 */