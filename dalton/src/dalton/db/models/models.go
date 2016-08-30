package models

import (
	"time"
	"labix.org/v2/mgo/bson"
	"fmt"
	"github.com/lair-framework/go-nmap"
)

type UserDB struct {
	Id bson.ObjectId `bson:"_id,omitempty" json:"_id,omitempty"`
	FullName string  `bson:"fullName" json:"fullName"`
	Title string `bson:"title,omitempty" json:"title,omitempty"`
	Role string `bson:"role,omitempty" json:"role,omitempty"`
	UserName string `bson:"userName" json:"userName"`
	Password string `bson:"password" json:"password"`
	Email string `bson:"email" json:"email"`
	JoinedDate time.Time `bson:"joinedDate,omitempty" json:"joinedDate,omitempty"`
}


func (user UserDB) GoString() string {

	return fmt.Sprintf("Id: %v , FullName : %s , Title : %s , Role : %s , UserName : %s , Password : %s , Email : %s , JoinedDate:%v",
		user.Id,user.FullName,user.Title,user.Role,user.UserName,user.Password,user.Email,user.JoinedDate)
}

type ScanDB struct {

	Id bson.ObjectId `bson:"_id,omitempty" json:"_id,omitempty"`
	Name string `bson:"name" json:"name"`
	CreatedAt time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UserId bson.ObjectId `bson:"userId" json:"userId"`
	Status int `bson:"status" json:"status"`
	HostId bson.ObjectId `bson:"hostId" json:"hostId"`
	Severity int `bson:"severity,omitempty" json:"severity,omitempty"`
}


func (scan ScanDB) GoString() string {

	return fmt.Sprintf("Id:%v , Name : %s , Created At : %v , UserId : %v , Status:%d , HostId: %v , Severity: %d",
	scan.Id,scan.Name,scan.CreatedAt,scan.UserId,scan.Status,scan.HostId,scan.Severity)
}

type AssetDB struct {

	Id bson.ObjectId `bson:"_id,omitempty" json:"_id,omitempty"`
	Host string `bson:"host" json:"host"`
	IPAddrs []string `bson:"ipAddrs,omitempty" json:"ipAddrs,omitempty"`
	CreatedAt time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	Reachable bool `bson:"reachable,omitempty" json:"reachable,omitempty"`
	Status bool `bson:"status,omitempty" json:"status,omitempty"`
	OS nmap.Os `bson:"os,omitempty" json:"os,omitempty"`
	OSInfo string `bson:"osInfo,omitempty" json:"osInfo,omitempty"`
	UpTime nmap.Uptime `bson:"upTime,omitempty" json:"upTime,omitempty"`
	EntryId bson.ObjectId `bson:"entryId" json:"entryId"`
	Ports []nmap.Port 	`bson:"ports,omitempty" json:"ports,omitempty"`
}


func (asset AssetDB) GoString() string {

	return fmt.Sprintf("Id :%v , Host : %s , IPAddresses : %v , CreatedAt : %v , Reachable: %v , Status: %v , OsInfo : %s , UpTime: %v , OS: %v ," +
		" Ports : %v",
	asset.Id,asset.Host,asset.IPAddrs,asset.CreatedAt,asset.Reachable,asset.Status,asset.OSInfo,asset.UpTime,asset.OS,asset.Ports)
}

/*
   ScanEntry defines if there is any ongoing test available or not , and which tests have been previously performed.
 */
type ScanEntry struct {

	//The scan id to be used
	ScanId bson.ObjectId `bson:"_id,omitempty" json:"id,omitempty"`
	//the scan start time
	StartTime time.Time  `bson:"startTime" json:"startTime,omitempty"`
	//the scan end time
	EndTime time.Time `bson:"endTime,omitempty" json:"endTime,omitempty"`
	//the scan initiated by
	InitiatedBy string `bson:"initiatedBy" json:"initiatedBy"`
	//The scan status , either the scan is "Running:false" or "Completed:true"
	Status bool `bson:"status" json:"status"`
	StatusMessage string `bson:"statusMessage,omitempty" json:"statusMessage,omitempty"`
	CommandArgs []string `bson:"commandArgs" json:"commandArgs"`
	Progress float64 `bson:"progress" json:"progress"`
}

func (entry ScanEntry) GoString() string{
	return fmt.Sprintf("_id:%v , StartTime: %v , EndTime : %v , InitiatedBy: %s , Status : %v " +
		" , Command : %v , Progress : %v , Status Message : %s",entry.ScanId,entry.StartTime,entry.EndTime,entry.InitiatedBy,entry.Status,entry.CommandArgs,entry.Progress,
	entry.StatusMessage)
}
