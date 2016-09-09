package scannerd

import (
	"dalton/db/models"
	"dalton/log"
	"fmt"
	"dalton/db"
	"dalton/security"
	"github.com/lair-framework/go-nmap"
	"time"
	"dalton/config"
)
func StartScanning() {
	//Get the temporary directory
	fmt.Println("Starting the Scanning Daemon.")
	tempDir , err := config.ReadConfigKey("general","tempDir")
	if err != nil {
		log.Log(SCANNER_NAME , fmt.Sprintf("We received the following error during accessing the temporary directory configuration settings : %v",err))
		return
	}
	for {
		var NewScan models.Reconn
		NewScan = <- NewScans
		log.Log(SCANNER_NAME,fmt.Sprintf("Starting the current scan , %v",NewScan))
		go beginScan(&NewScan,tempDir)
	}
}
func beginScan(requestedScan *models.Reconn, tempDir string) {
	//Intercept exceptions and log them
	defer func (){

		//intercept exceptions and log them
		data := recover()
		log.Log(SCANNER_NAME , fmt.Sprintf("Received an exception : %v ," +
			"  During Performing the following scan : %s",data , requestedScan.GoString()))
		//Log the error in the requested scan so that , it will be saved into the database.
		requestedScan.StatusMessage = fmt.Sprintf("%v",data)
		//update the current entry scan into the database
		db.UpdateEntry(requestedScan)
		return
	}()

	//deferred : remove it from the in-memory map
	defer delete(AvailableScans,requestedScan.ScanId.Hex())
	//Access the configuration details from the config file
	//Let us configure the current scan details
	scanSettings := &security.ScanSettings{

		Args:requestedScan.CommandArgs,
		TempDir:tempDir,
	}
	//Now initiate the current scan
	foundHosts , err := security.Scan(scanSettings)
	if err != nil {
		log.Log(SCANNER_NAME,fmt.Sprintf("Received an Error : %v ,  during processing the current scan: %s",err,requestedScan.GoString()))
		return
	}
	//Now begin iterating over all found hosts and save them into the database
	for _ , host := range foundHosts {
		convertedAsset , err := convertHostToAsset(requestedScan,&host)
		if err != nil {
			log.Log(SCANNER_NAME , fmt.Sprintf("Received an error during converting an nmap host to Dalton Asset : %v",err))
			continue
		}
		//Now save it into the database
		err = db.InsertAsset(convertedAsset)
		if err != nil {
			log.Log(SCANNER_NAME,fmt.Sprintf("Received an error during inserting the current asset into the database , %v",err))
			continue
		}
	}
	//Update the current scanEntry into the database
	requestedScan.Status = true
	requestedScan.EndTime = time.Now()
	requestedScan.Progress = 100
	requestedScan.StatusMessage = fmt.Sprintf("Found : (%d) Hosts , (%d) Up",len(foundHosts),len(foundHosts))
	//now update the requestedScan into the database and delete it from the map
	err = db.UpdateEntry(requestedScan)
	if err != nil {
		log.Log(SCANNER_NAME,fmt.Sprintf("Received an error during updating the current Scan : %v , With Error Details : %v",requestedScan,err))
	}
	//Just notify that the scan is already finished
	log.Log(SCANNER_NAME,fmt.Sprintf("Finished Scanning :%v , with Hosts : %d",requestedScan,len(foundHosts)))

}

func convertHostToAsset(scan *models.Reconn, host *nmap.Host) (*models.AssetDB , error) {

	addresses := make([]string,0)

	for _ , addr := range host.Addresses{
		addresses = append(addresses,addr.Addr)
	}
	var hostName string
	if len(host.Hostnames) > 0 {
		hostName = host.Hostnames[0].Name
	}else
	{
		if len(host.Addresses) > 0 {
			hostName = host.Addresses[0].Addr
		}
	}
	newAsset := &models.AssetDB{
		OS:host.Os,
		IPAddrs:addresses,
		CreatedAt:time.Now(),
		EntryId:scan.ScanId,
		Host:hostName,
		OSInfo:fmt.Sprintf("%v",host.Os),
		Reachable:true,
		Status:true,
		UpTime:host.Uptime,
		Ports:host.Ports,
	}

	return newAsset , nil
}



