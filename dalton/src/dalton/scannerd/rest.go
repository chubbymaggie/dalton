package scannerd

import (
	"dalton/auth"
	"dalton/db"
	"dalton/db/models"
	"dalton/log"
	"dalton/rest"
	"dalton/utils"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io/ioutil"
	"labix.org/v2/mgo/bson"
	"net/http"
	"strings"
	"time"
)

const (
	SCANNER_NAME            = "scannerd"
	ERROR_CODE              = 500
	SUCCESS_CODE            = 200
	SCANNERD_CHANNEL_BUFFER = 200
)

var (
	//Define the channel that will obtain the new tests from the web interface
	NewScans       chan models.Reconn
	AvailableScans map[string]models.Reconn
)

func init() {
	//Initialize the scanEntry channel to be buffered Scans channel
	NewScans = make(chan models.Reconn, SCANNERD_CHANNEL_BUFFER)
	//initialize an Empty Map
	AvailableScans = make(map[string]models.Reconn)
	//initialize the log
	log.InitLog(SCANNER_NAME)
	//Check the database for stored unfinished scans
	initInteralMap()
}

/*
   This function will be called only once during the init function of the scannerd package
   Its function is to check the database for any stored unfinished scans
*/
func initInteralMap() error {

	//Get all unfinished scans from the database
	query := bson.M{"status": false}
	searchResult, err := db.SearchEntries(query, 0, -1)
	if err != nil {
		log.Log(SCANNER_NAME, fmt.Sprintf(" We received an error during Getting all unfinished Scans from the database : %v", err))
		return err
	}
	//if there are unfinished scans in the database , loop over them and insert them one by one into the map
	//and add them into the channel
	if len(searchResult) > 0 {
		for _, currentScan := range searchResult {
			//Append the current unfinished scan into the database
			//set progress to zero
			currentScan.Progress = 0
			appendNewScan(&currentScan, false)
			addScanToChannel(&currentScan)

		}
	}
	return nil
}
func appendNewScan(scanEntry *models.Reconn, dbInsert bool) error {
	//add a new Scan entry
	AvailableScans[scanEntry.ScanId.Hex()] = *scanEntry
	//We should also add the scan into the database
	scanEntry.Status = false //Means the scan is already running
	scanEntry.StartTime = time.Now()
	if dbInsert {
		return db.InsertEntry(scanEntry)
	} else {
		return nil
	}
}

///////////////////////////////////////////////////////////////////////////////Web Related Functions////////////////////////////////////////////////////////////////////////////
func NewMux() *mux.Router {
	//define the new Web Multiplexer
	mux := mux.NewRouter()
	//Handle the insert Scan Command
	//Handle both PUT and POST HTTP Commands for sending new Scan Entries
	mux.HandleFunc("/scan/new", insertNewScan).Methods("POST", "PUT")
	mux.HandleFunc("/scan/search/{scanId}", getExistingScan).Methods("GET")
	mux.HandleFunc("/scan/all", getAllExistingScans).Methods("GET")
	mux.HandleFunc("/scan/active/all", getAllActiveScans).Methods("GET")
	//finally return the web multiplexer
	return mux
}

///////////////////////////////////////////////////////////////////Rest Security for Scannerd//////////////////////////////////////////////////////////////////////////////////////

/*
   This function will access the http request object for the current restful request and it will access "Dalton-Signature" http param
   and verify the contents in case-insensitive way
*/
func verifyAuthenticity(r *http.Request) error {
	//access the "Dalton-Signature
	daltonSignature := r.Header.Get(strings.ToLower(auth.DALTON_SIGNATURE_VAR))
	if daltonSignature == "" || len(daltonSignature) <= 0 {
		log.Log(SCANNER_NAME, fmt.Sprintf("UnAuthenticated Request was sent to Scannerd"))
		return fmt.Errorf("UnAuthenticated Request sent to Scannerd")
	}
	//Access the IP address of the Initiator from the request
	remoteAddr := r.RemoteAddr
	if strings.Contains(remoteAddr, ":") {
		remoteAddr = strings.Split(remoteAddr, ":")[0]
	}

	if remoteAddr == "" || len(remoteAddr) <= 0 {
		log.Log(SCANNER_NAME, fmt.Sprintf("Unable to access the remote address of the initiator of the current request."))
		return fmt.Errorf("Unable to access the remote address of the initiator of the current request")
	}
	//Now get verify the contents
	result := auth.VerifySignature(utils.DecodeString(daltonSignature), []byte(remoteAddr))

	if result {
		return nil
	} else {
		return fmt.Errorf("Invalid Signature sent , UnAuthorized Request , Scannerd will ignore the request.")
	}
}

func notifyClient(w http.ResponseWriter, message string, statusCode int) {
	restError := &rest.RestError{Message: message, SentTime: time.Now(), ErrorCode: statusCode}
	fmt.Fprintf(w, restError.ToJson())
}

/*
   This function insert a new scan into the database
*/
func insertNewScan(w http.ResponseWriter, r *http.Request) {
	err := verifyAuthenticity(r)
	if err != nil {
		notifyClient(w, err.Error(), ERROR_CODE)
		return
	}
	//Get the payload and convert it into object
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Log(SCANNER_NAME, fmt.Sprintf(" we Received an Error : %v", err))
		//returning to the rest caller
		restError := &rest.RestError{Message: fmt.Sprintf("UnRecognized Request Format , Received this Error : %v", err), SentTime: time.Now(), ErrorCode: ERROR_CODE}
		fmt.Fprintf(w, restError.ToJson())
	}
	//now unmarshal the received data back into json object
	var newScan models.Reconn
	err = json.Unmarshal(payload, &newScan)
	if err != nil {
		log.Log(SCANNER_NAME, fmt.Sprintf(" We Received an Error : %v", err))
		restError := &rest.RestError{Message: fmt.Sprintf("UnRecognized Payload sent during the request , Received this Error : %v", err), SentTime: time.Now(), ErrorCode: ERROR_CODE}
		fmt.Fprintf(w, restError.ToJson())
		return
	}
	//if everything went fine , just append that newScan into the newScans channel
	//add a new objectId into the new Scan
	//add the new scan into Scannerd for processing and insert it into the database
	err = appendNewScan(&newScan, true)
	//now add it to the channel at the end
	//add the new scan into the NewScans channel
	defer addScanToChannel(&newScan)
	if err != nil {

		log.Log(SCANNER_NAME, fmt.Sprintf(" We Received anError : %v", err))
		restError := &rest.RestError{Message: fmt.Sprintf("We received a problem during saving the new scan from rest interface "+
			" , Received this Error : %v", err), SentTime: time.Now(), ErrorCode: ERROR_CODE}
		fmt.Fprintf(w, restError.ToJson())
	} else {
		//Generate a success message
		success := &rest.RestSuccess{Message: "Successfully Received The New Scan, It is under Processing",
			ScanID: newScan.ScanId.Hex(), StatusCode: SUCCESS_CODE}
		log.Log(SCANNER_NAME, "Successfully Received the following scan Entry for processing : %v", newScan.ScanId.Hex())
		//send the results back to the restful API
		fmt.Fprintf(w, success.ToJson())
	}
}

/*
   This function will grab the ScanEntry based on The Scan Id that will be passed by the Rest calller
*/
func getExistingScan(w http.ResponseWriter, r *http.Request) {
	err := verifyAuthenticity(r)
	if err != nil {
		notifyClient(w, err.Error(), ERROR_CODE)
		return
	}
	urlParams := mux.Vars(r)
	scanId := urlParams["scanId"]
	if len(scanId) <= 0 {
		log.Log(SCANNER_NAME, fmt.Sprintf("Error in function (getExistingScan) Received an Empty ScanId"))
		errorReturned := &rest.RestError{ErrorCode: ERROR_CODE,
			Message:  fmt.Sprintf("Received an Empty ScanId ,Please Send a valid scanId."),
			SentTime: time.Now()}
		fmt.Fprintf(w, errorReturned.ToJson())
		return
	}
	//get the scan entry by the scanId
	scan_Object_id := bson.ObjectIdHex(scanId)
	//search for the loaded scans , if it exists , just return it
	existingScan, err := searchInMemoryScans(scan_Object_id)
	if err == nil {
		fmt.Fprintf(w, MarshalInterface(existingScan))
		return
	}
	foundScanEntry, err := db.SearchEntries(bson.M{"_id": scan_Object_id}, 0, 1)
	if err != nil || len(foundScanEntry) <= 0 || foundScanEntry == nil {
		errorReturned := &rest.RestError{ErrorCode: ERROR_CODE,
			Message:  fmt.Sprintf("Scan does not exist ,  Please send a valid ScanId or try again!"),
			SentTime: time.Now()}
		fmt.Fprintf(w, errorReturned.ToJson())
		return
	}
	fmt.Fprintf(w, MarshalInterface(foundScanEntry[0]))
}

func searchInMemoryScans(scanId bson.ObjectId) (*models.Reconn, error) {
	if scan, ok := AvailableScans[scanId.Hex()]; ok {
		return &scan, nil
	}
	return nil, fmt.Errorf("Scan is not under processing , It Might be already finished")
}

func getAllExistingScans(w http.ResponseWriter, r *http.Request) {
	err := verifyAuthenticity(r)
	if err != nil {
		notifyClient(w, err.Error(), ERROR_CODE)
		return
	}
	scans, err := db.GetAllScanEntries()
	if err != nil {
		log.Log(SCANNER_NAME, fmt.Sprintf("There was a problem getting ALL Scan Entries from the Database"))
		resultError := &rest.RestError{ErrorCode: ERROR_CODE, Message: fmt.Sprintf("There was a problem getting ALL Scan Entries from the database"), SentTime: time.Now()}
		fmt.Fprintf(w, resultError.ToJson())
		return
	}

	if len(scans) <= 0 {

		resultError := &rest.RestError{ErrorCode: ERROR_CODE, Message: fmt.Sprintf("There are no Active/Unfinished Scans for the moment"), SentTime: time.Now()}
		fmt.Fprintf(w, resultError.ToJson())
		return

	}
	batch := &rest.RestBatch{Description: "Existing Scans", Payload: scans, Size: len(scans)}
	//Return all scans
	fmt.Fprintf(w, batch.ToJson())
}

func getAllActiveScans(w http.ResponseWriter, r *http.Request) {

	err := verifyAuthenticity(r)

	if err != nil {
		notifyClient(w, err.Error(), ERROR_CODE)
		return
	}
	//getting all active scans
	activeScans := make([]models.Reconn, 0)
	for key := range AvailableScans {
		if value, ok := AvailableScans[key]; ok {
			activeScans = append(activeScans, value)
		}
	}
	batch := &rest.RestBatch{Description: "Active Scans", Payload: activeScans, Size: len(activeScans)}
	//now return them back to the client
	fmt.Fprintf(w, batch.ToJson())
}

func MarshalInterface(v interface{}) string {

	contents, err := json.Marshal(v)
	if err != nil {
		log.Log("Error in Marshalling an object")
		return ""
	}
	return string(contents)
}
func addScanToChannel(entry *models.Reconn) {

	NewScans <- *entry
}
