package rest

import (
	"encoding/json"
	"time"
	"dalton/log"
	"dalton/db/models"
)
/////////////////////////////////////////////////Rest Error /////////////////////////////////////////////////////////////////////////////////////////////////////////
type RestError struct {
	Message string `json:"message"`
	SentTime time.Time `json:"sentTime,omitempty"`
	ErrorCode int `json:"errorCode"`
}
func (restError *RestError) ToJson() string {

	contents , err := json.Marshal(restError)
	if err != nil {
		log.Log(err)
		return ""
	}
	return string(contents)
}

/////////////////////////////////////////////////Rest Success /////////////////////////////////////////////////////////////////////////////////////////////////////////
type RestSuccess struct {

	Message string `json:"message,omitempty"`
	ScanID string `json:"scanId"`
	StatusCode int `json:"statusCode"`
}
func (success RestSuccess) ToJson() string {

	contents , err := json.Marshal(&success)
	if err != nil {
		log.Log(err)
		return ""
	}
	return string(contents)
}

/////////////////////////////////////////////////Scan Status /////////////////////////////////////////////////////////////////////////////////////////////////////////
type ScanStatus struct {
	RestSuccess
	Progress float64 `json:"progress"`
}

func (scanStatus ScanStatus) ToJson() string {

	contents , err := json.Marshal(&scanStatus)
	if err != nil {
		log.Log(err)
		return ""
	}
	return string(contents)
}

type RestBatch struct {

	Description string `json:"description,omitempty"`
	Payload []models.ScanEntry `json:"payload"`
	Size int `json:"size"`
}

func (batch RestBatch) ToJson() string {

	contents , err := json.Marshal(batch)
	if err != nil {
		log.Log(err)
		return ""
	}
	return string(contents)
}
