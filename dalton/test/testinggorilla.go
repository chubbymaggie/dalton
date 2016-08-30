package main

import (
	"github.com/gorilla/mux"
	"net/http"
	"time"
	"encoding/json"
	"fmt"

)


type Message struct {

	Sender string `json:sender`
	Payload string `json:payload,omitempty`
	time time.Time `json:sendingTime,omitempty`
}

func (message *Message) SelfMarshal() ([]byte,error){
	return json.MarshalIndent(message,"","  ")
}

func main() {

	msg := Message{Sender:"Mohamed Ibrahim Fawzy",Payload:`
	 This is a bigger payload set inside this json message ,

	 this message shall be transferred over Restful Api,

	 Thank you for your collaboration again

	`,time:time.Now()}

	mux := mux.NewRouter()
	mux.HandleFunc("/home",func (w http.ResponseWriter , r *http.Request){

		contents , err := msg.SelfMarshal()
		if err != nil {
			fmt.Fprintf(w,"Received an Error : %v",err)
			return
		}
		fmt.Fprintf(w,string(contents))
	})

	//then start the HTTP Server to handle requests
	http.Handle("/",mux)

	fmt.Println("Starting the Http Server , Ready to Serve Requests")
	http.ListenAndServe(":9098",nil)
}
