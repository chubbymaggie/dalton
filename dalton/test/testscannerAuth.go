package main

import (
	"dalton/crypt"
	"dalton/config"
	"fmt"
	"dalton/utils"
)

func main() {

	ip := "192.168.1.8"
	signer := crypt.Signer{}
	privateKey , err := config.ReadConfigKey("security","privatekey")
	if err != nil {
		fmt.Println(err)
		return
	}
	signer.LoadPrivateKey(privateKey)
	signedContents , err := signer.SignContents([]byte(ip))
	if err != nil {
		fmt.Println(err)
		return
	}

	//convert into base64
	encodedData := utils.EncodeToString(signedContents)

	fmt.Println(encodedData)
}
