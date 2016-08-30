package auth

import (
	"dalton/config"
	"dalton/log"
	"dalton/crypt"
)


/*
    This package will authenticate any incoming request to either scannerd or analyzerd
    based upon specific variable names that are passed in
 */

const (

	DALTON_SIGNATURE_VAR ="DALTON-SIGNATURE"
	DALTON_CRYPT_VAR ="DALTON-CRYPT"
)



var (
	signer *crypt.Signer
)

func init(){

	//init the configuration of dalton
	PrivateKeyLocation , err := config.ReadConfigKey("security","privatekey")
	if err != nil {
		log.Log("Unable to retrieve the private key of dalton")
		return
	}
	//now begin initializing the signer
	signer = &crypt.Signer{}
	err  = signer.LoadPrivateKey(PrivateKeyLocation)
	if err != nil {
		log.Log("Unable to load the private key of dalton in Dalton Signer")
		return
	}
}
func VerifySignature(signedContents, contents []byte) bool {
	//now sign the contents
	return signer.VerifyContents(contents,signedContents)
}
