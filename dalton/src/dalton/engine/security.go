package engine

import (
	"dalton/crypt"
	"dalton/utils"
	"fmt"
	"io/ioutil"
	"os"
	path "path/filepath"
	"strings"
)

const (
	EXT_NASL_SCRIPT = ".nasl"
	EXT_SIG_FILE    = ".sig"
)

func SignScript(file, privatekey string) error {

	//first we load the contents of the passed script file
	script, err := os.Open(file)
	defer script.Close()
	if err != nil {
		return err
	}
	//read the contents of the script file
	contents, err := ioutil.ReadAll(script)
	if err != nil {
		return err
	}
	//now load the contents of the file
	signer := &crypt.Signer{}
	err = signer.LoadPrivateKey(privatekey)
	if err != nil {
		return err
	}
	//Now sign the contents of the file
	signedContents, err := signer.SignContents(contents)
	if err != nil {
		return err
	}
	//now convert them into base64
	signedStringContents := utils.EncodeToString(signedContents)
	//now access the fileinfo of the current script
	stats, err := script.Stat()
	if err != nil {
		return err
	}
	fileName := strings.Split(stats.Name(), ".")[0]
	//now get the directory of the current script
	fileDir := path.Dir(file)
	fullPath := fmt.Sprintf("%s/%s%s", fileDir, fileName, EXT_SIG_FILE)
	//open this new file or create it
	signFile, err := os.OpenFile(fullPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}
	defer signFile.Close()
	//now begin writing contents into that file
	fmt.Fprint(signFile, signedStringContents)
	return nil
}

func VerifyScript(file, privateKey string) bool {
	//get the signature file for the current script
	signFile := strings.Replace(file, EXT_NASL_SCRIPT, EXT_SIG_FILE, len(EXT_NASL_SCRIPT))
	//check if the file exists or not
	if _, err := os.Stat(signFile); err != nil {
		return false
	}
	//now the file exists, so read its contents and verify the file
	//first open the original script file
	script, err := os.Open(file)
	defer script.Close()
	if err != nil {
		return false
	}
	originalContents, err := ioutil.ReadAll(script)
	if err != nil {
		return false
	}
	//now read the signed contents as well
	signedFile, err := os.Open(signFile)
	defer signedFile.Close()
	if err != nil {
		return false
	}
	//now read the contents of the signed file
	signedContents, err := ioutil.ReadAll(signedFile)
	if err != nil {
		return false
	}
	//convert the base64 signed Contents back into bytes
	signedContents = utils.DecodeString(string(signedContents))
	//create a signer and verify the contents
	signer := &crypt.Signer{}
	//load the private key first
	signer.LoadPrivateKey(privateKey)
	return signer.VerifyContents(originalContents, signedContents)
}
