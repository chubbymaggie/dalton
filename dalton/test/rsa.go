package main

import (
	"crypto/rsa"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"fmt"
	"crypto/sha1"
	"crypto/rand"
	"crypto"
	"io"
)

func LoadContents(path string ) []byte {

	contents , err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return contents
}

func GetPrivateKey(path string) *rsa.PrivateKey {

	//load the contents of the file and pass it to the pem encoder
	contents := LoadContents(path)
	blockedKey , _ := pem.Decode(contents)
	key , err := x509.ParsePKCS1PrivateKey(blockedKey.Bytes)
	if err != nil {
		panic(err)
	}
	return key

}
func GetPublicKey(path string) *rsa.PublicKey {

	//load the contents of the file and pass it to the pem encoder
	contents := LoadContents(path)
	blockedKey , _ := pem.Decode(contents)
	pubkeyInterface ,err := x509.ParsePKIXPublicKey(blockedKey.Bytes)
	if err != nil {
		panic(err)
	}
	return pubkeyInterface.(*rsa.PublicKey)
}

func makeHashed(message string) []byte {
	hash := sha1.New()
	_ , err := io.WriteString(hash,message)
	if err != nil {

		panic(err)
	}
	return hash.Sum(nil)
}


func main() {

	//Load the private key
	var hash crypto.Hash
	key := GetPrivateKey("C:/projects/privatekey.pem")
	signedContents , err := rsa.SignPKCS1v15(rand.Reader,key,hash,makeHashed("Hello World."))
	if err != nil {
		panic(err)
	}
	//now let us verify the message using the public key
	pubPem := GetPublicKey("C:/projects/publickey.pem")
	//signedContents = append(signedContents,[]byte("a")...)
	err = rsa.VerifyPKCS1v15(pubPem,hash,makeHashed("Hello World."),signedContents)
	if err != nil {
		fmt.Println("Signature is not valid.")
	}else {
		fmt.Println("Signature Verified Successfully.")
	}



}