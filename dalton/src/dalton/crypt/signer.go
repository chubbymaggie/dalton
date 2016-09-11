package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

type Signer struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func (signer *Signer) InitSigner(privPath, PubPath string) (err error) {
	//handle the error
	defer func() {
		if data := recover(); data != nil {

			err = data.(error)
		}
	}()
	signer.PrivateKey = loadPrivateKey(privPath)
	signer.PublicKey = loadPublicKey(PubPath)
	err = nil
	return
}
func (signer *Signer) LoadPrivateKey(path string) error {

	signer.PrivateKey = loadPrivateKey(path)
	signer.PublicKey = &signer.PrivateKey.PublicKey
	return nil
}
func (signer *Signer) LoadPublicKey(path string) error {

	signer.PublicKey = loadPublicKey(path)
	return nil
}
func (signer *Signer) SignContents(contents []byte) (signedContents []byte, err error) {
	//get the hash
	hashed := signer.HashMessage(contents)
	var hashFunc crypto.Hash
	//now sign the contents
	signedContents, err = rsa.SignPKCS1v15(rand.Reader, signer.PrivateKey, hashFunc, hashed)
	return
}
func (signer *Signer) VerifyContents(contents, signedContents []byte) bool {

	//get the hash
	hashed := signer.HashMessage(contents)
	var hashFunc crypto.Hash
	//verify the contents
	err := rsa.VerifyPKCS1v15(signer.PublicKey, hashFunc, hashed, signedContents)
	if err != nil {
		return false
	} else {
		return true
	}

}
func (signer *Signer) HashMessage(message []byte) (hashedContents []byte) {

	sha1 := sha1.New()
	n, err := sha1.Write(message)
	if n < len(message) {
		panic("Dalton-Signer : " + "Can't write the entire Message into the hash writer to generate a hash ")
	}
	if err != nil {
		panic(err)
	}
	hashedContents = sha1.Sum(nil)
	return
}
func loadPublicKey(path string) *rsa.PublicKey {

	contents, err := ioutil.ReadFile(path)

	if err != nil {
		panic(err)
	}
	blockedContents, _ := pem.Decode(contents)

	//now parse the public key from the Cipher block
	pubInterface, err := x509.ParsePKIXPublicKey(blockedContents.Bytes)
	if err != nil {
		panic(err)
	}
	return pubInterface.(*rsa.PublicKey)
}
func loadPrivateKey(path string) *rsa.PrivateKey {

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	//decode the contents of the pem file
	blockedContents, _ := pem.Decode(contents)
	//load the private key
	//parse the private key from the pem decoded structure
	key, err := x509.ParsePKCS1PrivateKey(blockedContents.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}
