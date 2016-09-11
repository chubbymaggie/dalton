package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	//"encoding/base64"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func makeHash(message string) []byte {
	hash := sha1.New()
	_, err := io.WriteString(hash, message)
	if err != nil {

		panic(err)
	}
	return hash.Sum(nil)
}

func generateKey() *ecdsa.PrivateKey {

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func main() {
	message := "Hello World."
	hashed := makeHash(message)
	fmt.Println(fmt.Sprintf("%x", hashed))
	key := generateKey()
	r, s, err := ecdsa.Sign(rand.Reader, key, hashed)
	if err != nil {
		panic(err)
	}
	fmt.Println("r: ", *r)
	fmt.Println("s: ", *s)
	//now we need to verify
	//hashed = append(hashed,[]byte("a")...)
	if ecdsa.Verify(&key.PublicKey, hashed, r, s) {
		fmt.Println("Yes , The message is original")
	} else {
		fmt.Println("No , The Message has been tempered")
	}
}
