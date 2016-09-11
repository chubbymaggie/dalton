package crypt

import (
	"crypto/cipher"
	"fmt"

	"crypto/aes"
)

type CryptoManager struct {
	IV           []byte
	SymmetricKey []byte
	KeySize      int
}

func (symm *CryptoManager) SetIV(iv []byte) {
	symm.IV = iv
}

func (symm *CryptoManager) SetKey(key []byte) {
	symm.SymmetricKey = key
}

func (symm *CryptoManager) SetKeySize(keysize int) {
	symm.KeySize = keysize
}
func (symm *CryptoManager) Encrypt(data []byte) (encryptedData []byte, err error) {

	if symm.KeySize == 0 || symm.SymmetricKey == nil || symm.IV == nil {

		err = fmt.Errorf("CryptoManager: You have to initialize KeySize , Symmetric Key and Initialization Vector before using the algorithm.")
		return
	}
	blockCipher := makeCipher(symm)
	stream := cipher.NewCTR(blockCipher, symm.IV)
	stream.XORKeyStream(data, data)
	encryptedData = data
	err = nil
	return
}

func (symm *CryptoManager) Decrypt(data []byte) (decryptData []byte, err error) {
	if symm.KeySize == 0 || symm.SymmetricKey == nil || symm.IV == nil {
		err = fmt.Errorf("CryptoManager: You have to initialize KeySize , Symmetric Key and Initialization Vector before using the algorithm.")
		return
	}
	blockCipher := makeCipher(symm)
	stream := cipher.NewCTR(blockCipher, symm.IV)
	stream.XORKeyStream(data, data)
	decryptData = data
	err = nil
	return
}

func makeCipher(symm *CryptoManager) cipher.Block {
	c, err := aes.NewCipher(symm.SymmetricKey)
	if err != nil {
		panic(err)
	}
	return c
}
