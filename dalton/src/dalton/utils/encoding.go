package utils

import "encoding/base64"

func EncodeToString(data []byte) string {

	return base64.StdEncoding.EncodeToString(data)
}

func EncodeBytes(data []byte) []byte {

	base64.StdEncoding.Encode(data, data)
	return data
}

func DecodeBytes(data []byte) []byte {

	base64.StdEncoding.Decode(data, data)
	return data
}

func DecodeString(data string) []byte {

	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return decodedData
}
