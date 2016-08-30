package utils

import (

	"labix.org/v2/mgo/bson"
	"crypto/md5"
	"encoding/hex"
	"time"
	"fmt"
	"math/rand"
)

func NewObjectId() bson.ObjectId {

	currentTime := time.Now().Add(time.Nanosecond+time.Duration(rand.Float64()))
	hashedTime := GetMD5HashBytes(fmt.Sprintf("%s",currentTime.Nanosecond()))
	truncatedTime := hashedTime[0:12]
	hexTruncatedTime := hex.EncodeToString(truncatedTime)
	return bson.ObjectIdHex(hexTruncatedTime)

}

func GetMD5Hash(text string) string {
    hasher := md5.New()
    hasher.Write([]byte(text))
    return hex.EncodeToString(hasher.Sum(nil))
}

func GetMD5HashBytes(text string) []byte {
    hasher := md5.New()
    hasher.Write([]byte(text))
    return hasher.Sum(nil)
}
