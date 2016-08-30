package main

import (


	"fmt"
	"labix.org/v2/mgo/bson"
	"time"
	"dalton/crypt"
	"crypto/rand"
	"dalton/compress"
	"os"

)

type User struct {
	Id bson.ObjectId `bson:"_id"`
	Name string `bson:"Name"`
	Email string `bson:"Email"`
	UserName string `bson:"UserName"`
	JoinedDate time.Time `bson:"JoinedDate"`
}

func main() {

	writeTo , err := os.OpenFile("c:/Users/Fawzy/Desktop/test.gz.tar",os.O_RDONLY,0644)
	defer writeTo.Close()
	if err != nil {
		fmt.Println(fmt.Sprintf("Got Exception : %q",err))
		return
	}

	tarFiles, err := compress.ExtractTarFrom(writeTo)
	if err != nil {
		fmt.Println(fmt.Sprintf("Got Exception : %q",err))
		return
	}
	for index , file := range tarFiles{

		fmt.Println(fmt.Sprintf("%d.%s",index+1,file.Name))
	}

	//now begin the writing process
	/*archiver := compress.NewArchiver(compress.COMPRESS_GZIP_ALGORITHM,writeTo)
	defer archiver.Close()
	fileToAdd := []string{"c:/Users/Fawzy/Desktop/Phishing Assessment Suite.docx",
	"c:/Users/Fawzy/Desktop/Recommendation-Kilburn.pdf"}
	//now add the file
	for _, file := range fileToAdd {

		err = compress.AddFile(archiver,file)
		if err != nil {
			fmt.Println("Error Adding the file to the archiver")
		}
	}*/
	fmt.Println("Done Compressing File.")

	/*compressedData := compress.Compress(compress.COMPRESS_LZW_ALGORITHM,[]byte("Hello Mohamed,Hello Mohamed how are you"))
	fmt.Println("Compressed Data : ",fmt.Sprintf("%x",compressedData))
	//Now decompress the data back
	decompressedData := compress.Decompress(compress.COMPRESS_LZW_ALGORITHM,compressedData)
	fmt.Println("Decompressed Data : ",fmt.Sprintf("%s",decompressedData))*/
	/*defer func(){

		log.InitLog("scannerd")

		if data := recover();data != nil {

			log.Log(data)
		}
	}()
	database := db.GetDatabase()
	collection := database.C("users")
	var users []User
	another := User{Id:bson.NewObjectId(), Name:"Mohamed",Email:"csharpizer@gmail.com",UserName:"snouto",JoinedDate:time.Now()}
	collection.Insert(another)
	query := collection.Find(bson.M{"UserName":"snouto"})
	query.All(&users)
	for index , user := range users {

		fmt.Println(fmt.Sprintf("%d. User With ID : %s , UserName : %s , JoinedDate:%s",index,user.Id,user.UserName,user.JoinedDate))
	}*/
	/*path := "/media/snouto/rest/projects/dalton/dalton/test/privatekey.pem"
	signer := crypt.Signer{}
	err := signer.LoadPrivateKey(path)
	if err != nil {
		fmt.Println(err)
	}

	message := "Hello World."

	signedContents , err := signer.SignContents([]byte(message))

	if err != nil {
		fmt.Println(err)
	}
	//display the signed contents
	fmt.Println(fmt.Sprintf("%x",signedContents))
	//verify the contents now
	result := signer.VerifyContents([]byte(message),signedContents)

	if result {
		fmt.Println("The data is verified Successfully.")
	}else {
		fmt.Println("The data is not verified.")
	}*/
	/*var cryptomanager crypt.CryptoManager = crypt.CryptoManager{}
	makeKey(&cryptomanager)
	encryptedData ,err := cryptomanager.Encrypt([]byte("This is the message,This is the message,This is the message,This is the message"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Encrypted Data : " , base64.StdEncoding.EncodeToString(encryptedData))
	//now decrypting the data
	fmt.Println("Decrypting the data......")
	decrypteddata , err := cryptomanager.Decrypt(encryptedData)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Decrypted Data : ",fmt.Sprintf("%s",string(decrypteddata)))*/
	//now verify
}

func makeKey(crypto *crypt.CryptoManager){

	IV := []byte("This is the IVIV")
	crypto.IV = IV
	crypto.SetKeySize(32)
	key := make([]byte,32)
	rand.Read(key)
	crypto.SymmetricKey = key
}
