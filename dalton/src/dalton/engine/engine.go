package engine
//#cgo LDFLAGS: -I/usr/local/include/glib-2.0 -Lusr/local/lib -lopenvas_nasl -I/usr/local/include/glib-2.0
//#include<stdio.h>
//#include<stdlib.h>
//#include<openvas/nasl/nasl.h>
import "C"
import (
	"dalton/db/models"
)
const (
	MAX_COUNT = 999
)

type NaslFile struct {
	Authenticated int
	Target string
	File string
	DescriptionOnly int
	RegisteredPaths []string
	RootDir string
}
func DescribeNaslFile(naslFile *NaslFile) (*models.Script,error) {
	//Set the Description only field to always on , because we are getting only the description for that specific nasl file
	naslFile.DescriptionOnly = 1
	return executeNaslFile(naslFile,nil,nil)
}

func ExecuteNaslScript(nasl *NaslFile , messages *[]string , success *int) error{
	//set the description only field to always be off , because we are actually executing the current nasl script instead
	nasl.DescriptionOnly =0
	_ , err := executeNaslFile(nasl,messages,success)
	if err != nil {
		return err
	}
	return nil
}
func executeNaslFile(settings *NaslFile,messages *[]string,success *int) (*models.Script,error) {

	arguments := &C.struct_ExternalData{file:C.CString(settings.File),target:C.CString(settings.Target),
	authenticated:C.int(settings.Authenticated),descriptionOnly:C.int(settings.DescriptionOnly),rootDir:C.CString(settings.RootDir)}
	info := &C.struct_DaltonScriptInfo{}
	C.executeNasl(arguments,info)
	//Create a dummy script object
	script := &models.Script{}
	err := fillScriptWithDetails(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with CVE IDs
	err = fillScriptWithCves(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with bugTraqIds
	err = fillScriptWithBugTraqIds(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with Dependencies
	err = fillScriptWithDependencies(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with Require Keys
	err = fillScriptWithRequireKeys(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with mandatory keys
	err = fillScriptWithMandatoryKeys(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with Require Ports
	err = fillScriptWithRequirePorts(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with require UDP Port
	err = fillScriptWithRequireUDPPorts(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with Exclude Keys
	err = fillScriptWithExcludeKeys(script,info)
	if err != nil {
		return nil , err
	}
	//check to see if the script has been run or not
	if(settings.DescriptionOnly <= 0){
		results , err := fillScriptWithSecurityMessages(info)
		if err != nil {
			return nil,err
		}
		*messages = append(*messages,results...)
		result := int(info.Success)
		*success = result
	}
	//fill the script with Tags
	err = fillScriptWithTags(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with XReferences
	err = fillScriptWithXRefs(script,info)
	if err != nil {
		return nil , err
	}
	//fill the script with Add Preferences
	err = fillScriptWithAddPreferences(script,info)
	if err != nil {
		return nil , err
	}
	return script, nil
}
//DaltonDictContainer *ScriptAddPreferences[DALTON_MAX_ARRAY_SIZE];
/*
char *Name;
    char *Type;
    char *Value;
 */
func fillScriptWithAddPreferences(script *models.Script,info *C.struct_DaltonScriptInfo) error{

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()

	var counter int = 0
	Prefs := []models.DaltonDictContainer{}

	for counter < MAX_COUNT{

		if(info.ScriptAddPreferences[counter] != nil && info.ScriptAddPreferences[counter].Name != nil &&
		 info.ScriptAddPreferences[counter].Value != nil && info.ScriptAddPreferences[counter].Type != nil){

			Pref := models.DaltonDictContainer{
				Name:C.GoString(info.ScriptAddPreferences[counter].Name),
				Value:C.GoString(info.ScriptAddPreferences[counter].Value),
				Type:C.GoString(info.ScriptAddPreferences[counter].Type),
			}
			Prefs = append(Prefs,Pref)
		}
		counter++
	}
	return nil
}

//DaltonNameValuePair *ScriptXRefs[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithXRefs(script *models.Script,info *C.struct_DaltonScriptInfo) error{

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int =0
	xRefs := []models.DaltonNameValuePair{}
	for counter < MAX_COUNT{

		if(info.ScriptXRefs[counter] != nil && info.ScriptXRefs[counter].Name != nil &&
		info.ScriptXRefs[counter].Value != nil){

			xRef := models.DaltonNameValuePair{
				Name:C.GoString(info.ScriptXRefs[counter].Name),
				Value:C.GoString(info.ScriptXRefs[counter].Value),
			}
			xRefs = append(xRefs,xRef)
		}
		counter++
	}
	return nil
}

//DaltonNameValuePair *ScriptTags[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithTags(script *models.Script,info *C.struct_DaltonScriptInfo) error{

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()

	var counter int =0
	tags := []models.DaltonNameValuePair{}
	for counter < MAX_COUNT {

		if(info.ScriptTags[counter] != nil && info.ScriptTags[counter].Name != nil &&
		info.ScriptTags[counter].Value != nil){

			tag := models.DaltonNameValuePair{
				 Name:C.GoString(info.ScriptTags[counter].Name),
				Value:C.GoString(info.ScriptTags[counter].Value),
			}
			tags = append(tags,tag)
		}
		counter++
	}

	return nil
}

//DaltonStringContainer *ScriptMessages[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithSecurityMessages(info *C.struct_DaltonScriptInfo) ([]string,error) {

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	var SecurityMessages []string
	for counter < MAX_COUNT {
		if (info.ScriptMessages[counter] != nil && info.ScriptMessages[counter].Contents != nil ){
			SecurityMessages = append(SecurityMessages,C.GoString(info.ScriptMessages[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return SecurityMessages,nil
}

//DaltonStringContainer *ScriptExcludeKeys[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithExcludeKeys (script *models.Script , info *C.struct_DaltonScriptInfo) error{

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	for counter < MAX_COUNT {
		if (info.ScriptExcludeKeys[counter] != nil && info.ScriptExcludeKeys[counter].Contents != nil ){
			script.ScriptExcludeKeys = append(script.ScriptExcludeKeys,C.GoString(info.ScriptExcludeKeys[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return nil
}

//DaltonStringContainer *ScriptRequireUDPPorts[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithRequireUDPPorts(script *models.Script , info *C.struct_DaltonScriptInfo) error {

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	for counter < MAX_COUNT {
		if (info.ScriptRequireUDPPorts[counter] != nil && info.ScriptRequireUDPPorts[counter].Contents ){
			script.ScriptRequireUDP = append(script.ScriptRequireUDP,C.GoString(info.ScriptRequireUDPPorts[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return nil

}

//DaltonStringContainer *ScriptRequirePorts[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithRequirePorts(script *models.Script,info *C.struct_DaltonScriptInfo) error{

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	for counter < MAX_COUNT {
		if (info.ScriptRequirePorts[counter] != nil && info.ScriptRequirePorts[counter].Contents != nil){
			script.ScriptRequirePorts = append(script.ScriptRequirePorts,C.GoString(info.ScriptRequirePorts[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return nil

}

//DaltonStringContainer *ScriptMandatoryKeys[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithMandatoryKeys(script *models.Script,info *C.struct_DaltonScriptInfo) error {

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	for counter < MAX_COUNT {
		if (info.ScriptMandatoryKeys[counter] != nil && info.ScriptMandatoryKeys[counter].Contents != nil ){
			script.ScriptMandatoryKeys = append(script.ScriptMandatoryKeys,C.GoString(info.ScriptMandatoryKeys[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return nil
}

//DaltonStringContainer *ScriptRequireKeys[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithRequireKeys(script *models.Script,info *C.struct_DaltonScriptInfo) error{

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	for counter < MAX_COUNT {

		if (info.ScriptRequireKeys[counter] != nil && info.ScriptRequireKeys[counter].Contents != nil){
			script.ScriptRequireKeys = append(script.ScriptRequireKeys,C.GoString(info.ScriptRequireKeys[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return nil
}

//DaltonStringContainer *ScriptDependencies[DALTON_MAX_ARRAY_SIZE];

func fillScriptWithDependencies(script *models.Script , info *C.struct_DaltonScriptInfo) error {

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	for counter < MAX_COUNT {

		if (info.ScriptDependencies[counter] != nil && info.ScriptDependencies[counter].Contents != nil ){
			script.ScriptDependencies = append(script.ScriptDependencies,C.GoString(info.ScriptDependencies[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return nil
}

//DaltonStringContainer *ScriptBugTraqIds[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithBugTraqIds(script *models.Script,info *C.struct_DaltonScriptInfo) error{

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	for counter < MAX_COUNT {

		if (info.ScriptBugTraqIds[counter] != nil && info.ScriptBugTraqIds[counter].Contents != nil){
			script.ScriptBugTraqIds = append(script.ScriptBugTraqIds,C.GoString(info.ScriptBugTraqIds[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return nil
}

//DaltonStringContainer *ScriptCveIds[DALTON_MAX_ARRAY_SIZE];
func fillScriptWithCves(script *models.Script,info *C.struct_DaltonScriptInfo) error {

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	var counter int  = 0
	for counter < MAX_COUNT {

		if (info.ScriptCveIds[counter] != nil && info.ScriptCveIds[counter].Contents != nil ){
			script.ScriptCveIds = append(script.ScriptCveIds,C.GoString(info.ScriptCveIds[counter].Contents))
		}else{
			break
		}
		counter++
	}
	return nil
}
/*
 char * ScriptName;
    char * ScriptVersion;
    int    ScriptTimeout;
    char * ScriptDescription;
    char * ScriptCopyright;
    char * ScriptSummary;
    int    ScriptCategory;
    char * ScriptFamily;
    char *ScriptId;
    char *ScriptOid;
 */
func fillScriptWithDetails(script *models.Script,info *C.struct_DaltonScriptInfo) error {

	defer func () {

		if data := recover(); data != nil{
			return
		}
	}()
	//Fill the copyright
	script.ScriptCopyRight = C.GoString(info.ScriptCopyright)
	//fill the version
	script.ScriptVersion = C.GoString(info.ScriptVersion)
	//fill the timeout
	script.ScriptTimeout = int(info.ScriptTimeout)
	//fill the description
	script.ScriptDescription = C.GoString(info.ScriptDescription)
	//fill the summary
	script.ScriptSummary = C.GoString(info.ScriptSummary)
	//fill the Category
	script.ScriptCategory = int(info.ScriptCategory)
	//fill the Script Family
	script.ScriptFamily = C.GoString(info.ScriptFamily)
	//fill the script Id
	script.ScriptId = C.GoString(info.ScriptId)
	//fill the script Oid
	script.ScriptOid = C.GoString(info.ScriptOid)
	return nil
}
