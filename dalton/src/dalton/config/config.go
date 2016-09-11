package config

import (
	ini "gopkg.in/ini.v1"
	"log"
	"os"
	"fmt"
)

const (

	//the environment variable to load the ini configuration file
	CONFIG_VARIABLE = "DALTONCONF"
)

var (
	configFile *ini.File
)

/*
  This is the init function that will load the configuration  file upon initialization
*/
func init() {

	defer func() {

		if data := recover(); data != nil {

			log.Fatal("Got Exception : \n", data)
		}

	}()

	//read the configuration file from the environment
	///media/snouto/rest/projects/dalton/dalton/tmp/dalton.ini
	//os.Getenv(CONFIG_VARIABLE)
	if location := os.Getenv(CONFIG_VARIABLE); location != "" {

		config, err := ini.InsensitiveLoad(location)
		if err != nil {

			log.Fatal("Got Exception : \n", "Unable to read the configuration file from the environment Variable (", CONFIG_VARIABLE, ").")

			return
		}

		configFile = config

	}

}

func ReadKey(sectionName, key string) *ini.Key {

	if configFile == nil {

		return nil

	}

	section, err := configFile.GetSection(sectionName)

	if err != nil {
		msg := fmt.Sprintf("Unable to read section : %s\n", sectionName)
		log.Fatal(msg)
		return nil
	}

	return section.Key(key)
}

func ReadConfigKey(sectionName, key string) (string, error) {

	if configFile == nil {

		return "", fmt.Errorf("Configuration file is null , this shouldn't happen.")

	}

	section, err := configFile.GetSection(sectionName)

	if err != nil {
		msg := fmt.Sprintf("Unable to read section : %s\n", sectionName)
		log.Fatal(msg)
		return "", fmt.Errorf(msg)
	}

	return section.Key(key).String(), nil
}
