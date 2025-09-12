package config

import (
	"asterfusion/client/logger"
	"strings"

	"github.com/spf13/viper"
)

func GetFirmware() string {
	viper.SetConfigName("sonic_version")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/sonic/")
	err := viper.ReadInConfig()
	if err != nil {
		logger.Error("Failed to get firmware info: %s", err.Error())
	}

	firmware := viper.Get("build_version").(string)
	firmware = strings.Replace(firmware, "'", "", -1)
	return firmware
}
